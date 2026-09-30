//go:build !e2e_testing

package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/internal/msgx"
	"golang.org/x/sys/unix"
)

type StdConn struct {
	*net.UDPConn
	isV4  bool
	sysFd uintptr
	l     *slog.Logger

	// listenHost and port are the configured address and the bound port, which a connected socket shares.
	listenHost netip.Addr
	port       uint16
	// rc reaches the listener's descriptor for another listen routine's Rebind.
	rc    syscall.RawConn
	socks *connSocks
	// listening is set once ListenOut runs. The listener's and every connected socket's readers hand their batches
	// to it on rx, so the EncReader runs on ListenOut's goroutine alone; done closes when ListenOut returns.
	listening atomic.Bool
	rx        chan *rxBatch
	done      chan struct{}
	// free holds the batches ListenOut has delivered, for the readers to fill again.
	free chan *rxBatch
}

var _ Conn = &StdConn{}
var _ EstablishedPeerConn = &StdConn{}

func NewListener(l *slog.Logger, s Settings) (Conn, error) {
	lc := NewListenConfig(s.Multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", s.Listen.String())
	if err != nil {
		return nil, err
	}

	if uc, ok := pc.(*net.UDPConn); ok {
		c := &StdConn{UDPConn: uc, l: l, listenHost: s.Listen.Addr(), rx: make(chan *rxBatch, 1), done: make(chan struct{}),
			free: make(chan *rxBatch, rxBatchesKept)}

		rc, err := uc.SyscallConn()
		if err != nil {
			return nil, fmt.Errorf("failed to open udp socket: %w", err)
		}
		c.rc = rc

		err = rc.Control(func(fd uintptr) {
			c.sysFd = fd
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get udp fd: %w", err)
		}

		la, err := c.LocalAddr()
		if err != nil {
			return nil, err
		}
		c.isV4 = la.Addr().Is4()
		c.port = la.Port()
		c.socks = joinConnSocks(c, la, s)

		return c, nil
	}

	return nil, fmt.Errorf("unexpected PacketConn: %T %#v", pc, pc)
}

func NewListenConfig(multi bool) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if multi {
				var controlErr error
				err := c.Control(func(fd uintptr) {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
						controlErr = fmt.Errorf("SO_REUSEPORT failed: %v", err)
						return
					}
				})
				if err != nil {
					return err
				}
				if controlErr != nil {
					return controlErr
				}
			}

			return nil
		},
	}
}

//go:linkname sendto golang.org/x/sys/unix.sendto
//go:noescape
func sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen int32) (err error)

func (u *StdConn) WriteTo(b []byte, ap netip.AddrPort) error {
	if t := u.socks.table.Load(); t != nil {
		if p := (*t)[ap]; p != nil {
			bufs := [1][]byte{b}
			if sent, err := u.connSockRun(p, ap, bufs[:]); sent == 1 || err != nil {
				return err
			}
		}
	}
	return u.writeTo(b, ap)
}

// writeTo sends b through the listener.
func (u *StdConn) writeTo(b []byte, ap netip.AddrPort) error {
	var sa unsafe.Pointer
	var addrLen int32

	if u.isV4 {
		if ap.Addr().Is6() {
			return ErrInvalidIPv6RemoteForSocket
		}

		var rsa unix.RawSockaddrInet4
		rsa.Family = unix.AF_INET
		rsa.Addr = ap.Addr().As4()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:], ap.Port())
		sa = unsafe.Pointer(&rsa)
		addrLen = syscall.SizeofSockaddrInet4
	} else {
		var rsa unix.RawSockaddrInet6
		rsa.Family = unix.AF_INET6
		rsa.Addr = ap.Addr().As16()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:], ap.Port())
		sa = unsafe.Pointer(&rsa)
		addrLen = syscall.SizeofSockaddrInet6
	}

	// Golang stdlib doesn't handle EAGAIN correctly in some situations so we do writes ourselves
	// See https://github.com/golang/go/issues/73919
	for {
		//_, _, err := unix.Syscall6(unix.SYS_SENDTO, u.sysFd, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, sa, addrLen)
		err := sendto(int(u.sysFd), b, 0, sa, addrLen)
		if err == nil {
			// Written, get out before the error handling
			return nil
		}

		if errors.Is(err, syscall.EINTR) {
			// Write was interrupted, retry
			continue
		}

		if errors.Is(err, syscall.EAGAIN) {
			return &net.OpError{Op: "sendto", Err: unix.EWOULDBLOCK}
		}

		if errors.Is(err, syscall.EBADF) {
			return net.ErrClosed
		}

		return &net.OpError{Op: "sendto", Err: err}
	}
}

func (u *StdConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	// An un-sendable destination costs its own packet, never the ones behind it in the batch.
	// TODO: writeTo maps EWOULDBLOCK to an error, so a full listener send buffer
	// silently drops those packets (linux blocks instead). Poll for
	// writability on EAGAIN before giving up on them.
	written := 0
	t := u.socks.table.Load()
	if t == nil {
		for i, b := range bufs {
			if err := u.writeTo(b, addrs[i]); err == nil {
				written++
			} else {
				u.l.Debug("failed to write packet in batch", "udpAddr", addrs[i], "error", err)
			}
		}
		return written, nil
	}
	for off := 0; off < len(bufs); {
		// A run of datagrams to one peer goes out together, on its connected socket if it has or earns one.
		dst := addrs[off]
		end := off + 1
		for end < len(bufs) && addrs[end] == dst {
			end++
		}
		if p := (*t)[dst]; p != nil {
			for off < end {
				sent, err := u.connSockRun(p, dst, bufs[off:end])
				written += sent
				off += sent
				if err == nil {
					break
				}
				u.l.Debug("failed to write packet in batch", "udpAddr", dst, "error", err)
				off++
			}
		}
		// The listener sends what no connected socket took.
		for ; off < end; off++ {
			if err := u.writeTo(bufs[off], dst); err == nil {
				written++
			} else {
				u.l.Debug("failed to write packet in batch", "udpAddr", dst, "error", err)
			}
		}
	}
	return written, nil
}

func (u *StdConn) LocalAddr() (netip.AddrPort, error) {
	a := u.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("LocalAddr returned invalid IP address: %s", v.IP)
		}
		return netip.AddrPortFrom(addr, uint16(v.Port)), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *StdConn) ReloadConfig(c *config.C) {
	// TODO
}

func NewUDPStatsEmitter(udpConns []Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

// ListenOut delivers the batches that the listener's reader and the connected sockets' readers hand it.
func (u *StdConn) ListenOut(r EncReader, flush func()) error {
	defer close(u.done)
	u.listening.Store(true)
	u.startConnSocks()
	errc := make(chan error, 1)
	go func() { errc <- u.readListener() }()
	for {
		select {
		case b := <-u.rx:
			for i := range b.n {
				r(b.addrs[i], b.pkts[i])
			}
			flush()
			u.putBatch(b)
		case err := <-errc:
			return err
		}
	}
}

// rxBatch is one recvmsg_x batch: n datagrams in pkts, from addrs. A reader takes one only while its socket is
// readable, so an idle connected socket holds none.
type rxBatch struct {
	n     int
	pkts  [msgx.Batch][]byte
	addrs [msgx.Batch]netip.AddrPort
	buf   []byte
	names [msgx.Batch]unix.RawSockaddrInet6
	iovs  [msgx.Batch]unix.Iovec
	hdrs  [msgx.Batch]msgx.Hdr
}

// rxBatchesKept is how many batches a listener keeps for reuse: one being delivered and one queued, plus one for
// each socket reading at once, the listener and up to 8 connected sockets. Each is msgx.Batch*MTU, about 576KB.
const rxBatchesKept = 11

func (u *StdConn) getBatch() *rxBatch {
	select {
	case b := <-u.free:
		return b
	default:
	}
	b := &rxBatch{buf: make([]byte, msgx.Batch*MTU)}
	for i := range b.hdrs {
		b.iovs[i].Base = &b.buf[i*MTU]
		b.iovs[i].SetLen(MTU)
		b.hdrs[i] = msgx.Hdr{Name: (*byte)(unsafe.Pointer(&b.names[i])), Iov: &b.iovs[i], Iovlen: 1}
	}
	return b
}

func (u *StdConn) putBatch(b *rxBatch) {
	select {
	case u.free <- b:
	default:
	}
}

// noRecvX is set once recvmsg_x is refused or misbehaves; every reader then reads one datagram per syscall.
var noRecvX atomic.Bool

// parse checks the n entries recvmsg_x filled and sets pkts and addrs from them. It rejects a batch that intact
// msghdr_x entries can't produce, which is how a change to xnu's private struct layout would show up.
func (b *rxBatch) parse(n int) error {
	if n > len(b.hdrs) {
		return fmt.Errorf("returned %d datagrams for %d headers", n, len(b.hdrs))
	}
	for i := range n {
		h := &b.hdrs[i]
		if h.Datalen > MTU {
			return fmt.Errorf("datagram %d is %d bytes, past the %d byte buffer", i, h.Datalen, MTU)
		}
		sa := &b.names[i]
		switch {
		case sa.Family == unix.AF_INET && h.Namelen == unix.SizeofSockaddrInet4:
			sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
			b.addrs[i] = netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa4.Port))[:]))
		case sa.Family == unix.AF_INET6 && h.Namelen == unix.SizeofSockaddrInet6:
			b.addrs[i] = netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:]))
		default:
			return fmt.Errorf("datagram %d has address family %d with length %d", i, sa.Family, h.Namelen)
		}
		b.pkts[i] = b.buf[i*MTU : i*MTU+int(h.Datalen) : i*MTU+int(h.Datalen)]
	}
	b.n = n
	return nil
}

// batchReader reads one socket in batches. Its fn is bound once, since a closure passed through the RawConn
// interface escapes and would allocate on every read.
type batchReader struct {
	u     *StdConn
	conn  *net.UDPConn
	rc    syscall.RawConn
	b     *rxBatch
	errno syscall.Errno
	fn    func(fd uintptr) bool
}

func (u *StdConn) newBatchReader(conn *net.UDPConn, rc syscall.RawConn) *batchReader {
	r := &batchReader{u: u, conn: conn, rc: rc}
	r.fn = r.recv
	return r
}

func (r *batchReader) recv(fd uintptr) bool {
	b := r.u.getBatch()
	for i := range b.hdrs {
		b.hdrs[i].Namelen = unix.SizeofSockaddrInet6
		b.hdrs[i].Flags = 0
		b.hdrs[i].Datalen = 0
	}
	n, errno := msgx.Recv(fd, b.hdrs[:])
	if errno == unix.EAGAIN {
		r.u.putBatch(b)
		return false
	}
	b.n, r.b, r.errno = n, b, errno
	return true
}

// read returns the next batch: up to msgx.Batch datagrams from one recvmsg_x, or one datagram once recvmsg_x is off.
func (u *StdConn) read(r *batchReader) (*rxBatch, error) {
	if !noRecvX.Load() {
		r.b = nil
		err := r.rc.Read(r.fn)
		b := r.b
		switch {
		case err != nil:
			if b != nil {
				u.putBatch(b)
			}
			return nil, err
		case r.errno == 0:
			perr := b.parse(b.n)
			if perr == nil {
				return b, nil
			}
			// The batch was read through a layout the kernel no longer writes, so none of it is trustworthy.
			u.disableRecvX("returned an unexpected header", perr)
		case msgx.Unsupported(r.errno):
			u.disableRecvX("unavailable", r.errno)
		default:
			u.putBatch(b)
			return nil, r.errno
		}
		u.putBatch(b)
	}
	b := u.getBatch()
	n, from, err := r.conn.ReadFromUDPAddrPort(b.buf[:MTU])
	if err != nil {
		u.putBatch(b)
		return nil, err
	}
	b.n, b.pkts[0], b.addrs[0] = 1, b.buf[:n:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
	return b, nil
}

func (u *StdConn) disableRecvX(why string, err error) {
	if noRecvX.CompareAndSwap(false, true) {
		u.l.Warn("recvmsg_x "+why+", reading one datagram per syscall", "error", err)
	}
}

// readListener hands the listener's batches to ListenOut until the listener closes.
func (u *StdConn) readListener() error {
	r := u.newBatchReader(u.UDPConn, u.rc)
	for {
		b, err := u.read(r)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			u.l.Error("unexpected udp socket receive error", "error", err)
			continue
		}
		if !u.deliver(b) {
			return net.ErrClosed
		}
	}
}

// deliver hands b to ListenOut, and reports false once ListenOut has returned.
func (u *StdConn) deliver(b *rxBatch) bool {
	select {
	case u.rx <- b:
		return true
	case <-u.done:
		u.putBatch(b)
		return false
	}
}

// Close closes the connected sockets of every listen routine, then the listener.
func (u *StdConn) Close() error {
	u.stopConnSocks()
	return u.UDPConn.Close()
}

func (u *StdConn) SupportsMultipleReaders() bool {
	return false
}

// Rebind clears the interface the kernel scoped this socket to, so that sends are routed against the current
// routing table instead of the interface we happened to be on when the socket was created. Darwin pins sockets
// this way on its own, which is what strands us after the underlying network changes. Control.RebindUDPServer
// rebinds only the first writer, so this clears the other listen routines' listeners too. Connected sockets are
// closed after the listeners are cleared, and later ones copy the cleared scope and pick their source addresses
// afresh.
func (u *StdConn) Rebind() error {
	var err error
	if u.isV4 {
		err = syscall.SetsockoptInt(int(u.sysFd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, 0)
	} else {
		err = syscall.SetsockoptInt(int(u.sysFd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, 0)
	}
	for _, m := range u.socks.siblings(u) {
		err = errors.Join(err, m.clearBoundIf())
	}
	u.closeConnSocks("rebind")
	return err
}

// clearBoundIf clears the interface the listener is scoped to through its RawConn, which fails on a listener that
// closed concurrently instead of reaching whatever reused its descriptor number.
func (u *StdConn) clearBoundIf() error {
	level, opt := syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF
	if u.isV4 {
		level, opt = syscall.IPPROTO_IP, syscall.IP_BOUND_IF
	}
	var serr error
	if err := u.rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), level, opt, 0) }); err != nil {
		return err
	}
	return serr
}
