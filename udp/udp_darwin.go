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
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/slackhq/nebula/config"
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
	// reader is ListenOut's reader, which connected socket readers share; readMu serializes them, since an
	// EncReader isn't safe for concurrent use.
	reader atomic.Pointer[readerPair]
	readMu sync.Mutex
}

type readerPair struct {
	r     EncReader
	flush func()
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
		c := &StdConn{UDPConn: uc, l: l, listenHost: s.Listen.Addr()}

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

func (u *StdConn) ListenOut(r EncReader, flush func()) error {
	buffer := make([]byte, MTU)
	u.reader.Store(&readerPair{r: r, flush: flush})
	u.startConnSocks()

	for {
		// Just read one packet at a time
		n, rua, err := u.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			u.l.Error("unexpected udp socket receive error", "error", err)
			continue
		}

		u.readMu.Lock()
		r(netip.AddrPortFrom(rua.Addr().Unmap(), rua.Port()), buffer[:n:n])
		flush()
		u.readMu.Unlock()
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
