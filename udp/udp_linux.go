//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

type StdConn struct {
	udpConn *net.UDPConn
	rawConn syscall.RawConn
	isV4    bool
	l       *slog.Logger
	batch   int

	// sendmmsg scratch. Each queue has its own StdConn, so no locking is
	// needed. Sized to MaxWriteBatch at construction; WriteBatch chunks
	// larger inputs.
	writeMsgs  []rawMessage
	writeIovs  []iovec
	writeNames [][]byte

	// sendmmsg(2) callback state. sendmmsgCB is bound once in NewListener
	// to the sendmmsgRun method value so passing it to rawConn.Write does
	// not allocate a fresh closure per send; sendmmsgN/Sent/Errno carry
	// the inputs and outputs across the call without escaping locals.
	sendmmsgCB    func(fd uintptr) bool
	sendmmsgN     int
	sendmmsgSent  int
	sendmmsgErrno syscall.Errno
}

func setReusePort(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		//CloseOnExec already set by the runtime
	})
	if err != nil {
		return err
	}
	return opErr
}

func NewListener(l *slog.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	listen := netip.AddrPortFrom(ip, uint16(port))
	lc := net.ListenConfig{}
	if multi {
		lc.Control = setReusePort
	}
	//this context is only used during the bind operation, you can't cancel it to kill the socket
	pc, err := lc.ListenPacket(context.Background(), "udp", listen.String())
	if err != nil {
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}
	udpConn := pc.(*net.UDPConn)
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}
	//gotta find out if we got an AF_INET6 socket or not:
	out := &StdConn{
		udpConn: udpConn,
		rawConn: rawConn,
		l:       l,
		batch:   batch,
	}

	af, err := out.getSockOptInt(unix.SO_DOMAIN)
	if err != nil {
		_ = out.Close()
		return nil, err
	}
	out.isV4 = af == unix.AF_INET

	out.prepareWriteMessages(MaxWriteBatch)
	out.sendmmsgCB = out.sendmmsgRun

	return out, nil
}

func (u *StdConn) prepareWriteMessages(n int) {
	u.writeMsgs = make([]rawMessage, n)
	u.writeIovs = make([]iovec, n)
	u.writeNames = make([][]byte, n)

	for i := range u.writeMsgs {
		u.writeNames[i] = make([]byte, unix.SizeofSockaddrInet6)
		u.writeMsgs[i].Hdr.Name = &u.writeNames[i][0]
	}
}

func (u *StdConn) SupportsMultipleReaders() bool {
	return true
}

func (u *StdConn) Rebind() error {
	return nil
}

func (u *StdConn) getSockOptInt(opt int) (int, error) {
	if u.rawConn == nil {
		return 0, fmt.Errorf("no UDP connection")
	}
	var out int
	var opErr error
	err := u.rawConn.Control(func(fd uintptr) {
		out, opErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	})
	if err != nil {
		return 0, err
	}
	return out, opErr
}

func (u *StdConn) setSockOptInt(opt int, n int) error {
	if u.rawConn == nil {
		return fmt.Errorf("no UDP connection")
	}
	var opErr error
	err := u.rawConn.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, opt, n)
	})
	if err != nil {
		return err
	}
	return opErr
}

func (u *StdConn) SetRecvBuffer(n int) error {
	return u.setSockOptInt(unix.SO_RCVBUFFORCE, n)
}

func (u *StdConn) SetSendBuffer(n int) error {
	return u.setSockOptInt(unix.SO_SNDBUFFORCE, n)
}

func (u *StdConn) SetSoMark(mark int) error {
	return u.setSockOptInt(unix.SO_MARK, mark)
}

func (u *StdConn) GetRecvBuffer() (int, error) {
	return u.getSockOptInt(unix.SO_RCVBUF)
}

func (u *StdConn) GetSendBuffer() (int, error) {
	return u.getSockOptInt(unix.SO_SNDBUF)
}

func (u *StdConn) GetSoMark() (int, error) {
	return u.getSockOptInt(unix.SO_MARK)
}

func (u *StdConn) LocalAddr() (netip.AddrPort, error) {
	a := u.udpConn.LocalAddr()

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

func recvmmsg(fd uintptr, msgs []rawMessage) (int, bool, error) {
	var errno syscall.Errno
	n, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		fd,
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		unix.MSG_WAITFORONE,
		0,
		0,
	)
	if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
		// No data available, block for I/O and try again.
		return int(n), false, nil
	}
	if errno != 0 {
		return int(n), true, &net.OpError{Op: "recvmmsg", Err: errno}
	}
	return int(n), true, nil
}

func (u *StdConn) listenOutSingle(r EncReader, flush func()) error {
	var err error
	var n int
	var from netip.AddrPort
	buffer := make([]byte, MTU)

	for {
		n, from, err = u.udpConn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		// listenOutSingle uses ReadFromUDPAddrPort which discards cmsgs,
		// so the outer ECN field is not visible on this path. Zero RxMeta
		// (Not-ECT) means RFC 6040 combine is a no-op.
		r(from, buffer[:n], RxMeta{})
		flush()
	}
}

// readSockaddr decodes the source address out of a recvmmsg name buffer
func (u *StdConn) readSockaddr(name []byte) netip.AddrPort {
	var ip netip.Addr
	// It's ok to skip the ok check here, the slicing is the only error that can occur and it will panic
	if u.isV4 {
		ip, _ = netip.AddrFromSlice(name[4:8])
	} else {
		ip, _ = netip.AddrFromSlice(name[8:24])
	}
	return netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(name[2:4]))
}

func (u *StdConn) listenOutBatch(r EncReader, flush func()) error {
	var n int
	var operr error

	bufSize := MTU
	cmsgSpace := 0
	msgs, buffers, names, _ := u.PrepareRawMessages(u.batch, bufSize, cmsgSpace)

	//reader needs to capture variables from this function, since it's used as a lambda with rawConn.Read
	//defining it outside the loop so it gets re-used
	reader := func(fd uintptr) (done bool) {
		n, done, operr = recvmmsg(fd, msgs)
		return done
	}

	for {
		err := u.rawConn.Read(reader)
		if err != nil {
			return err
		}
		if operr != nil {
			return operr
		}

		for i := 0; i < n; i++ {
			r(u.readSockaddr(names[i]), buffers[i][:msgs[i].Len], RxMeta{})
		}

		flush()
	}
}

func (u *StdConn) ListenOut(r EncReader, flush func()) error {
	if u.batch == 1 {
		return u.listenOutSingle(r, flush)
	} else {
		return u.listenOutBatch(r, flush)
	}
}

func (u *StdConn) WriteTo(b []byte, ip netip.AddrPort) error {
	_, err := u.udpConn.WriteToUDPAddrPort(b, ip)
	return err
}

// WriteBatch sends bufs via sendmmsg(2) using the preallocated scratch on
// StdConn. If supported, consecutive packets to the same destination with
// matching segment sizes (all but possibly the last) are coalesced into a
// single mmsghdr entry
//
// If sendmmsg returns an error and zero entries went out, we fall back to
// per-packet WriteTo for that chunk so the caller still gets best-effort
// delivery. On a partial send we resume at the first un-acked entry on
// the next iteration.
func (u *StdConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort, _ []byte) error {
	for i := 0; i < len(bufs); {
		chunk := min(len(bufs)-i, len(u.writeMsgs))

		for k := 0; k < chunk; k++ {
			u.writeIovs[k].Base = &bufs[i+k][0]
			setIovLen(&u.writeIovs[k], len(bufs[i+k]))

			nlen, err := writeSockaddr(u.writeNames[k], addrs[i+k], u.isV4)
			if err != nil {
				return err
			}

			hdr := &u.writeMsgs[k].Hdr
			hdr.Iov = &u.writeIovs[k]
			setMsgIovlen(hdr, 1)
			hdr.Namelen = uint32(nlen)
		}

		sent, serr := u.sendmmsg(chunk)
		if serr != nil && sent <= 0 {
			// sendmmsg returns -1 / sent=0 when entry 0 itself failed; log
			// that entry's destination and fall back to per-packet WriteTo
			// for the whole chunk so the caller still gets best-effort
			// delivery without duplicating packets the kernel accepted.
			u.l.Warn("sendmmsg failed, falling back to per-packet WriteTo",
				"err", serr,
				"entries", chunk,
				"entry0_dst", addrs[i],
				"isV4", u.isV4,
			)
			for k := 0; k < chunk; k++ {
				if werr := u.WriteTo(bufs[i+k], addrs[i+k]); werr != nil {
					return werr
				}
			}
			i += chunk
			continue
		}
		i += sent
	}
	return nil
}

// sendmmsg issues sendmmsg(2) against the first n entries of u.writeMsgs.
// The bound u.sendmmsgCB is passed to rawConn.Write so no closure is
// allocated per call; inputs and outputs ride on the StdConn fields.
func (u *StdConn) sendmmsg(n int) (int, error) {
	u.sendmmsgN = n
	u.sendmmsgSent = 0
	u.sendmmsgErrno = 0
	if err := u.rawConn.Write(u.sendmmsgCB); err != nil {
		return u.sendmmsgSent, err
	}
	if u.sendmmsgErrno != 0 {
		return u.sendmmsgSent, &net.OpError{Op: "sendmmsg", Err: u.sendmmsgErrno}
	}
	return u.sendmmsgSent, nil
}

// sendmmsgRun is the rawConn.Write callback. It is bound once into
// u.sendmmsgCB at construction so it stays alloc-free in the hot path;
// inputs (sendmmsgN) and outputs (sendmmsgSent, sendmmsgErrno) ride on
// the receiver rather than escaping locals.
func (u *StdConn) sendmmsgRun(fd uintptr) bool {
	r1, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, fd,
		uintptr(unsafe.Pointer(&u.writeMsgs[0])), uintptr(u.sendmmsgN),
		0, 0, 0,
	)
	if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
		return false
	}
	u.sendmmsgSent = int(r1)
	u.sendmmsgErrno = errno
	return true
}

// writeSockaddr encodes addr into buf (which must be at least
// SizeofSockaddrInet6 bytes). Returns the number of bytes used. If isV4 is
// true and addr is not a v4 (or v4-in-v6) address, returns an error.
func writeSockaddr(buf []byte, addr netip.AddrPort, isV4 bool) (int, error) {
	ap := addr.Addr().Unmap()
	if isV4 {
		if !ap.Is4() {
			return 0, ErrInvalidIPv6RemoteForSocket
		}
		// struct sockaddr_in: { sa_family_t(2), in_port_t(2, BE), in_addr(4), zero(8) }
		// sa_family is host endian.
		binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET)
		binary.BigEndian.PutUint16(buf[2:4], addr.Port())
		ip4 := ap.As4()
		copy(buf[4:8], ip4[:])
		clear(buf[8:16])
		return unix.SizeofSockaddrInet4, nil
	}
	// struct sockaddr_in6: { sa_family_t(2), in_port_t(2, BE), flowinfo(4), in6_addr(16), scope_id(4) }
	binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(buf[2:4], addr.Port())
	binary.NativeEndian.PutUint32(buf[4:8], 0)
	ip6 := addr.Addr().As16()
	copy(buf[8:24], ip6[:])
	binary.NativeEndian.PutUint32(buf[24:28], 0)
	return unix.SizeofSockaddrInet6, nil
}

func (u *StdConn) ReloadConfig(c *config.C) {
	b := c.GetInt("listen.read_buffer", 0)
	if b > 0 {
		err := u.SetRecvBuffer(b)
		if err == nil {
			s, err := u.GetRecvBuffer()
			if err == nil {
				u.l.Info("listen.read_buffer was set", "size", s)
			} else {
				u.l.Warn("Failed to get listen.read_buffer", "error", err)
			}
		} else {
			u.l.Error("Failed to set listen.read_buffer", "error", err)
		}
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		err := u.SetSendBuffer(b)
		if err == nil {
			s, err := u.GetSendBuffer()
			if err == nil {
				u.l.Info("listen.write_buffer was set", "size", s)
			} else {
				u.l.Warn("Failed to get listen.write_buffer", "error", err)
			}
		} else {
			u.l.Error("Failed to set listen.write_buffer", "error", err)
		}
	}

	b = c.GetInt("listen.so_mark", 0)
	s, err := u.GetSoMark()
	if b > 0 || (err == nil && s != 0) {
		err := u.SetSoMark(b)
		if err == nil {
			s, err := u.GetSoMark()
			if err == nil {
				u.l.Info("listen.so_mark was set", "mark", s)
			} else {
				u.l.Warn("Failed to get listen.so_mark", "error", err)
			}
		} else {
			u.l.Error("Failed to set listen.so_mark", "error", err)
		}
	}
}

func (u *StdConn) getMemInfo(meminfo *[unix.SK_MEMINFO_VARS]uint32) error {
	var vallen uint32 = 4 * unix.SK_MEMINFO_VARS

	if u.rawConn == nil {
		return fmt.Errorf("no UDP connection")
	}
	var opErr error
	err := u.rawConn.Control(func(fd uintptr) {
		_, _, syserr := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(unix.SOL_SOCKET), uintptr(unix.SO_MEMINFO), uintptr(unsafe.Pointer(meminfo)), uintptr(unsafe.Pointer(&vallen)), 0)
		if syserr != 0 {
			opErr = syserr
		}
	})
	if err != nil {
		return err
	}
	return opErr
}

func (u *StdConn) Close() error {
	if u.udpConn != nil {
		return u.udpConn.Close()
	}
	return nil
}

func NewUDPStatsEmitter(udpConns []Conn) func() {
	// Check if our kernel supports SO_MEMINFO before registering the gauges
	var udpGauges [][unix.SK_MEMINFO_VARS]metrics.Gauge
	var meminfo [unix.SK_MEMINFO_VARS]uint32
	if err := udpConns[0].(*StdConn).getMemInfo(&meminfo); err == nil {
		udpGauges = make([][unix.SK_MEMINFO_VARS]metrics.Gauge, len(udpConns))
		for i := range udpConns {
			udpGauges[i] = [unix.SK_MEMINFO_VARS]metrics.Gauge{
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.rmem_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.rcvbuf", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.wmem_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.sndbuf", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.fwd_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.wmem_queued", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.optmem", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.backlog", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.drops", i), nil),
			}
		}
	}

	return func() {
		for i, gauges := range udpGauges {
			if err := udpConns[i].(*StdConn).getMemInfo(&meminfo); err == nil {
				for j := 0; j < unix.SK_MEMINFO_VARS; j++ {
					gauges[j].Update(int64(meminfo[j]))
				}
			}
		}
	}
}
