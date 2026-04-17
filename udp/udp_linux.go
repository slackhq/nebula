//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

type StdConn struct {
	udpConn *net.UDPConn
	rawConn syscall.RawConn
	isV4    bool
	l       *logrus.Logger
	batch   int

	// sendmmsg scratch. Each queue has its own StdConn, so no locking is
	// needed. Sized to MaxWriteBatch at construction; WriteBatch chunks
	// larger inputs.
	writeMsgs  []rawMessage
	writeIovs  []iovec
	writeNames [][]byte
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

func NewListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
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

	return out, nil
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

func (u *StdConn) listenOutSingle(r EncReader) error {
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
		r(from, buffer[:n])
	}
}

func (u *StdConn) listenOutBatch(r EncReader) error {
	var ip netip.Addr
	var n int
	var operr error

	msgs, buffers, names := u.PrepareRawMessages(u.batch)

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
			// Its ok to skip the ok check here, the slicing is the only error that can occur and it will panic
			if u.isV4 {
				ip, _ = netip.AddrFromSlice(names[i][4:8])
			} else {
				ip, _ = netip.AddrFromSlice(names[i][8:24])
			}
			r(netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(names[i][2:4])), buffers[i][:msgs[i].Len])
		}
	}
}

func (u *StdConn) ListenOut(r EncReader) error {
	if u.batch == 1 {
		return u.listenOutSingle(r)
	} else {
		return u.listenOutBatch(r)
	}
}

func (u *StdConn) WriteTo(b []byte, ip netip.AddrPort) error {
	_, err := u.udpConn.WriteToUDPAddrPort(b, ip)
	return err
}

// WriteBatch sends bufs via sendmmsg(2) using the preallocated scratch on
// StdConn. Chunks larger than the scratch are processed in multiple syscalls.
// If sendmmsg returns a fatal error mid-chunk we fall back to single WriteTo
// calls for the remainder so the caller still gets best-effort delivery.
func (u *StdConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) error {
	if len(bufs) != len(addrs) {
		return fmt.Errorf("WriteBatch: len(bufs)=%d != len(addrs)=%d", len(bufs), len(addrs))
	}

	i := 0
	for i < len(bufs) {
		chunk := len(bufs) - i
		if chunk > len(u.writeMsgs) {
			chunk = len(u.writeMsgs)
		}

		for k := 0; k < chunk; k++ {
			b := bufs[i+k]
			if len(b) == 0 {
				// sendmmsg with an empty iovec is legal but pointless; fall
				// through after filling the slot so Base is still valid.
				u.writeIovs[k].Base = nil
				setIovLen(&u.writeIovs[k], 0)
			} else {
				u.writeIovs[k].Base = &b[0]
				setIovLen(&u.writeIovs[k], len(b))
			}
			nlen, err := writeSockaddr(u.writeNames[k], addrs[i+k], u.isV4)
			if err != nil {
				return err
			}
			u.writeMsgs[k].Hdr.Namelen = uint32(nlen)
		}

		sent, serr := u.sendmmsg(chunk)
		if serr != nil {
			if sent <= 0 {
				// nothing went out; fall back to WriteTo for this chunk.
				for k := 0; k < chunk; k++ {
					if err := u.WriteTo(bufs[i+k], addrs[i+k]); err != nil {
						return err
					}
				}
				i += chunk
				continue
			}
			// partial: treat as success for the sent packets and retry the
			// remainder on the next outer-loop iteration.
		}
		if sent == 0 {
			return fmt.Errorf("sendmmsg made no progress")
		}
		i += sent
	}
	return nil
}

func (u *StdConn) sendmmsg(n int) (int, error) {
	var sent int
	var sysErr error
	err := u.rawConn.Write(func(fd uintptr) (done bool) {
		r1, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			fd,
			uintptr(unsafe.Pointer(&u.writeMsgs[0])),
			uintptr(n),
			0,
			0,
			0,
		)
		if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
			return false
		}
		sent = int(r1)
		if errno != 0 {
			sysErr = &net.OpError{Op: "sendmmsg", Err: errno}
		}
		return true
	})
	if err != nil {
		return sent, err
	}
	return sent, sysErr
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
		for j := 8; j < 16; j++ {
			buf[j] = 0
		}
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
				u.l.WithField("size", s).Info("listen.read_buffer was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.read_buffer")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.read_buffer")
		}
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		err := u.SetSendBuffer(b)
		if err == nil {
			s, err := u.GetSendBuffer()
			if err == nil {
				u.l.WithField("size", s).Info("listen.write_buffer was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.write_buffer")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.write_buffer")
		}
	}

	b = c.GetInt("listen.so_mark", 0)
	s, err := u.GetSoMark()
	if b > 0 || (err == nil && s != 0) {
		err := u.SetSoMark(b)
		if err == nil {
			s, err := u.GetSoMark()
			if err == nil {
				u.l.WithField("mark", s).Info("listen.so_mark was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.so_mark")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.so_mark")
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
