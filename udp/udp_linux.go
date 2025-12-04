//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
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
	sysFd int
	isV4  bool
	l     *logrus.Logger
	batch int
}

func maybeIPV4(ip net.IP) (net.IP, bool) {
	ip4 := ip.To4()
	if ip4 != nil {
		return ip4, true
	}
	return ip, false
}

func NewListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	af := unix.AF_INET6
	if ip.Is4() {
		af = unix.AF_INET
	}
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(af, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}

	if multi {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return nil, fmt.Errorf("unable to set SO_REUSEPORT: %s", err)
		}
	}

	var sa unix.Sockaddr
	if ip.Is4() {
		sa4 := &unix.SockaddrInet4{Port: port}
		sa4.Addr = ip.As4()
		sa = sa4
	} else {
		sa6 := &unix.SockaddrInet6{Port: port}
		sa6.Addr = ip.As16()
		sa = sa6
	}
	if err = unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	return &StdConn{sysFd: fd, isV4: ip.Is4(), l: l, batch: batch}, err
}

func (u *StdConn) SupportsMultipleReaders() bool {
	return true
}

func (u *StdConn) Rebind() error {
	return nil
}

func (u *StdConn) SetRecvBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
}

func (u *StdConn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (u *StdConn) SetSoMark(mark int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_MARK, mark)
}

func (u *StdConn) GetRecvBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (u *StdConn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (u *StdConn) GetSoMark() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_MARK)
}

func (u *StdConn) LocalAddr() (netip.AddrPort, error) {
	sa, err := unix.Getsockname(u.sysFd)
	if err != nil {
		return netip.AddrPort{}, err
	}

	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port)), nil

	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), uint16(sa.Port)), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported sock type: %T", sa)
	}
}

func (u *StdConn) ListenOut(r EncReader) {
	var ip netip.Addr

	msgs, buffers, names := u.PrepareRawMessages(u.batch)
	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	for {
		n, err := read(msgs)
		if err != nil {
			u.l.WithError(err).Debug("udp socket is closed, exiting read loop")
			return
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

func (u *StdConn) ReadSingle(msgs []rawMessage) (int, error) {
	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&(msgs[0].Hdr))),
			0,
			0,
			0,
			0,
		)

		if err != 0 {
			return 0, &net.OpError{Op: "recvmsg", Err: err}
		}

		msgs[0].Len = uint32(n)
		return 1, nil
	}
}

func (u *StdConn) ReadMulti(msgs []rawMessage) (int, error) {
	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(len(msgs)),
			unix.MSG_WAITFORONE,
			0,
			0,
		)

		if err != 0 {
			return 0, &net.OpError{Op: "recvmmsg", Err: err}
		}

		return int(n), nil
	}
}

func (u *StdConn) WriteTo(b []byte, ip netip.AddrPort) error {
	if u.isV4 {
		return u.writeTo4(b, ip)
	}
	return u.writeTo6(b, ip)
}

func (u *StdConn) writeTo6(b []byte, ip netip.AddrPort) error {
	var rsa unix.RawSockaddrInet6
	rsa.Family = unix.AF_INET6
	rsa.Addr = ip.Addr().As16()
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:], ip.Port())

	for {
		_, _, err := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)),
			uintptr(0),
			uintptr(unsafe.Pointer(&rsa)),
			uintptr(unix.SizeofSockaddrInet6),
		)

		if err != 0 {
			return &net.OpError{Op: "sendto", Err: err}
		}

		return nil
	}
}

func (u *StdConn) writeTo4(b []byte, ip netip.AddrPort) error {
	if !ip.Addr().Is4() {
		return ErrInvalidIPv6RemoteForSocket
	}

	var rsa unix.RawSockaddrInet4
	rsa.Family = unix.AF_INET
	rsa.Addr = ip.Addr().As4()
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:], ip.Port())

	for {
		_, _, err := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)),
			uintptr(0),
			uintptr(unsafe.Pointer(&rsa)),
			uintptr(unix.SizeofSockaddrInet4),
		)

		if err != 0 {
			return &net.OpError{Op: "sendto", Err: err}
		}

		return nil
	}
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
	_, _, err := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(u.sysFd), uintptr(unix.SOL_SOCKET), uintptr(unix.SO_MEMINFO), uintptr(unsafe.Pointer(meminfo)), uintptr(unsafe.Pointer(&vallen)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func (u *StdConn) Close() error {
	return syscall.Close(u.sysFd)
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
