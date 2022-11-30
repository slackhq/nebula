//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"golang.org/x/sys/unix"
)

//TODO: make it support reload as best you can!

type Conn struct {
	sysFd int
	isV4  bool
	l     *logrus.Logger
	batch int
}

var x int

// From linux/sock_diag.h
const (
	_SK_MEMINFO_RMEM_ALLOC = iota
	_SK_MEMINFO_RCVBUF
	_SK_MEMINFO_WMEM_ALLOC
	_SK_MEMINFO_SNDBUF
	_SK_MEMINFO_FWD_ALLOC
	_SK_MEMINFO_WMEM_QUEUED
	_SK_MEMINFO_OPTMEM
	_SK_MEMINFO_BACKLOG
	_SK_MEMINFO_DROPS

	_SK_MEMINFO_VARS
)

type _SK_MEMINFO [_SK_MEMINFO_VARS]uint32

func isIPV4(ip net.IP) (net.IP, bool) {
	if len(ip) == net.IPv4len {
		return ip, true
	}

	if len(ip) == net.IPv6len && isZeros(ip[0:10]) && ip[10] == 0xff && ip[11] == 0xff {
		return ip[12:16], true
	}

	return ip, false
}

func isZeros(p net.IP) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != 0 {
			return false
		}
	}
	return true
}

func NewListener(l *logrus.Logger, ip string, port int, multi bool, batch int) (*Conn, error) {
	lip := net.ParseIP(ip)
	lipV4, isV4 := isIPV4(lip)
	af := unix.AF_INET6
	if isV4 {
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

	copy(lip[:], net.ParseIP(ip))

	if multi {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return nil, fmt.Errorf("unable to set SO_REUSEPORT: %s", err)
		}
	}

	//TODO: support multiple listening IPs (for limiting ipv6)
	var sa unix.Sockaddr
	if isV4 {
		sa4 := &unix.SockaddrInet4{Port: port}
		copy(sa4.Addr[:], lipV4)
		sa = sa4
	} else {
		sa6 := &unix.SockaddrInet6{Port: port}
		sa = sa6
	}
	if err = unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	//TODO: this may be useful for forcing threads into specific cores
	//unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU, x)
	//v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU)
	//l.Println(v, err)

	return &Conn{sysFd: fd, isV4: isV4, l: l, batch: batch}, err
}

func (u *Conn) Rebind() error {
	return nil
}

func (u *Conn) SetRecvBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
}

func (u *Conn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (u *Conn) GetRecvBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (u *Conn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (u *Conn) LocalAddr() (*Addr, error) {
	sa, err := unix.Getsockname(u.sysFd)
	if err != nil {
		return nil, err
	}

	addr := &Addr{}
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		addr.IP = net.IP{sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]}.To16()
		addr.Port = uint16(sa.Port)
	case *unix.SockaddrInet6:
		addr.IP = sa.Addr[0:]
		addr.Port = uint16(sa.Port)
	}

	return addr, nil
}

func (u *Conn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	udpAddr := &Addr{}
	nb := make([]byte, 12, 12)

	//TODO: should we track this?
	//metric := metrics.GetOrRegisterHistogram("test.batch_read", nil, metrics.NewExpDecaySample(1028, 0.015))
	msgs, buffers, names := u.PrepareRawMessages(u.batch)
	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	for {
		n, err := read(msgs)
		if err != nil {
			u.l.WithError(err).Error("Failed to read packets")
			continue
		}

		//metric.Update(int64(n))
		for i := 0; i < n; i++ {
			if u.isV4 {
				udpAddr.IP = names[i][4:8]
			} else {
				udpAddr.IP = names[i][8:24]
			}
			udpAddr.Port = binary.BigEndian.Uint16(names[i][2:4])
			r(udpAddr, nil, plaintext[:0], buffers[i][:msgs[i].Len], h, fwPacket, lhf, nb, q, cache.Get(u.l))
		}
	}
}

func (u *Conn) ReadSingle(msgs []rawMessage) (int, error) {
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

func (u *Conn) ReadMulti(msgs []rawMessage) (int, error) {
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

func (u *Conn) WriteTo(b []byte, addr *Addr) error {
	var rsaPtr unsafe.Pointer
	var rsaSize int
	if u.isV4 {
		addrV4, isAddrV4 := isIPV4(addr.IP)
		if !isAddrV4 {
			return fmt.Errorf("Listener is IPv4, but writing to IPv6 remote")
		}
		var rsa unix.RawSockaddrInet4
		rsa.Family = unix.AF_INET
		rsa.Port = (addr.Port >> 8) | ((addr.Port & 0xff) << 8)
		copy(rsa.Addr[:], addrV4)
		rsaPtr = unsafe.Pointer(&rsa)
		rsaSize = unix.SizeofSockaddrInet4
	} else {
		var rsa unix.RawSockaddrInet6
		rsa.Family = unix.AF_INET6
		rsa.Port = (addr.Port >> 8) | ((addr.Port & 0xff) << 8)
		copy(rsa.Addr[:], addr.IP)
		rsaPtr = unsafe.Pointer(&rsa)
		rsaSize = unix.SizeofSockaddrInet6
	}

	for {
		_, _, err := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)),
			uintptr(0),
			uintptr(rsaPtr),
			uintptr(rsaSize),
		)

		if err != 0 {
			return &net.OpError{Op: "sendto", Err: err}
		}

		//TODO: handle incomplete writes

		return nil
	}
}

func (u *Conn) ReloadConfig(c *config.C) {
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
}

func (u *Conn) getMemInfo(meminfo *_SK_MEMINFO) error {
	var vallen uint32 = 4 * _SK_MEMINFO_VARS
	_, _, err := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(u.sysFd), uintptr(unix.SOL_SOCKET), uintptr(unix.SO_MEMINFO), uintptr(unsafe.Pointer(meminfo)), uintptr(unsafe.Pointer(&vallen)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func NewUDPStatsEmitter(udpConns []*Conn) func() {
	// Check if our kernel supports SO_MEMINFO before registering the gauges
	var udpGauges [][_SK_MEMINFO_VARS]metrics.Gauge
	var meminfo _SK_MEMINFO
	if err := udpConns[0].getMemInfo(&meminfo); err == nil {
		udpGauges = make([][_SK_MEMINFO_VARS]metrics.Gauge, len(udpConns))
		for i := range udpConns {
			udpGauges[i] = [_SK_MEMINFO_VARS]metrics.Gauge{
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
			if err := udpConns[i].getMemInfo(&meminfo); err == nil {
				for j := 0; j < _SK_MEMINFO_VARS; j++ {
					gauges[j].Update(int64(meminfo[j]))
				}
			}
		}
	}
}
