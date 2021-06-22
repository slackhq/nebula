// +build !android
// +build !e2e_testing

package nebula

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

//TODO: make it support reload as best you can!

type udpConn struct {
	sysFd int
	l     *logrus.Logger
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

func NewListener(l *logrus.Logger, ip string, port int, multi bool) (*udpConn, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}

	var lip [16]byte
	copy(lip[:], net.ParseIP(ip))

	if multi {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return nil, fmt.Errorf("unable to set SO_REUSEPORT: %s", err)
		}
	}

	//TODO: support multiple listening IPs (for limiting ipv6)
	if err = unix.Bind(fd, &unix.SockaddrInet6{Addr: lip, Port: port}); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	//TODO: this may be useful for forcing threads into specific cores
	//unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU, x)
	//v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU)
	//l.Println(v, err)

	return &udpConn{sysFd: fd, l: l}, err
}

func (u *udpConn) Rebind() error {
	return nil
}

func (u *udpConn) SetRecvBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
}

func (u *udpConn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (u *udpConn) GetRecvBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (u *udpConn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (u *udpConn) LocalAddr() (*udpAddr, error) {
	sa, err := unix.Getsockname(u.sysFd)
	if err != nil {
		return nil, err
	}

	addr := &udpAddr{}
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

func (u *udpConn) ListenOut(f *Interface, q int) {
	plaintext := make([]byte, mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	udpAddr := &udpAddr{}
	nb := make([]byte, 12, 12)

	lhh := f.lightHouse.NewRequestHandler()

	//TODO: should we track this?
	//metric := metrics.GetOrRegisterHistogram("test.batch_read", nil, metrics.NewExpDecaySample(1028, 0.015))
	msgs, buffers, names := u.PrepareRawMessages(f.udpBatchSize)
	read := u.ReadMulti
	if f.udpBatchSize == 1 {
		read = u.ReadSingle
	}

	conntrackCache := NewConntrackCacheTicker(f.conntrackCacheTimeout)

	for {
		n, err := read(msgs)
		if err != nil {
			u.l.WithError(err).Error("Failed to read packets")
			continue
		}

		//metric.Update(int64(n))
		for i := 0; i < n; i++ {
			udpAddr.IP = names[i][8:24]
			udpAddr.Port = binary.BigEndian.Uint16(names[i][2:4])
			f.readOutsidePackets(udpAddr, plaintext[:0], buffers[i][:msgs[i].Len], header, fwPacket, lhh, nb, q, conntrackCache.Get(u.l))
		}
	}
}

func (u *udpConn) ReadSingle(msgs []rawMessage) (int, error) {
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

func (u *udpConn) ReadMulti(msgs []rawMessage) (int, error) {
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

func (u *udpConn) WriteTo(b []byte, addr *udpAddr) error {

	var rsa unix.RawSockaddrInet6
	rsa.Family = unix.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&rsa.Port))
	p[0] = byte(addr.Port >> 8)
	p[1] = byte(addr.Port)
	copy(rsa.Addr[:], addr.IP)

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

		//TODO: handle incomplete writes

		return nil
	}
}

func (u *udpConn) reloadConfig(c *Config) {
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

func (u *udpConn) getMemInfo(meminfo *_SK_MEMINFO) error {
	var vallen uint32 = 4 * _SK_MEMINFO_VARS
	_, _, err := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(u.sysFd), uintptr(unix.SOL_SOCKET), uintptr(unix.SO_MEMINFO), uintptr(unsafe.Pointer(meminfo)), uintptr(unsafe.Pointer(&vallen)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func NewUDPStatsEmitter(udpConns []*udpConn) func() {
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

func hostDidRoam(addr *udpAddr, newaddr *udpAddr) bool {
	return !addr.Equals(newaddr)
}
