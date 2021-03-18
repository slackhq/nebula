// +build !android

package udp

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	c "github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

//TODO: make it support reload as best you can!

type linuxConn struct {
	fd    int
	l     *logrus.Logger
	mtu   int
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

func NewConn(ip string, port int, batch int, multi bool, mtu int, l *logrus.Logger) (*linuxConn, error) {
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

	if multi {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return nil, fmt.Errorf("unable to set SO_REUSEPORT: %s", err)
		}
	}

	var lip [16]byte
	copy(lip[:], net.ParseIP(ip))

	//TODO: support multiple listening IPs (for limiting ipv6)
	if err = unix.Bind(fd, &unix.SockaddrInet6{Addr: lip, Port: port}); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	//TODO: this may be useful for forcing threads into specific cores
	//unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU, x)
	//v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU)
	//l.Println(v, err)

	return &linuxConn{fd: fd, l: l, batch: batch, mtu: mtu}, err
}

func (lc *linuxConn) Rebind() error {
	return nil
}

func (lc *linuxConn) SetRecvBuffer(n int) error {
	return unix.SetsockoptInt(lc.fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
}

func (lc *linuxConn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(lc.fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (lc *linuxConn) GetRecvBuffer() (int, error) {
	return unix.GetsockoptInt(lc.fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (lc *linuxConn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(lc.fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (lc *linuxConn) LocalAddr() (*Addr, error) {
	sa, err := unix.Getsockname(lc.fd)
	if err != nil {
		return nil, err
	}

	addr := &Addr{}
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		addr.IP = sa.Addr[0:]
		addr.Port = uint16(sa.Port)
	case *unix.SockaddrInet6:
		addr.IP = sa.Addr[0:]
		addr.Port = uint16(sa.Port)
	}

	return addr, nil
}

func (lc *linuxConn) ListenOut(reader EncReader, lhf LightHouseHandlerFunc, cache *ConntrackCacheTicker, q int) error {
	plaintext := make([]byte, lc.mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	addr := &Addr{}
	nb := make([]byte, 12, 12)

	msgs, buffers, names := lc.PrepareRawMessages(lc.batch)
	read := lc.readMulti
	if lc.batch == 1 {
		read = lc.readSingle
	}

	for {
		n, err := read(msgs)
		if err != nil {
			lc.l.WithError(err).Error("Failed to read packets")
			continue
		}

		//metric.Update(int64(n))
		for i := 0; i < n; i++ {
			addr.IP = names[i][8:24]
			addr.Port = binary.BigEndian.Uint16(names[i][2:4])
			reader(addr, plaintext[:0], buffers[i][:msgs[i].Len], header, fwPacket, lhf, nb, q, cache.Get())
		}
	}
}

func (lc *linuxConn) readSingle(msgs []rawMessage) (int, error) {
	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMSG,
			uintptr(lc.fd),
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

func (lc *linuxConn) readMulti(msgs []rawMessage) (int, error) {
	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMMSG,
			uintptr(lc.fd),
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

func (lc *linuxConn) WriteTo(b []byte, addr *Addr) error {
	var rsa unix.RawSockaddrInet6
	rsa.Family = unix.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&rsa.Port))
	p[0] = byte(addr.Port >> 8)
	p[1] = byte(addr.Port)
	copy(rsa.Addr[:], addr.IP)

	for {
		_, _, err := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(lc.fd),
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

func (lc *linuxConn) ReloadConfig(c *c.Config) {
	configSetBuffers(lc, c)
}

func (lc *linuxConn) getMemInfo(meminfo *_SK_MEMINFO) error {
	var vallen uint32 = 4 * _SK_MEMINFO_VARS
	_, _, err := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(lc.fd),
		uintptr(unix.SOL_SOCKET),
		uintptr(unix.SO_MEMINFO),
		uintptr(unsafe.Pointer(meminfo)),
		uintptr(unsafe.Pointer(&vallen)),
		0,
	)
	if err != 0 {
		return err
	}
	return nil
}

func (lc *linuxConn) logger() *logrus.Logger {
	return lc.l
}

func (lc *linuxConn) EmitStats() {
	//TODO
}

//func NewUDPStatsEmitter(udpConns []*udpConn) func() {
//	// Check if our kernel supports SO_MEMINFO before registering the gauges
//	var udpGauges [][_SK_MEMINFO_VARS]metrics.Gauge
//	var meminfo _SK_MEMINFO
//	if err := udpConns[0].getMemInfo(&meminfo); err == nil {
//		udpGauges = make([][_SK_MEMINFO_VARS]metrics.Gauge, len(udpConns))
//		for i := range udpConns {
//			udpGauges[i] = [_SK_MEMINFO_VARS]metrics.Gauge{
//				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.rmem_alloc", i), nil),
//				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.rcvbuf", i), nil),
//				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.wmem_alloc", i), nil),
//				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.sndbuf", i), nil),
//				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.fwd_alloc", i), nil),
//				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.wmem_queued", i), nil),
//				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.optmem", i), nil),
//				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.backlog", i), nil),
//				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.drops", i), nil),
//			}
//		}
//	}
//
//	return func() {
//		for i, gauges := range udpGauges {
//			if err := udpConns[i].getMemInfo(&meminfo); err == nil {
//				for j := 0; j < _SK_MEMINFO_VARS; j++ {
//					gauges[j].Update(int64(meminfo[j]))
//				}
//			}
//		}
//	}
//}
