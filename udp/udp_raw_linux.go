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
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// RawOverhead is the number of bytes that need to be reserved at the start of
// the raw bytes passed to (*RawConn).WriteTo. This is used by WriteTo to prefix
// the IP and UDP headers.
const RawOverhead = 28

type RawConn struct {
	sysFd    int
	basePort uint16
	l        *logrus.Logger
}

func NewRawConn(l *logrus.Logger, ip string, port int, basePort uint16) (*RawConn, error) {
	syscall.ForkLock.RLock()
	// With IPPROTO_UDP, the linux kernel tries to deliver every UDP packet
	// received in the system to our socket. This constantly overflows our
	// buffer and marks our socket as having dropped packets. This makes the
	// stats on the socket useless.
	//
	// In contrast, IPPROTO_RAW is not delivered any packets and thus our read
	// buffer will not fill up and mark as having dropped packets. The only
	// difference is that we have to assemble the IP header as well, but this
	// is fairly easy since Linux does the checksum for us.
	//
	// TODO: How to get this working with Inet6 correctly? I was having issues
	// with the source address when testing before, probably need to `bind(2)`?
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, err
	}

	// We only want to send, not recv. This will hopefully help the kernel avoid
	// wasting time on us
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 0); err != nil {
		return nil, fmt.Errorf("unable to set SO_RCVBUF: %s", err)
	}

	var lip [16]byte
	copy(lip[:], net.ParseIP(ip))

	// TODO do we need to `bind(2)` so that we send from the correct address/interface?
	if err = unix.Bind(fd, &unix.SockaddrInet6{Addr: lip, Port: port}); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	return &RawConn{
		sysFd:    fd,
		basePort: basePort,
		l:        l,
	}, nil
}

// WriteTo must be called with raw leaving the first `udp.RawOverhead` bytes empty,
// for the IP/UDP headers.
func (u *RawConn) WriteTo(raw []byte, fromPort uint16, ip netip.AddrPort) error {
	var rsa unix.RawSockaddrInet4
	rsa.Family = unix.AF_INET
	rsa.Addr = ip.Addr().As4()

	totalLen := len(raw)
	udpLen := totalLen - ipv4.HeaderLen

	// IP header
	raw[0] = byte(ipv4.Version<<4 | (ipv4.HeaderLen >> 2 & 0x0f))
	raw[1] = 0 // tos
	binary.BigEndian.PutUint16(raw[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(raw[4:6], 0)   // id (linux does it for us)
	binary.BigEndian.PutUint16(raw[6:8], 0)   // frag options
	raw[8] = byte(64)                         // ttl
	raw[9] = byte(17)                         // protocol
	binary.BigEndian.PutUint16(raw[10:12], 0) // checksum (linux does it for us)
	binary.BigEndian.PutUint32(raw[12:16], 0) // src (linux does it for us)
	copy(raw[16:20], rsa.Addr[:])             // dst

	// UDP header
	fromPort = u.basePort + fromPort
	binary.BigEndian.PutUint16(raw[20:22], uint16(fromPort))  // src port
	binary.BigEndian.PutUint16(raw[22:24], uint16(ip.Port())) // dst port
	binary.BigEndian.PutUint16(raw[24:26], uint16(udpLen))    // UDP length
	binary.BigEndian.PutUint16(raw[26:28], 0)                 // checksum (optional)

	for {
		_, _, err := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&raw[0])),
			uintptr(len(raw)),
			uintptr(0),
			uintptr(unsafe.Pointer(&rsa)),
			uintptr(unix.SizeofSockaddrInet4),
		)

		if err != 0 {
			return &net.OpError{Op: "sendto", Err: err}
		}

		//TODO: handle incomplete writes

		return nil
	}
}

func (u *RawConn) ReloadConfig(c *config.C) {
	b := c.GetInt("listen.write_buffer", 0)
	if b <= 0 {
		return
	}

	if err := u.SetSendBuffer(b); err != nil {
		u.l.WithError(err).Error("Failed to set listen.write_buffer")
		return
	}

	s, err := u.GetSendBuffer()
	if err != nil {
		u.l.WithError(err).Warn("Failed to get listen.write_buffer")
		return
	}

	u.l.WithField("size", s).Info("listen.write_buffer was set")
}

func (u *RawConn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (u *RawConn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (u *RawConn) getMemInfo(meminfo *[unix.SK_MEMINFO_VARS]uint32) error {
	var vallen uint32 = 4 * unix.SK_MEMINFO_VARS
	_, _, err := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(u.sysFd), uintptr(unix.SOL_SOCKET), uintptr(unix.SO_MEMINFO), uintptr(unsafe.Pointer(meminfo)), uintptr(unsafe.Pointer(&vallen)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func NewRawStatsEmitter(rawConn *RawConn) func() {
	// Check if our kernel supports SO_MEMINFO before registering the gauges
	var gauges [unix.SK_MEMINFO_VARS]metrics.Gauge
	var meminfo [unix.SK_MEMINFO_VARS]uint32
	if err := rawConn.getMemInfo(&meminfo); err == nil {
		gauges = [unix.SK_MEMINFO_VARS]metrics.Gauge{
			metrics.GetOrRegisterGauge("raw.rmem_alloc", nil),
			metrics.GetOrRegisterGauge("raw.rcvbuf", nil),
			metrics.GetOrRegisterGauge("raw.wmem_alloc", nil),
			metrics.GetOrRegisterGauge("raw.sndbuf", nil),
			metrics.GetOrRegisterGauge("raw.fwd_alloc", nil),
			metrics.GetOrRegisterGauge("raw.wmem_queued", nil),
			metrics.GetOrRegisterGauge("raw.optmem", nil),
			metrics.GetOrRegisterGauge("raw.backlog", nil),
			metrics.GetOrRegisterGauge("raw.drops", nil),
		}
	} else {
		// return no-op because we don't support SO_MEMINFO
		return func() {}
	}

	return func() {
		if err := rawConn.getMemInfo(&meminfo); err == nil {
			for j := 0; j < unix.SK_MEMINFO_VARS; j++ {
				gauges[j].Update(int64(meminfo[j]))
			}
		}
	}
}
