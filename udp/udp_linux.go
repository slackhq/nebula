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
	"github.com/slackhq/nebula/packet"
	"golang.org/x/sys/unix"
)

const iovMax = 128 //1024 //no unix constant for this? from limits.h
//todo I'd like this to be 1024 but we seem to hit errors around ~130?

type StdConn struct {
	sysFd     int
	isV4      bool
	l         *logrus.Logger
	batch     int
	enableGRO bool

	msgs []rawMessage
	iovs [][]iovec
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

	const batchSize = 8192
	msgs := make([]rawMessage, 0, batchSize) //todo configure
	iovs := make([][]iovec, batchSize)
	for i := range iovs {
		iovs[i] = make([]iovec, iovMax)
	}
	return &StdConn{
		sysFd: fd,
		isV4:  ip.Is4(),
		l:     l,
		batch: batch,
		msgs:  msgs,
		iovs:  iovs,
	}, err
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
	msgs, packets := u.PrepareRawMessages(u.batch, u.isV4)
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
			packets[i].Payload = packets[i].Payload[:msgs[i].Len]
			packets[i].Update(getRawMessageControlLen(&msgs[i]))
		}
		r(packets[:n])
		for i := 0; i < n; i++ { //todo reset this in prev loop, but this makes debug ez
			msgs[i].Hdr.Controllen = uint64(unix.CmsgSpace(2))
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

func (u *StdConn) WriteToBatch(b []byte, ip netip.AddrPort) error {
	if u.isV4 {
		return u.writeTo4(b, ip)
	}
	return u.writeTo6(b, ip)
}

func (u *StdConn) Prep(pkt *packet.Packet, addr netip.AddrPort) error {
	nl, err := u.encodeSockaddr(pkt.Name, addr)
	if err != nil {
		return err
	}
	pkt.ReadyToSend = true
	pkt.Name = pkt.Name[:nl]
	return nil
}

func (u *StdConn) WriteBatch(pkts []*packet.Packet) (int, error) {
	if len(pkts) == 0 {
		return 0, nil
	}

	u.msgs = u.msgs[:0]
	//u.iovs = u.iovs[:0]

	sent := 0
	var mostRecentPkt *packet.Packet
	mostRecentPktSize := 0
	//segmenting := false
	idx := 0
	for _, pkt := range pkts {
		if !pkt.ReadyToSend || len(pkt.Payload) == 0 {
			sent++
			continue
		}
		lastIdx := idx - 1
		if mostRecentPkt != nil && pkt.CompatibleForSegmentationWith(mostRecentPkt, mostRecentPktSize) && u.msgs[lastIdx].Hdr.Iovlen < iovMax {
			u.msgs[lastIdx].Hdr.Controllen = uint64(len(mostRecentPkt.Control))
			u.msgs[lastIdx].Hdr.Control = &mostRecentPkt.Control[0]

			u.iovs[lastIdx][u.msgs[lastIdx].Hdr.Iovlen].Base = &pkt.Payload[0]
			u.iovs[lastIdx][u.msgs[lastIdx].Hdr.Iovlen].Len = uint64(len(pkt.Payload))
			u.msgs[lastIdx].Hdr.Iovlen++

			mostRecentPktSize += len(pkt.Payload)
			mostRecentPkt.SetSegSizeForTX()
		} else {
			u.msgs = append(u.msgs, rawMessage{})
			u.iovs[idx][0] = iovec{
				Base: &pkt.Payload[0],
				Len:  uint64(len(pkt.Payload)),
			}

			msg := &u.msgs[idx]
			iov := &u.iovs[idx][0]
			idx++

			msg.Hdr.Iov = iov
			msg.Hdr.Iovlen = 1
			setRawMessageControl(msg, nil)
			msg.Hdr.Flags = 0

			msg.Hdr.Name = &pkt.Name[0]
			msg.Hdr.Namelen = uint32(len(pkt.Name))
			mostRecentPkt = pkt
			mostRecentPktSize = len(pkt.Payload)
		}
	}

	if len(u.msgs) == 0 {
		return sent, nil
	}

	offset := 0
	for offset < len(u.msgs) {
		n, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&u.msgs[offset])),
			uintptr(len(u.msgs)-offset),
			0,
			0,
			0,
		)

		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			//for i := 0; i < len(u.msgs); i++ {
			//	for j := 0; j < int(u.msgs[i].Hdr.Iovlen); j++ {
			//		u.l.WithFields(logrus.Fields{
			//			"msg_index": i,
			//			"iov idx":   j,
			//			"iov":       fmt.Sprintf("%+v", u.iovs[i][j]),
			//		}).Warn("failed to send message")
			//	}
			//
			//}
			u.l.WithFields(logrus.Fields{
				"errno":   errno,
				"idx":     idx,
				"len":     len(u.msgs),
				"deets":   fmt.Sprintf("%+v", u.msgs),
				"lastIOV": fmt.Sprintf("%+v", u.iovs[len(u.msgs)-1][u.msgs[len(u.msgs)-1].Hdr.Iovlen-1]),
			}).Error("failed to send message")
			return sent + offset, &net.OpError{Op: "sendmmsg", Err: errno}
		}

		if n == 0 {
			break
		}
		offset += int(n)
	}

	return sent + len(u.msgs), nil
}

func (u *StdConn) encodeSockaddr(dst []byte, addr netip.AddrPort) (uint32, error) {
	if u.isV4 {
		if !addr.Addr().Is4() {
			return 0, fmt.Errorf("Listener is IPv4, but writing to IPv6 remote")
		}
		var sa unix.RawSockaddrInet4
		sa.Family = unix.AF_INET
		sa.Addr = addr.Addr().As4()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], addr.Port())
		size := unix.SizeofSockaddrInet4
		copy(dst[:size], (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa)))[:])
		return uint32(size), nil
	}

	var sa unix.RawSockaddrInet6
	sa.Family = unix.AF_INET6
	sa.Addr = addr.Addr().As16()
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], addr.Port())
	size := unix.SizeofSockaddrInet6
	copy(dst[:size], (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&sa)))[:])
	return uint32(size), nil
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
	u.configureGRO(true)
}

func (u *StdConn) configureGRO(enable bool) {
	if enable == u.enableGRO {
		return
	}

	if enable {
		if err := unix.SetsockoptInt(u.sysFd, unix.SOL_UDP, unix.UDP_GRO, 1); err != nil {
			u.l.WithError(err).Warn("Failed to enable UDP GRO")
			return
		}
		u.enableGRO = true
		u.l.Info("UDP GRO enabled")
	} else {
		if err := unix.SetsockoptInt(u.sysFd, unix.SOL_UDP, unix.UDP_GRO, 0); err != nil && err != unix.ENOPROTOOPT {
			u.l.WithError(err).Warn("Failed to disable UDP GRO")
		}
		u.enableGRO = false
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
