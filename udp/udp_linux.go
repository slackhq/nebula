//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/packet"
	"golang.org/x/sys/unix"
)

const (
	defaultGSOMaxSegments  = 16
	defaultGSOFlushTimeout = 150 * time.Microsecond
	maxGSOBatchBytes       = 0xFFFF
)

var (
	errGSOFallback = errors.New("udp gso fallback")
	errGSODisabled = errors.New("udp gso disabled")
)

var readTimeout = unix.NsecToTimeval(int64(time.Millisecond * 500))

type gsoState struct {
	m            sync.Mutex
	Buf          []byte
	Addr         netip.AddrPort
	SegSize      int
	MaxSegments  int
	MaxBytes     int
	FlushTimeout time.Duration
	Timer        *time.Timer

	packets []*packet.Packet
	msg     rawMessage
	name    [unix.SizeofSockaddrInet6]byte
	iov     []iovec
	ctrl    []byte
}

func (g *gsoState) Init() {
	g.iov = make([]iovec, g.MaxSegments)
	for i := 0; i < g.MaxSegments; i++ {
		g.iov[i] = iovec{}
	}
	g.msg.Hdr.Iov = &g.iov[0]
	g.msg.Hdr.Iovlen = 1

	g.packets = make([]*packet.Packet, 0, g.MaxSegments)
	g.ctrl = make([]byte, unix.CmsgSpace(2))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&g.ctrl[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	setCmsgLen(hdr, unix.CmsgLen(2))
	g.msg.Hdr.Control = &g.ctrl[0]
	g.msg.Hdr.Controllen = uint64(len(g.ctrl))

	g.name = [unix.SizeofSockaddrInet6]byte{}
	g.msg.Hdr.Name = &g.name[0]

}

func (g *gsoState) setSegSizeLocked(segSize int) {
	g.SegSize = segSize
	x := unix.CmsgLen(0)
	binary.LittleEndian.PutUint16(g.ctrl[x:x+2], uint16(segSize))
}

func (g *gsoState) setNameLocked(x netip.AddrPort, isV4 bool) {
	g.Addr = x
	nameLen := encodeSockaddr(g.name[:], g.Addr, isV4)
	g.msg.Hdr.Name = &g.name[0]
	g.msg.Hdr.Namelen = nameLen
}

func encodeSockaddr(dst []byte, addr netip.AddrPort, isV4 bool) uint32 {
	if isV4 {
		//todo?
		//if !addr.Addr().Is4() {
		//	return 0, fmt.Errorf("Listener is IPv4, but writing to IPv6 remote")
		//}
		var sa unix.RawSockaddrInet4
		sa.Family = unix.AF_INET
		sa.Addr = addr.Addr().As4()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], addr.Port())
		size := unix.SizeofSockaddrInet4
		copy(dst[:size], (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa)))[:])
		return uint32(size)
	}

	var sa unix.RawSockaddrInet6
	sa.Family = unix.AF_INET6
	sa.Addr = addr.Addr().As16()
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], addr.Port())
	size := unix.SizeofSockaddrInet6
	copy(dst[:size], (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&sa)))[:])
	return uint32(size)
}

func (g *gsoState) sendmsgLocked(fd int) error {
	//name already set
	//ctrl already set
	//g.iov = g.iov[:0]
	g.msg.Hdr.Iovlen = uint64(len(g.packets))
	for i := range g.packets {
		g.iov[i].Base = &g.packets[i].Payload[0]
		g.iov[i].Len = uint64(len(g.packets[i].Payload))
	}

	const flags = 0
	for {
		_, _, err := unix.Syscall(
			unix.SYS_SENDMSG,
			uintptr(fd),
			uintptr(unsafe.Pointer(&g.msg)),
			uintptr(flags),
		)
		//todo no matter what, reset things
		for i := range g.packets {
			pool := packet.GetPool()
			pool.Put(g.packets[i])
		}
		g.packets = g.packets[:0]

		if err != 0 {
			return &net.OpError{Op: "sendmsg", Err: err}
		}

		return nil
	}
}

type StdConn struct {
	sysFd     int
	isV4      bool
	l         *logrus.Logger
	batch     int
	enableGRO bool
	enableGSO bool
	gso       gsoState
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

	// Set a read timeout
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &readTimeout); err != nil {
		return nil, fmt.Errorf("unable to set SO_RCVTIMEO: %s", err)
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

func (u *StdConn) ListenOut(pg PacketBufferGetter, pc chan *packet.Packet) error {
	var ip netip.Addr

	msgs, packets, names := u.PrepareRawMessages(u.batch, pg)
	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	for {
		n, err := read(msgs)
		if err != nil {
			return err
		}

		for i := 0; i < n; i++ {
			out := packets[i]
			out.Payload = out.Payload[:msgs[i].Len]

			// Its ok to skip the ok check here, the slicing is the only error that can occur and it will panic
			if u.isV4 {
				ip, _ = netip.AddrFromSlice(names[i][4:8])
			} else {
				ip, _ = netip.AddrFromSlice(names[i][8:24])
			}
			out.Addr = netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(names[i][2:4]))
			ctrlLen := getRawMessageControlLen(&msgs[i])
			if ctrlLen > 0 {
				packets[i].SegSize = parseGROControl(packets[i].Control[:ctrlLen])
			} else {
				packets[i].SegSize = 0
			}

			pc <- out

			//rotate this packet out so we don't overwrite it
			packets[i] = pg()
			msgs[i].Hdr.Iov.Base = &packets[i].Payload[0]
			if u.enableGRO {
				msgs[i].Hdr.Control = &packets[i].Control[0]
				msgs[i].Hdr.Controllen = uint64(cap(packets[i].Control))
			}

		}
	}
}

func parseGROControl(control []byte) int {
	if len(control) == 0 {
		return 0
	}

	cmsgs, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return 0
	}

	for _, c := range cmsgs {
		if c.Header.Level == unix.SOL_UDP && c.Header.Type == unix.UDP_GRO && len(c.Data) >= 2 {
			segSize := int(binary.LittleEndian.Uint16(c.Data[:2]))
			return segSize
		}
	}

	return 0
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
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
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
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return 0, &net.OpError{Op: "recvmmsg", Err: err}
		}

		return int(n), nil
	}
}

func (u *StdConn) WriteTo(p *packet.Packet) error {
	if u.enableGSO && p.Addr.IsValid() {
		if err := u.queueGSOPacket(p); err == nil {
			return nil
		} else if !errors.Is(err, errGSOFallback) {
			return err
		}
	}

	var err error
	if u.isV4 {
		err = u.writeTo4(p.Payload, p.Addr)
	} else {
		err = u.writeTo4(p.Payload, p.Addr)
	}
	packet.GetPool().Put(p)
	return err
}

func (u *StdConn) WriteDirect(b []byte, addr netip.AddrPort) error {
	if u.isV4 {
		return u.writeTo4(b, addr)
	}
	return u.writeTo6(b, addr)
}

func (u *StdConn) scheduleGSOFlushLocked() {
	if u.gso.Timer == nil {
		u.gso.Timer = time.AfterFunc(u.gso.FlushTimeout, u.gsoFlushTimer)
		return
	}
	u.gso.Timer.Reset(u.gso.FlushTimeout)
}

func (u *StdConn) stopGSOTimerLocked() {
	if u.gso.Timer != nil {
		u.gso.Timer.Stop()
		u.gso.Timer = nil //todo I also don't like this
	}
}

func (u *StdConn) queueGSOPacket(p *packet.Packet) error {
	if len(p.Payload) == 0 {
		return nil
	}

	u.gso.m.Lock()
	defer u.gso.m.Unlock()

	if !u.enableGSO || !p.Addr.IsValid() || len(p.Payload) > u.gso.MaxBytes {
		if err := u.flushGSOlocked(); err != nil {
			return err
		}
		return errGSOFallback
	}

	if len(u.gso.packets) == 0 {
		u.gso.setNameLocked(p.Addr, u.isV4)
		u.gso.SegSize = len(p.Payload)
		u.gso.packets = append(u.gso.packets, p)
	} else if p.Addr != u.gso.Addr || len(p.Payload) != u.gso.SegSize {
		if err := u.flushGSOlocked(); err != nil {
			return err
		} //todo deal with "one small packet" case
		u.gso.setNameLocked(p.Addr, u.isV4)
		u.gso.SegSize = len(p.Payload)
		u.gso.packets = append(u.gso.packets, p)
	} else {
		u.gso.packets = append(u.gso.packets, p)
	}

	//big todo
	//if len(u.gso.Buf)+len(p.Payload) > u.gso.MaxBytes {
	//	if err := u.flushGSOlocked(); err != nil {
	//		return err
	//	}
	//	u.gso.setNameLocked(p.Addr, u.isV4)
	//	u.gso.SegSize = len(p.Payload)
	//	u.gso.packets = append(u.gso.packets, p)
	//}

	if len(u.gso.packets) >= u.gso.MaxSegments || u.gso.FlushTimeout <= 0 {
		return u.flushGSOlocked()
	}

	u.scheduleGSOFlushLocked()
	return nil
}

func (u *StdConn) flushGSOlocked() error {
	if len(u.gso.packets) == 0 {
		u.stopGSOTimerLocked()
		return nil
	}

	u.stopGSOTimerLocked()

	if u.gso.SegSize <= 0 {
		return errGSOFallback
	}

	err := u.gso.sendmsgLocked(u.sysFd)
	if errors.Is(err, errGSODisabled) {
		u.l.WithField("addr", u.gso.Addr).Warn("UDP GSO disabled by kernel, falling back to sendto")
		u.enableGSO = false
		//todo!
		//return u.sendSegmentsIndividually(payload, addr, segSize)
	}
	u.gso.SegSize = 0

	return err
}

func (u *StdConn) gsoFlushTimer() {
	u.gso.m.Lock()
	_ = u.flushGSOlocked()
	u.gso.m.Unlock()
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
		return fmt.Errorf("Listener is IPv4, but writing to IPv6 remote")
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
	u.configureGSO(c)
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
		return
	}

	if err := unix.SetsockoptInt(u.sysFd, unix.SOL_UDP, unix.UDP_GRO, 0); err != nil && err != unix.ENOPROTOOPT {
		u.l.WithError(err).Warn("Failed to disable UDP GRO")
	}
	u.enableGRO = false
}

func (u *StdConn) configureGSO(c *config.C) {
	enable := c.GetBool("listen.enable_gso", true)
	if !enable {
		u.disableGSO()
	} else {
		u.enableGSO = true
	}

	segments := c.GetInt("listen.gso_max_segments", defaultGSOMaxSegments)
	if segments < 1 {
		segments = 1
	}
	u.gso.MaxSegments = segments

	maxBytes := c.GetInt("listen.gso_max_bytes", 0)
	if maxBytes <= 0 {
		maxBytes = MTU * segments
	}
	if maxBytes > maxGSOBatchBytes {
		u.l.WithField("requested", maxBytes).Warn("listen.gso_max_bytes larger than UDP limit; clamping")
		maxBytes = maxGSOBatchBytes
	}
	u.gso.MaxBytes = maxBytes

	timeout := c.GetDuration("listen.gso_flush_timeout", defaultGSOFlushTimeout)
	if timeout < 0 {
		timeout = 0
	}
	u.gso.FlushTimeout = timeout
	u.gso.Init()
}

func (u *StdConn) disableGSO() {
	u.gso.m.Lock()
	defer u.gso.m.Unlock()
	u.enableGSO = false
	_ = u.flushGSOlocked()
	u.gso.Buf = nil
	u.gso.packets = u.gso.packets[:0]
	u.gso.SegSize = 0
	u.stopGSOTimerLocked()
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
