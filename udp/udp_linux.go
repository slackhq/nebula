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
	"golang.org/x/sys/unix"
)

var readTimeout = unix.NsecToTimeval(int64(time.Millisecond * 500))

const (
	defaultGSOMaxSegments    = 8
	defaultGSOFlushTimeout   = 150 * time.Microsecond
	defaultGROReadBufferSize = MTU * defaultGSOMaxSegments
	maxGSOBatchBytes         = 0xFFFF
)

var (
	errGSOFallback = errors.New("udp gso fallback")
	errGSODisabled = errors.New("udp gso disabled")
)

type StdConn struct {
	sysFd int
	isV4  bool
	l     *logrus.Logger
	batch int

	enableGRO bool
	enableGSO bool

	gsoMu           sync.Mutex
	gsoBuf          []byte
	gsoAddr         netip.AddrPort
	gsoSegSize      int
	gsoSegments     int
	gsoMaxSegments  int
	gsoMaxBytes     int
	gsoFlushTimeout time.Duration
	gsoTimer        *time.Timer

	groBufSize int
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

	return &StdConn{
		sysFd:           fd,
		isV4:            ip.Is4(),
		l:               l,
		batch:           batch,
		gsoMaxSegments:  defaultGSOMaxSegments,
		gsoMaxBytes:     MTU * defaultGSOMaxSegments,
		gsoFlushTimeout: defaultGSOFlushTimeout,
		groBufSize:      MTU,
	}, err
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

func (u *StdConn) ListenOut(r EncReader) error {
	var (
		ip       netip.Addr
		controls [][]byte
	)

	bufSize := u.readBufferSize()
	msgs, buffers, names := u.PrepareRawMessages(u.batch, bufSize)
	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	for {
		desired := u.readBufferSize()
		if len(buffers) == 0 || cap(buffers[0]) < desired {
			msgs, buffers, names = u.PrepareRawMessages(u.batch, desired)
			controls = nil
		}

		if u.enableGRO {
			if controls == nil {
				controls = make([][]byte, len(msgs))
				for i := range controls {
					controls[i] = make([]byte, unix.CmsgSpace(4))
				}
			}
			for i := range msgs {
				setRawMessageControl(&msgs[i], controls[i])
			}
		} else if controls != nil {
			for i := range msgs {
				setRawMessageControl(&msgs[i], nil)
			}
			controls = nil
		}

		n, err := read(msgs)
		if err != nil {
			return err
		}

		for i := 0; i < n; i++ {
			// Its ok to skip the ok check here, the slicing is the only error that can occur and it will panic
			if u.isV4 {
				ip, _ = netip.AddrFromSlice(names[i][4:8])
			} else {
				ip, _ = netip.AddrFromSlice(names[i][8:24])
			}
			addr := netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(names[i][2:4]))
			payload := buffers[i][:msgs[i].Len]

			if u.enableGRO && u.l.IsLevelEnabled(logrus.DebugLevel) {
				ctrlLen := getRawMessageControlLen(&msgs[i])
				msgFlags := getRawMessageFlags(&msgs[i])
				u.l.WithFields(logrus.Fields{
					"tag":         "gro-debug",
					"stage":       "recv",
					"payload_len": len(payload),
					"ctrl_len":    ctrlLen,
					"msg_flags":   msgFlags,
				}).Debug("gro batch data")
				if controls != nil && ctrlLen > 0 {
					maxDump := ctrlLen
					if maxDump > 16 {
						maxDump = 16
					}
					u.l.WithFields(logrus.Fields{
						"tag":         "gro-debug",
						"stage":       "control-bytes",
						"control_hex": fmt.Sprintf("%x", controls[i][:maxDump]),
						"datalen":     ctrlLen,
					}).Debug("gro control dump")
				}
			}

			sawControl := false
			if controls != nil {
				if ctrlLen := getRawMessageControlLen(&msgs[i]); ctrlLen > 0 {
					if segSize, segCount := parseGROControl(controls[i][:ctrlLen]); segSize > 0 {
						sawControl = true
						if u.l.IsLevelEnabled(logrus.DebugLevel) {
							u.l.WithFields(logrus.Fields{
								"tag":        "gro-debug",
								"stage":      "control",
								"seg_size":   segSize,
								"seg_count":  segCount,
								"payloadLen": len(payload),
							}).Debug("gro control parsed")
						}
						segSize = normalizeGROSegSize(segSize, segCount, len(payload))
						if segSize > 0 && segSize < len(payload) {
							if u.emitGROSegments(r, addr, payload, segSize) {
								continue
							}
						}
					}
				}
			}

			if u.enableGRO && len(payload) > MTU {
				if !sawControl && u.l.IsLevelEnabled(logrus.DebugLevel) {
					u.l.WithFields(logrus.Fields{
						"tag":         "gro-debug",
						"stage":       "fallback",
						"payload_len": len(payload),
					}).Debug("gro control missing; splitting payload by MTU")
				}
				if u.emitGROSegments(r, addr, payload, MTU) {
					continue
				}
			}

			r(addr, payload)
		}
	}
}

func (u *StdConn) readBufferSize() int {
	if u.enableGRO && u.groBufSize > MTU {
		return u.groBufSize
	}
	return MTU
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

func (u *StdConn) WriteTo(b []byte, ip netip.AddrPort) error {
	if u.enableGSO && ip.IsValid() {
		if err := u.queueGSOPacket(b, ip); err == nil {
			return nil
		} else if !errors.Is(err, errGSOFallback) {
			return err
		}
	}

	if u.isV4 {
		return u.writeTo4(b, ip)
	}
	return u.writeTo6(b, ip)
}

func (u *StdConn) WriteBatch(pkts []BatchPacket) (int, error) {
	if len(pkts) == 0 {
		return 0, nil
	}

	msgs := make([]rawMessage, 0, len(pkts))
	iovs := make([]iovec, 0, len(pkts))
	names := make([][unix.SizeofSockaddrInet6]byte, 0, len(pkts))

	sent := 0

	for _, pkt := range pkts {
		if len(pkt.Payload) == 0 {
			sent++
			continue
		}

		if u.enableGSO && pkt.Addr.IsValid() {
			if err := u.queueGSOPacket(pkt.Payload, pkt.Addr); err == nil {
				sent++
				continue
			} else if !errors.Is(err, errGSOFallback) {
				return sent, err
			}
		}

		if !pkt.Addr.IsValid() {
			if err := u.WriteTo(pkt.Payload, pkt.Addr); err != nil {
				return sent, err
			}
			sent++
			continue
		}

		msgs = append(msgs, rawMessage{})
		iovs = append(iovs, iovec{})
		names = append(names, [unix.SizeofSockaddrInet6]byte{})

		idx := len(msgs) - 1
		msg := &msgs[idx]
		iov := &iovs[idx]
		name := &names[idx]

		setIovecSlice(iov, pkt.Payload)
		msg.Hdr.Iov = iov
		msg.Hdr.Iovlen = 1
		setRawMessageControl(msg, nil)
		msg.Hdr.Flags = 0

		nameLen, err := u.encodeSockaddr(name[:], pkt.Addr)
		if err != nil {
			return sent, err
		}
		msg.Hdr.Name = &name[0]
		msg.Hdr.Namelen = nameLen
	}

	if len(msgs) == 0 {
		return sent, nil
	}

	offset := 0
	for offset < len(msgs) {
		n, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&msgs[offset])),
			uintptr(len(msgs)-offset),
			0,
			0,
			0,
		)

		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return sent + offset, &net.OpError{Op: "sendmmsg", Err: errno}
		}

		if n == 0 {
			break
		}
		offset += int(n)
	}

	return sent + len(msgs), nil
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

	u.configureGRO(c)
	u.configureGSO(c)
}

func (u *StdConn) configureGRO(c *config.C) {
	if c == nil {
		return
	}

	enable := c.GetBool("listen.enable_gro", false)
	if enable == u.enableGRO {
		if enable {
			if size := c.GetInt("listen.gro_read_buffer", 0); size > 0 {
				u.setGROBufferSize(size)
			}
		}
		return
	}

	if enable {
		if err := unix.SetsockoptInt(u.sysFd, unix.SOL_UDP, unix.UDP_GRO, 1); err != nil {
			u.l.WithError(err).Warn("Failed to enable UDP GRO")
			return
		}
		u.enableGRO = true
		u.setGROBufferSize(c.GetInt("listen.gro_read_buffer", defaultGROReadBufferSize))
		u.l.WithField("buffer_size", u.groBufSize).Info("UDP GRO enabled")
		return
	}

	if err := unix.SetsockoptInt(u.sysFd, unix.SOL_UDP, unix.UDP_GRO, 0); err != nil && err != unix.ENOPROTOOPT {
		u.l.WithError(err).Warn("Failed to disable UDP GRO")
	}
	u.enableGRO = false
	u.groBufSize = MTU
}

func (u *StdConn) configureGSO(c *config.C) {
	enable := c.GetBool("listen.enable_gso", false)
	if !enable {
		u.disableGSO()
	} else {
		u.enableGSO = true
	}

	segments := c.GetInt("listen.gso_max_segments", defaultGSOMaxSegments)
	if segments < 1 {
		segments = 1
	}
	u.gsoMaxSegments = segments

	maxBytes := c.GetInt("listen.gso_max_bytes", 0)
	if maxBytes <= 0 {
		maxBytes = MTU * segments
	}
	if maxBytes > maxGSOBatchBytes {
		u.l.WithField("requested", maxBytes).Warn("listen.gso_max_bytes larger than UDP limit; clamping")
		maxBytes = maxGSOBatchBytes
	}
	u.gsoMaxBytes = maxBytes

	timeout := c.GetDuration("listen.gso_flush_timeout", defaultGSOFlushTimeout)
	if timeout < 0 {
		timeout = 0
	}
	u.gsoFlushTimeout = timeout
}

func (u *StdConn) setGROBufferSize(size int) {
	if size < MTU {
		size = defaultGROReadBufferSize
	}
	if size > maxGSOBatchBytes {
		size = maxGSOBatchBytes
	}
	u.groBufSize = size
}

func (u *StdConn) disableGSO() {
	u.gsoMu.Lock()
	defer u.gsoMu.Unlock()
	u.enableGSO = false
	_ = u.flushGSOlocked()
	u.gsoBuf = nil
	u.gsoSegments = 0
	u.gsoSegSize = 0
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

func (u *StdConn) queueGSOPacket(b []byte, addr netip.AddrPort) error {
	if len(b) == 0 {
		return nil
	}

	u.gsoMu.Lock()
	defer u.gsoMu.Unlock()

	if !u.enableGSO || !addr.IsValid() || len(b) > u.gsoMaxBytes {
		if err := u.flushGSOlocked(); err != nil {
			return err
		}
		return errGSOFallback
	}

	if u.gsoSegments == 0 {
		if cap(u.gsoBuf) < u.gsoMaxBytes {
			u.gsoBuf = make([]byte, 0, u.gsoMaxBytes)
		}
		u.gsoAddr = addr
		u.gsoSegSize = len(b)
	} else if addr != u.gsoAddr || len(b) != u.gsoSegSize {
		if err := u.flushGSOlocked(); err != nil {
			return err
		}
		if cap(u.gsoBuf) < u.gsoMaxBytes {
			u.gsoBuf = make([]byte, 0, u.gsoMaxBytes)
		}
		u.gsoAddr = addr
		u.gsoSegSize = len(b)
	}

	if len(u.gsoBuf)+len(b) > u.gsoMaxBytes {
		if err := u.flushGSOlocked(); err != nil {
			return err
		}
		if cap(u.gsoBuf) < u.gsoMaxBytes {
			u.gsoBuf = make([]byte, 0, u.gsoMaxBytes)
		}
		u.gsoAddr = addr
		u.gsoSegSize = len(b)
	}

	u.gsoBuf = append(u.gsoBuf, b...)
	u.gsoSegments++

	if u.gsoSegments >= u.gsoMaxSegments || u.gsoFlushTimeout <= 0 {
		return u.flushGSOlocked()
	}

	u.scheduleGSOFlushLocked()
	return nil
}

func (u *StdConn) flushGSOlocked() error {
	if u.gsoSegments == 0 {
		u.stopGSOTimerLocked()
		return nil
	}

	payload := append([]byte(nil), u.gsoBuf...)
	addr := u.gsoAddr
	segSize := u.gsoSegSize

	u.gsoBuf = u.gsoBuf[:0]
	u.gsoSegments = 0
	u.gsoSegSize = 0
	u.stopGSOTimerLocked()

	if segSize <= 0 {
		return errGSOFallback
	}

	err := u.sendSegmented(payload, addr, segSize)
	if errors.Is(err, errGSODisabled) {
		u.l.WithField("addr", addr).Warn("UDP GSO disabled by kernel, falling back to sendto")
		u.enableGSO = false
		return u.sendSegmentsIndividually(payload, addr, segSize)
	}

	return err
}

func (u *StdConn) sendSegmented(payload []byte, addr netip.AddrPort, segSize int) error {
	if len(payload) == 0 {
		return nil
	}

	control := make([]byte, unix.CmsgSpace(2))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	setCmsgLen(hdr, unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(control[unix.CmsgLen(0):unix.CmsgLen(0)+2], uint16(segSize))

	var sa unix.Sockaddr
	if addr.Addr().Is4() {
		var sa4 unix.SockaddrInet4
		sa4.Port = int(addr.Port())
		sa4.Addr = addr.Addr().As4()
		sa = &sa4
	} else {
		var sa6 unix.SockaddrInet6
		sa6.Port = int(addr.Port())
		sa6.Addr = addr.Addr().As16()
		sa = &sa6
	}

	if _, err := unix.SendmsgN(u.sysFd, payload, control, sa, 0); err != nil {
		if errno, ok := err.(syscall.Errno); ok && (errno == unix.EINVAL || errno == unix.ENOTSUP || errno == unix.EOPNOTSUPP) {
			return errGSODisabled
		}
		return &net.OpError{Op: "sendmsg", Err: err}
	}
	return nil
}

func (u *StdConn) sendSegmentsIndividually(buf []byte, addr netip.AddrPort, segSize int) error {
	if segSize <= 0 {
		return errGSOFallback
	}

	for offset := 0; offset < len(buf); offset += segSize {
		end := offset + segSize
		if end > len(buf) {
			end = len(buf)
		}
		var err error
		if u.isV4 {
			err = u.writeTo4(buf[offset:end], addr)
		} else {
			err = u.writeTo6(buf[offset:end], addr)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (u *StdConn) scheduleGSOFlushLocked() {
	if u.gsoTimer == nil {
		u.gsoTimer = time.AfterFunc(u.gsoFlushTimeout, u.gsoFlushTimer)
		return
	}
	u.gsoTimer.Reset(u.gsoFlushTimeout)
}

func (u *StdConn) stopGSOTimerLocked() {
	if u.gsoTimer != nil {
		u.gsoTimer.Stop()
		u.gsoTimer = nil
	}
}

func (u *StdConn) gsoFlushTimer() {
	u.gsoMu.Lock()
	defer u.gsoMu.Unlock()
	_ = u.flushGSOlocked()
}

func parseGROControl(control []byte) (int, int) {
	if len(control) == 0 {
		return 0, 0
	}

	cmsgs, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return 0, 0
	}

	for _, c := range cmsgs {
		if c.Header.Level == unix.SOL_UDP && c.Header.Type == unix.UDP_GRO && len(c.Data) >= 2 {
			segSize := int(binary.NativeEndian.Uint16(c.Data[:2]))
			segCount := 0
			if len(c.Data) >= 4 {
				segCount = int(binary.NativeEndian.Uint16(c.Data[2:4]))
			}
			return segSize, segCount
		}
	}

	return 0, 0
}

func (u *StdConn) emitGROSegments(r EncReader, addr netip.AddrPort, payload []byte, segSize int) bool {
	if segSize <= 0 {
		return false
	}

	for offset := 0; offset < len(payload); offset += segSize {
		end := offset + segSize
		if end > len(payload) {
			end = len(payload)
		}
		segment := make([]byte, end-offset)
		copy(segment, payload[offset:end])
		r(addr, segment)
	}
	return true
}

func normalizeGROSegSize(segSize, segCount, total int) int {
	if segSize <= 0 || total <= 0 {
		return segSize
	}

	if segSize > total && segCount > 0 {
		segSize = total / segCount
		if segSize == 0 {
			segSize = total
		}
	}

	if segCount <= 1 && segSize > 0 && total > segSize {
		calculated := total / segSize
		if calculated <= 1 {
			calculated = (total + segSize - 1) / segSize
		}
		if calculated > 1 {
			segCount = calculated
		}
	}

	if segSize > MTU {
		return MTU
	}

	return segSize
}

func (u *StdConn) Close() error {
	u.disableGSO()
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
