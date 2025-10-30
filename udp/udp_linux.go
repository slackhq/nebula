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
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

const (
	defaultGSOMaxSegments    = 64
	defaultGSOMaxBytes       = 64000
	defaultGROReadBufferSize = 2 * defaultGSOMaxBytes
	defaultGSOFlushTimeout   = 50 * time.Microsecond
)

type StdConn struct {
	sysFd int
	isV4  bool
	l     *logrus.Logger
	batch int

	enableGRO bool
	enableGSO bool

	controlLen atomic.Int32

	gsoMu              sync.Mutex
	gsoPendingBuf      []byte
	gsoPendingSegments int
	gsoPendingAddr     netip.AddrPort
	gsoPendingSegSize  int
	gsoMaxSegments     int
	gsoMaxBytes        int
	gsoFlushTimeout    time.Duration
	gsoFlushTimer      *time.Timer
	gsoControlBuf      []byte

	gsoBatches  metrics.Counter
	gsoSegments metrics.Counter
	groSegments metrics.Counter
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

	return &StdConn{
		sysFd:           fd,
		isV4:            ip.Is4(),
		l:               l,
		batch:           batch,
		gsoMaxSegments:  defaultGSOMaxSegments,
		gsoMaxBytes:     defaultGSOMaxBytes,
		gsoFlushTimeout: defaultGSOFlushTimeout,
		gsoBatches:      metrics.GetOrRegisterCounter("udp.gso.batches", nil),
		gsoSegments:     metrics.GetOrRegisterCounter("udp.gso.segments", nil),
		groSegments:     metrics.GetOrRegisterCounter("udp.gro.segments", nil),
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

func (u *StdConn) ListenOut(r EncReader) {
	var ip netip.Addr

	msgs, buffers, names, controls := u.PrepareRawMessages(u.batch)
	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	for {
		//desiredControl := int(u.controlLen.Load())
		hasControl := len(controls) > 0
		//if (desiredControl > 0) != hasControl || (desiredControl > 0 && hasControl && len(controls[0]) != desiredControl) {
		//	msgs, buffers, names, controls = u.PrepareRawMessages(u.batch)
		//	hasControl = len(controls) > 0
		//}
		//
		if hasControl {
			for i := range msgs {
				if len(controls) <= i || len(controls[i]) == 0 {
					continue
				}
				msgs[i].Hdr.Controllen = controllen(len(controls[i]))
			}
		}

		n, err := read(msgs)
		if err != nil {
			u.l.WithError(err).Debug("udp socket is closed, exiting read loop")
			return
		}

		for i := 0; i < n; i++ {
			payloadLen := int(msgs[i].Len)
			if payloadLen == 0 {
				continue
			}

			// Its ok to skip the ok check here, the slicing is the only error that can occur and it will panic
			if u.isV4 {
				ip, _ = netip.AddrFromSlice(names[i][4:8])
			} else {
				ip, _ = netip.AddrFromSlice(names[i][8:24])
			}
			addr := netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(names[i][2:4]))

			if len(controls) > i && len(controls[i]) > 0 {
				if segSize, segCount := u.parseGROSegment(&msgs[i], controls[i]); segSize > 0 && segSize < payloadLen {
					if u.emitSegments(r, addr, buffers[i][:payloadLen], segSize, segCount) {
						continue
					}
					if segCount > 1 {
						u.l.WithFields(logrus.Fields{
							"tag":         "gro-debug",
							"stage":       "listen_out",
							"reason":      "emit_failed",
							"payload_len": payloadLen,
							"seg_size":    segSize,
							"seg_count":   segCount,
						}).Debug("gro-debug fallback to single packet")
					}
				}
			}

			r(addr, buffers[i][:payloadLen])
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
	if u.enableGSO {
		if err := u.writeToGSO(b, ip); err != nil {
			return err
		}
		return nil
	}

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

func (u *StdConn) writeToGSO(b []byte, addr netip.AddrPort) error {
	if len(b) == 0 {
		return nil
	}

	if !addr.IsValid() {
		return u.directWrite(b, addr)
	}

	u.gsoMu.Lock()
	defer u.gsoMu.Unlock()

	if cap(u.gsoPendingBuf) < u.gsoMaxBytes { //I feel like this is bad?
		u.gsoPendingBuf = make([]byte, 0, u.gsoMaxBytes)
	}

	if u.gsoPendingSegments > 0 && u.gsoPendingAddr != addr {
		if err := u.flushPendingLocked(); err != nil {
			return err
		}
	}

	if len(b) > u.gsoMaxBytes || u.gsoMaxSegments <= 1 {
		if err := u.flushPendingLocked(); err != nil {
			return err
		}
		return u.directWrite(b, addr)
	}

	if u.gsoPendingSegments == 0 {
		u.gsoPendingAddr = addr
		u.gsoPendingSegSize = len(b)
	} else {
		if len(b) > u.gsoPendingSegSize {
			if err := u.flushPendingLocked(); err != nil {
				return err
			}
			u.gsoPendingAddr = addr
			u.gsoPendingSegSize = len(b)
		} else if len(b) < u.gsoPendingSegSize {
			if err := u.flushPendingLocked(); err != nil {
				return err
			}
			u.gsoPendingAddr = addr
			u.gsoPendingSegSize = len(b)
		}
	}

	if len(u.gsoPendingBuf)+len(b) > u.gsoMaxBytes {
		if err := u.flushPendingLocked(); err != nil {
			return err
		}
		u.gsoPendingAddr = addr
		u.gsoPendingSegSize = len(b)
	}

	u.gsoPendingBuf = append(u.gsoPendingBuf, b...)
	u.gsoPendingSegments++

	if u.gsoPendingSegments >= u.gsoMaxSegments {
		return u.flushPendingLocked()
	}

	if u.gsoFlushTimeout <= 0 {
		return u.flushPendingLocked()
	}

	u.scheduleFlushLocked()
	return nil
}

func (u *StdConn) flushPendingLocked() error {
	if u.gsoPendingSegments == 0 {
		u.stopFlushTimerLocked()
		return nil
	}

	buf := u.gsoPendingBuf[:len(u.gsoPendingBuf)]
	addr := u.gsoPendingAddr
	segSize := u.gsoPendingSegSize
	segments := u.gsoPendingSegments

	u.stopFlushTimerLocked()

	var err error
	if segments <= 1 || !u.enableGSO {
		err = u.directWrite(buf, addr)
	} else {
		err = u.sendSegmentedLocked(buf, addr, segSize)
		if err != nil && (errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP)) {
			u.enableGSO = false
			u.l.WithError(err).Warn("UDP GSO not supported, disabling")
			err = u.sendSequentialLocked(buf, addr, segSize)
		}
	}

	if err == nil && segments > 1 && u.enableGSO {
		if u.gsoBatches != nil {
			u.gsoBatches.Inc(1)
		}
		if u.gsoSegments != nil {
			u.gsoSegments.Inc(int64(segments))
		}
	}

	u.gsoPendingBuf = u.gsoPendingBuf[:0]
	u.gsoPendingSegments = 0
	u.gsoPendingSegSize = 0
	u.gsoPendingAddr = netip.AddrPort{}

	return err
}

func (u *StdConn) sendSegmentedLocked(buf []byte, addr netip.AddrPort, segSize int) error {
	if len(buf) == 0 {
		return nil
	}
	if segSize <= 0 {
		segSize = len(buf)
	}

	if len(u.gsoControlBuf) < unix.CmsgSpace(2) {
		u.gsoControlBuf = make([]byte, unix.CmsgSpace(2))
	}
	control := u.gsoControlBuf[:unix.CmsgSpace(2)]
	for i := range control {
		control[i] = 0
	}

	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	setCmsgLen(hdr, 2)
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT

	dataOff := unix.CmsgLen(0)
	binary.NativeEndian.PutUint16(control[dataOff:dataOff+2], uint16(segSize))

	var sa unix.Sockaddr
	if u.isV4 {
		sa4 := &unix.SockaddrInet4{Port: int(addr.Port())}
		sa4.Addr = addr.Addr().As4()
		sa = sa4
	} else {
		sa6 := &unix.SockaddrInet6{Port: int(addr.Port())}
		sa6.Addr = addr.Addr().As16()
		sa = sa6
	}

	for {
		n, err := unix.SendmsgN(u.sysFd, buf, control[:unix.CmsgSpace(2)], sa, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return &net.OpError{Op: "sendmsg", Err: err}
		}
		if n != len(buf) {
			return &net.OpError{Op: "sendmsg", Err: unix.EIO}
		}
		return nil
	}
}

func (u *StdConn) sendSequentialLocked(buf []byte, addr netip.AddrPort, segSize int) error {
	if len(buf) == 0 {
		return nil
	}
	if segSize <= 0 {
		segSize = len(buf)
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
		if end == len(buf) {
			break
		}
	}

	return nil
}

func (u *StdConn) scheduleFlushLocked() {
	if u.gsoFlushTimeout <= 0 {
		_ = u.flushPendingLocked()
		return
	}
	if u.gsoFlushTimer == nil {
		u.gsoFlushTimer = time.AfterFunc(u.gsoFlushTimeout, u.flushTimerHandler)
		return
	}
	if !u.gsoFlushTimer.Stop() {
		// timer already fired or running; allow handler to exit if no data
	}
	u.gsoFlushTimer.Reset(u.gsoFlushTimeout)
}

func (u *StdConn) stopFlushTimerLocked() {
	if u.gsoFlushTimer != nil {
		u.gsoFlushTimer.Stop()
	}
}

func (u *StdConn) flushTimerHandler() {
	//u.l.Warn("timer hit")
	u.gsoMu.Lock()
	defer u.gsoMu.Unlock()

	if u.gsoPendingSegments == 0 {
		return
	}

	if err := u.flushPendingLocked(); err != nil {
		u.l.WithError(err).Warn("Failed to flush GSO batch")
	}
}

func (u *StdConn) directWrite(b []byte, addr netip.AddrPort) error {
	if u.isV4 {
		return u.writeTo4(b, addr)
	}
	return u.writeTo6(b, addr)
}

func (u *StdConn) emitSegments(r EncReader, addr netip.AddrPort, payload []byte, segSize, segCount int) bool {
	if segSize <= 0 || segSize >= len(payload) {
		if u.l.Level >= logrus.DebugLevel {
			u.l.WithFields(logrus.Fields{
				"tag":         "gro-debug",
				"stage":       "emit",
				"reason":      "invalid_seg_size",
				"payload_len": len(payload),
				"seg_size":    segSize,
				"seg_count":   segCount,
			}).Debug("gro-debug skip emit")
		}
		return false
	}

	totalLen := len(payload)
	if segCount <= 0 {
		segCount = (totalLen + segSize - 1) / segSize
	}
	if segCount <= 1 {
		if u.l.Level >= logrus.DebugLevel {
			u.l.WithFields(logrus.Fields{
				"tag":         "gro-debug",
				"stage":       "emit",
				"reason":      "single_segment",
				"payload_len": totalLen,
				"seg_size":    segSize,
				"seg_count":   segCount,
			}).Debug("gro-debug skip emit")
		}
		return false
	}

	//segments := make([][]byte, 0, segCount)
	start := 0
	//var firstHeader header.H
	//firstParsed := false
	//var firstCounter uint64
	//var firstRemote uint32
	numSegments := 0
	//for start < totalLen && len(segments) < segCount {
	for start < totalLen && numSegments < segCount {
		end := start + segSize
		if end > totalLen {
			end = totalLen
		}

		//segment := append([]byte(nil), payload[start:end]...)
		r(addr, payload[start:end])
		numSegments++
		//segments = append(segments, segment)
		start = end

		//if !firstParsed {
		//	if err := firstHeader.Parse(segment); err == nil {
		//		firstParsed = true
		//		firstCounter = firstHeader.MessageCounter
		//		firstRemote = firstHeader.RemoteIndex
		//	} else if u.l.IsLevelEnabled(logrus.DebugLevel) {
		//		u.l.WithFields(logrus.Fields{
		//			"tag":         "gro-debug",
		//			"stage":       "emit",
		//			"event":       "parse_fail",
		//			"seg_index":   len(segments) - 1,
		//			"seg_size":    segSize,
		//			"seg_count":   segCount,
		//			"payload_len": totalLen,
		//			"err":         err,
		//		}).Debug("gro-debug segment parse failed")
		//	}
		//}
	}

	//for idx, segment := range segments {
	//	r(addr, segment)
	//if idx == len(segments)-1 && len(segment) < segSize && u.l.IsLevelEnabled(logrus.DebugLevel) {
	//	var tail header.H
	//	if err := tail.Parse(segment); err == nil {
	//		u.l.WithFields(logrus.Fields{
	//			"tag":             "gro-debug",
	//			"stage":           "emit",
	//			"event":           "tail_segment",
	//			"segment_len":     len(segment),
	//			"remote_index":    tail.RemoteIndex,
	//			"message_counter": tail.MessageCounter,
	//		}).Debug("gro-debug tail segment metadata")
	//	} else {
	//		u.l.WithError(err).Warn("Failed to parse tail segment")
	//	}
	//}
	//}

	if u.groSegments != nil {
		//u.groSegments.Inc(int64(len(segments)))
		u.groSegments.Inc(int64(numSegments))
	}

	//if len(segments) > 0 {
	//	lastLen := len(segments[len(segments)-1])
	//	if u.l.IsLevelEnabled(logrus.DebugLevel) {
	//		u.l.WithFields(logrus.Fields{
	//			"tag":           "gro-debug",
	//			"stage":         "emit",
	//			"event":         "success",
	//			"payload_len":   totalLen,
	//			"seg_size":      segSize,
	//			"seg_count":     segCount,
	//			"actual_segs":   len(segments),
	//			"last_seg_len":  lastLen,
	//			"addr":          addr.String(),
	//			"first_remote":  firstRemote,
	//			"first_counter": firstCounter,
	//		}).Debug("gro-debug emit")
	//	}
	//}

	return true
}

func (u *StdConn) parseGROSegment(msg *rawMessage, control []byte) (int, int) {
	ctrlLen := int(msg.Hdr.Controllen)
	if ctrlLen <= 0 {
		return 0, 0
	}
	if ctrlLen > len(control) {
		ctrlLen = len(control)
	}

	cmsgs, err := unix.ParseSocketControlMessage(control[:ctrlLen])
	if err != nil {
		u.l.WithError(err).Debug("failed to parse UDP GRO control message")
		return 0, 0
	}

	for _, c := range cmsgs {
		if c.Header.Level == unix.SOL_UDP && c.Header.Type == unix.UDP_GRO && len(c.Data) >= 2 {
			segSize := int(binary.NativeEndian.Uint16(c.Data[:2]))
			segCount := 0
			if len(c.Data) >= 4 {
				segCount = int(binary.NativeEndian.Uint16(c.Data[2:4]))
			}
			u.l.WithFields(logrus.Fields{
				"tag":       "gro-debug",
				"stage":     "parse",
				"seg_size":  segSize,
				"seg_count": segCount,
			}).Debug("gro-debug control parsed")
			return segSize, segCount
		}
	}

	return 0, 0
}

func (u *StdConn) configureGRO(enable bool) {
	if enable == u.enableGRO {
		if enable {
			u.controlLen.Store(int32(unix.CmsgSpace(2)))
		} else {
			u.controlLen.Store(0)
		}
		return
	}

	if enable {
		if err := unix.SetsockoptInt(u.sysFd, unix.SOL_UDP, unix.UDP_GRO, 1); err != nil {
			u.l.WithError(err).Warn("Failed to enable UDP GRO")
			u.enableGRO = false
			u.controlLen.Store(0)
			return
		}
		u.enableGRO = true
		u.controlLen.Store(int32(unix.CmsgSpace(2)))
		u.l.Info("UDP GRO enabled")
	} else {
		if u.enableGRO {
			if err := unix.SetsockoptInt(u.sysFd, unix.SOL_UDP, unix.UDP_GRO, 0); err != nil {
				u.l.WithError(err).Warn("Failed to disable UDP GRO")
			}
		}
		u.enableGRO = false
		u.controlLen.Store(0)
	}
}

func (u *StdConn) configureGSO(enable bool, c *config.C) {
	u.gsoMu.Lock()
	defer u.gsoMu.Unlock()

	if !enable {
		if u.enableGSO {
			if err := u.flushPendingLocked(); err != nil {
				u.l.WithError(err).Warn("Failed to flush GSO buffers while disabling")
			}
			u.enableGSO = false
			if u.gsoFlushTimer != nil {
				u.gsoFlushTimer.Stop()
			}
			u.l.Info("UDP GSO disabled")
		}
		return
	}

	maxSegments := c.GetInt("listen.gso_max_segments", defaultGSOMaxSegments)
	if maxSegments < 2 {
		maxSegments = 2
	}

	maxBytes := c.GetInt("listen.gso_max_bytes", 0)
	if maxBytes <= 0 {
		maxBytes = defaultGSOMaxBytes
	}
	if maxBytes < MTU {
		maxBytes = MTU
	}

	flushTimeout := c.GetDuration("listen.gso_flush_timeout", defaultGSOFlushTimeout)
	if flushTimeout < 0 {
		flushTimeout = 0
	}

	u.enableGSO = true
	u.gsoMaxSegments = maxSegments
	u.gsoMaxBytes = maxBytes
	u.gsoFlushTimeout = flushTimeout

	if cap(u.gsoPendingBuf) < u.gsoMaxBytes {
		u.gsoPendingBuf = make([]byte, 0, u.gsoMaxBytes)
	} else {
		u.gsoPendingBuf = u.gsoPendingBuf[:0]
	}

	if len(u.gsoControlBuf) < unix.CmsgSpace(2) {
		u.gsoControlBuf = make([]byte, unix.CmsgSpace(2))
	}

	u.l.WithFields(logrus.Fields{
		"segments":      u.gsoMaxSegments,
		"bytes":         u.gsoMaxBytes,
		"flush_timeout": u.gsoFlushTimeout,
	}).Info("UDP GSO configured")
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

	u.configureGRO(c.GetBool("listen.enable_gro", false))
	u.configureGSO(c.GetBool("listen.enable_gso", false), c)
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
	u.gsoMu.Lock()
	flushErr := u.flushPendingLocked()
	u.gsoMu.Unlock()

	closeErr := syscall.Close(u.sysFd)
	if flushErr != nil {
		return flushErr
	}
	return closeErr
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
