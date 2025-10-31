//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"golang.org/x/sys/unix"
)

const (
	defaultGSOMaxSegments    = 8
	defaultGSOMaxBytes       = MTU * defaultGSOMaxSegments
	defaultGROReadBufferSize = MTU * defaultGSOMaxSegments
	defaultGSOFlushTimeout   = 50 * time.Microsecond
	linuxMaxGSOBatchBytes    = 0xFFFF // Linux UDP GSO still limits the datagram payload to 64 KiB
	maxSendmmsgBatch         = 32
)

type StdConn struct {
	sysFd int
	isV4  bool
	l     *logrus.Logger
	batch int

	enableGRO bool
	enableGSO bool

	controlLen atomic.Int32

	gsoMaxSegments  int
	gsoMaxBytes     int
	gsoFlushTimeout time.Duration

	groSegmentPool sync.Pool
	groBufSize     atomic.Int64
	rxBufferPool   chan []byte
	gsoBufferPool  sync.Pool

	gsoBatches  metrics.Counter
	gsoSegments metrics.Counter
	groSegments metrics.Counter

	sendShards   []*sendShard
	shardCounter atomic.Uint32
}

type sendTask struct {
	buf      []byte
	addr     netip.AddrPort
	segSize  int
	segments int
	owned    bool
}

const sendShardQueueDepth = 128

type sendShard struct {
	parent *StdConn

	mu sync.Mutex

	pendingBuf      []byte
	pendingSegments int
	pendingAddr     netip.AddrPort
	pendingSegSize  int
	flushTimer      *time.Timer
	controlBuf      []byte

	mmsgHeaders []linuxMmsgHdr
	mmsgIovecs  []unix.Iovec
	mmsgLengths []int

	outQueue   chan *sendTask
	workerDone sync.WaitGroup
}

func (u *StdConn) initSendShards() {
	shardCount := runtime.GOMAXPROCS(0)
	if shardCount < 1 {
		shardCount = 1
	}
	u.resizeSendShards(shardCount)
}

func (u *StdConn) selectSendShard(addr netip.AddrPort) *sendShard {
	if len(u.sendShards) == 0 {
		return nil
	}
	if len(u.sendShards) == 1 {
		return u.sendShards[0]
	}
	idx := int(u.shardCounter.Add(1)-1) % len(u.sendShards)
	if idx < 0 {
		idx = -idx
	}
	return u.sendShards[idx]
}

func (u *StdConn) resizeSendShards(count int) {
	if count <= 0 {
		count = runtime.GOMAXPROCS(0)
		if count < 1 {
			count = 1
		}
	}

	if len(u.sendShards) == count {
		return
	}

	for _, shard := range u.sendShards {
		if shard == nil {
			continue
		}
		shard.mu.Lock()
		if shard.pendingSegments > 0 {
			if err := shard.flushPendingLocked(); err != nil {
				u.l.WithError(err).Warn("Failed to flush send shard while resizing")
			}
		} else {
			shard.stopFlushTimerLocked()
		}
		buf := shard.pendingBuf
		shard.pendingBuf = nil
		shard.mu.Unlock()
		if buf != nil {
			u.releaseGSOBuf(buf)
		}
		shard.stopSender()
	}

	newShards := make([]*sendShard, count)
	for i := range newShards {
		shard := &sendShard{parent: u}
		shard.startSender()
		newShards[i] = shard
	}
	u.sendShards = newShards
	u.shardCounter.Store(0)
	u.l.WithField("send_shards", count).Debug("Configured UDP send shards")
}

func (u *StdConn) setGroBufferSize(size int) {
	if size < defaultGROReadBufferSize {
		size = defaultGROReadBufferSize
	}
	u.groBufSize.Store(int64(size))
	u.groSegmentPool = sync.Pool{New: func() any {
		return make([]byte, size)
	}}
	if u.rxBufferPool == nil {
		poolSize := u.batch * 4
		if poolSize < u.batch {
			poolSize = u.batch
		}
		u.rxBufferPool = make(chan []byte, poolSize)
		for i := 0; i < poolSize; i++ {
			u.rxBufferPool <- make([]byte, size)
		}
	}
}

func (u *StdConn) borrowRxBuffer(desired int) []byte {
	if desired < MTU {
		desired = MTU
	}
	if u.rxBufferPool == nil {
		return make([]byte, desired)
	}
	buf := <-u.rxBufferPool
	if cap(buf) < desired {
		buf = make([]byte, desired)
	}
	return buf[:desired]
}

func (u *StdConn) recycleBuffer(buf []byte) {
	if buf == nil {
		return
	}
	if u.rxBufferPool == nil {
		return
	}
	buf = buf[:cap(buf)]
	desired := int(u.groBufSize.Load())
	if desired < MTU {
		desired = MTU
	}
	if cap(buf) < desired {
		return
	}
	select {
	case u.rxBufferPool <- buf[:desired]:
	default:
	}
}

func (u *StdConn) recycleBufferSet(bufs [][]byte) {
	for i := range bufs {
		u.recycleBuffer(bufs[i])
	}
}

func (u *StdConn) borrowGSOBuf() []byte {
	size := u.gsoMaxBytes
	if size <= 0 {
		size = MTU
	}
	if v := u.gsoBufferPool.Get(); v != nil {
		buf := v.([]byte)
		if cap(buf) < size {
			return make([]byte, 0, size)
		}
		return buf[:0]
	}
	return make([]byte, 0, size)
}

func (u *StdConn) releaseGSOBuf(buf []byte) {
	if buf == nil {
		return
	}
	size := u.gsoMaxBytes
	if size <= 0 {
		size = MTU
	}
	buf = buf[:0]
	if cap(buf) > size*4 {
		return
	}
	u.gsoBufferPool.Put(buf)
}

func (s *sendShard) ensureMmsgCapacity(n int) {
	if cap(s.mmsgHeaders) < n {
		s.mmsgHeaders = make([]linuxMmsgHdr, n)
	}
	s.mmsgHeaders = s.mmsgHeaders[:n]
	if cap(s.mmsgIovecs) < n {
		s.mmsgIovecs = make([]unix.Iovec, n)
	}
	s.mmsgIovecs = s.mmsgIovecs[:n]
	if cap(s.mmsgLengths) < n {
		s.mmsgLengths = make([]int, n)
	}
	s.mmsgLengths = s.mmsgLengths[:n]
}

func (s *sendShard) ensurePendingBuf(p *StdConn) {
	if s.pendingBuf == nil {
		s.pendingBuf = p.borrowGSOBuf()
	}
}

func (s *sendShard) startSender() {
	if s.outQueue != nil {
		return
	}
	s.outQueue = make(chan *sendTask, sendShardQueueDepth)
	s.workerDone.Add(1)
	go s.senderLoop()
}

func (s *sendShard) stopSender() {
	s.closeSender()
	s.workerDone.Wait()
}

func (s *sendShard) closeSender() {
	s.mu.Lock()
	queue := s.outQueue
	s.outQueue = nil
	s.mu.Unlock()
	if queue != nil {
		close(queue)
	}
}

func (s *sendShard) senderLoop() {
	defer s.workerDone.Done()
	for task := range s.outQueue {
		if task == nil {
			continue
		}
		_ = s.processTask(task)
	}
}

func (s *sendShard) processTask(task *sendTask) error {
	if task == nil {
		return nil
	}
	p := s.parent
	defer func() {
		if task.owned && task.buf != nil {
			p.releaseGSOBuf(task.buf)
		}
		task.buf = nil
	}()
	if len(task.buf) == 0 {
		return nil
	}
	useGSO := p.enableGSO && task.segments > 1
	if useGSO {
		if err := s.sendSegmentedLocked(task.buf, task.addr, task.segSize); err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) {
				p.enableGSO = false
				p.l.WithError(err).Warn("UDP GSO not supported, disabling")
			} else {
				p.l.WithError(err).Warn("Failed to flush GSO batch")
				return err
			}
		} else {
			s.recordGSOMetrics(task)
			return nil
		}
	}
	if err := s.sendSequentialLocked(task.buf, task.addr, task.segSize); err != nil {
		p.l.WithError(err).Warn("Failed to flush batch")
		return err
	}
	return nil
}

func (s *sendShard) recordGSOMetrics(task *sendTask) {
	p := s.parent
	if p.gsoBatches != nil {
		p.gsoBatches.Inc(1)
	}
	if p.gsoSegments != nil {
		p.gsoSegments.Inc(int64(task.segments))
	}
	if p.l.IsLevelEnabled(logrus.DebugLevel) {
		p.l.WithFields(logrus.Fields{
			"tag":          "gso-debug",
			"stage":        "flush",
			"segments":     task.segments,
			"segment_size": task.segSize,
			"batch_bytes":  len(task.buf),
			"remote_addr":  task.addr.String(),
		}).Debug("gso batch sent")
	}
}

func (s *sendShard) write(b []byte, addr netip.AddrPort) error {
	if len(b) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.parent

	if !p.enableGSO || !addr.IsValid() {
		return p.directWrite(b, addr)
	}

	s.ensurePendingBuf(p)

	if s.pendingSegments > 0 && s.pendingAddr != addr {
		if err := s.flushPendingLocked(); err != nil {
			return err
		}
		s.ensurePendingBuf(p)
	}

	if len(b) > p.gsoMaxBytes || p.gsoMaxSegments <= 1 {
		if err := s.flushPendingLocked(); err != nil {
			return err
		}
		return p.directWrite(b, addr)
	}

	if s.pendingSegments == 0 {
		s.pendingAddr = addr
		s.pendingSegSize = len(b)
	} else if len(b) != s.pendingSegSize {
		if err := s.flushPendingLocked(); err != nil {
			return err
		}
		s.pendingAddr = addr
		s.pendingSegSize = len(b)
		s.ensurePendingBuf(p)
	}

	if len(s.pendingBuf)+len(b) > p.gsoMaxBytes {
		if err := s.flushPendingLocked(); err != nil {
			return err
		}
		s.pendingAddr = addr
		s.pendingSegSize = len(b)
		s.ensurePendingBuf(p)
	}

	s.pendingBuf = append(s.pendingBuf, b...)
	s.pendingSegments++

	if s.pendingSegments >= p.gsoMaxSegments {
		return s.flushPendingLocked()
	}

	if p.gsoFlushTimeout <= 0 {
		return s.flushPendingLocked()
	}

	s.scheduleFlushLocked()
	return nil
}

func (s *sendShard) flushPendingLocked() error {
	if s.pendingSegments == 0 {
		s.stopFlushTimerLocked()
		return nil
	}

	buf := s.pendingBuf
	task := &sendTask{
		buf:      buf,
		addr:     s.pendingAddr,
		segSize:  s.pendingSegSize,
		segments: s.pendingSegments,
		owned:    true,
	}

	s.pendingBuf = nil
	s.pendingSegments = 0
	s.pendingSegSize = 0
	s.pendingAddr = netip.AddrPort{}

	s.stopFlushTimerLocked()

	queue := s.outQueue
	s.mu.Unlock()
	var err error
	if queue == nil {
		err = s.processTask(task)
	} else {
		defer func() {
			if r := recover(); r != nil {
				err = s.processTask(task)
			}
		}()
		queue <- task
	}
	s.mu.Lock()
	return err
}

func (s *sendShard) sendSegmentedLocked(buf []byte, addr netip.AddrPort, segSize int) error {
	if len(buf) == 0 {
		return nil
	}
	if segSize <= 0 {
		segSize = len(buf)
	}

	if len(s.controlBuf) < unix.CmsgSpace(2) {
		s.controlBuf = make([]byte, unix.CmsgSpace(2))
	}
	control := s.controlBuf[:unix.CmsgSpace(2)]
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
	if s.parent.isV4 {
		sa4 := &unix.SockaddrInet4{Port: int(addr.Port())}
		sa4.Addr = addr.Addr().As4()
		sa = sa4
	} else {
		sa6 := &unix.SockaddrInet6{Port: int(addr.Port())}
		sa6.Addr = addr.Addr().As16()
		sa = sa6
	}

	for {
		n, err := unix.SendmsgN(s.parent.sysFd, buf, control[:unix.CmsgSpace(2)], sa, 0)
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

func (s *sendShard) sendSequentialLocked(buf []byte, addr netip.AddrPort, segSize int) error {
	if len(buf) == 0 {
		return nil
	}
	if segSize <= 0 {
		segSize = len(buf)
	}
	if segSize >= len(buf) {
		return s.parent.directWrite(buf, addr)
	}

	var (
		namePtr *byte
		nameLen uint32
	)
	if s.parent.isV4 {
		var sa4 unix.RawSockaddrInet4
		sa4.Family = unix.AF_INET
		sa4.Addr = addr.Addr().As4()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa4.Port))[:], addr.Port())
		namePtr = (*byte)(unsafe.Pointer(&sa4))
		nameLen = uint32(unsafe.Sizeof(sa4))
	} else {
		var sa6 unix.RawSockaddrInet6
		sa6.Family = unix.AF_INET6
		sa6.Addr = addr.Addr().As16()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa6.Port))[:], addr.Port())
		namePtr = (*byte)(unsafe.Pointer(&sa6))
		nameLen = uint32(unsafe.Sizeof(sa6))
	}

	total := len(buf)
	if total == 0 {
		return nil
	}
	basePtr := uintptr(unsafe.Pointer(&buf[0]))
	offset := 0

	for offset < total {
		remaining := total - offset
		segments := (remaining + segSize - 1) / segSize
		if segments > maxSendmmsgBatch {
			segments = maxSendmmsgBatch
		}

		s.ensureMmsgCapacity(segments)
		msgs := s.mmsgHeaders[:segments]
		iovecs := s.mmsgIovecs[:segments]
		lens := s.mmsgLengths[:segments]

		batchStart := offset
		segOffset := offset
		actual := 0
		for actual < segments && segOffset < total {
			segLen := segSize
			if segLen > total-segOffset {
				segLen = total - segOffset
			}

			msgs[actual] = linuxMmsgHdr{}
			lens[actual] = segLen
			iovecs[actual].Base = &buf[segOffset]
			setIovecLen(&iovecs[actual], segLen)
			msgs[actual].Hdr.Iov = &iovecs[actual]
			setMsghdrIovlen(&msgs[actual].Hdr, 1)
			msgs[actual].Hdr.Name = namePtr
			msgs[actual].Hdr.Namelen = nameLen
			msgs[actual].Hdr.Control = nil
			msgs[actual].Hdr.Controllen = 0
			msgs[actual].Hdr.Flags = 0
			msgs[actual].Len = 0

			actual++
			segOffset += segLen
		}
		if actual == 0 {
			break
		}
		msgs = msgs[:actual]
		lens = lens[:actual]

	retry:
		sent, err := sendmmsg(s.parent.sysFd, msgs, 0)
		if err != nil {
			if err == unix.EINTR {
				goto retry
			}
			return &net.OpError{Op: "sendmmsg", Err: err}
		}
		if sent == 0 {
			goto retry
		}

		bytesSent := 0
		for i := 0; i < sent; i++ {
			bytesSent += lens[i]
		}
		offset = batchStart + bytesSent

		if sent < len(msgs) {
			for j := sent; j < len(msgs); j++ {
				start := int(uintptr(unsafe.Pointer(iovecs[j].Base)) - basePtr)
				if start < 0 || start >= total {
					continue
				}
				end := start + lens[j]
				if end > total {
					end = total
				}
				if err := s.parent.directWrite(buf[start:end], addr); err != nil {
					return err
				}
				if end > offset {
					offset = end
				}
			}
		}
	}

	return nil
}

func (s *sendShard) scheduleFlushLocked() {
	timeout := s.parent.gsoFlushTimeout
	if timeout <= 0 {
		_ = s.flushPendingLocked()
		return
	}
	if s.flushTimer == nil {
		s.flushTimer = time.AfterFunc(timeout, s.flushTimerHandler)
		return
	}
	if !s.flushTimer.Stop() {
		// allow existing timer to drain
	}
	if !s.flushTimer.Reset(timeout) {
		s.flushTimer = time.AfterFunc(timeout, s.flushTimerHandler)
	}
}

func (s *sendShard) stopFlushTimerLocked() {
	if s.flushTimer != nil {
		s.flushTimer.Stop()
	}
}

func (s *sendShard) flushTimerHandler() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingSegments == 0 {
		return
	}
	if err := s.flushPendingLocked(); err != nil {
		s.parent.l.WithError(err).Warn("Failed to flush GSO batch")
	}
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

	if ip.Is4() && udpChecksumDisabled() {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_NO_CHECK, 1); err != nil {
			l.WithError(err).Warn("Failed to disable IPv4 UDP checksum via SO_NO_CHECK")
		} else {
			l.Debug("Disabled IPv4 UDP checksum using SO_NO_CHECK")
		}
	}

	conn := &StdConn{
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
	}
	conn.setGroBufferSize(defaultGROReadBufferSize)
	conn.initSendShards()
	return conn, err
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
		desiredGroSize := int(u.groBufSize.Load())
		if desiredGroSize < MTU {
			desiredGroSize = MTU
		}
		if len(buffers) == 0 || cap(buffers[0]) < desiredGroSize {
			u.recycleBufferSet(buffers)
			msgs, buffers, names, controls = u.PrepareRawMessages(u.batch)
		}
		desiredControl := int(u.controlLen.Load())
		hasControl := len(controls) > 0
		if (desiredControl > 0) != hasControl || (desiredControl > 0 && hasControl && len(controls[0]) != desiredControl) {
			u.recycleBufferSet(buffers)
			msgs, buffers, names, controls = u.PrepareRawMessages(u.batch)
			hasControl = len(controls) > 0
		}

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
			u.recycleBufferSet(buffers)
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
			buf := buffers[i]
			payload := buf[:payloadLen]
			released := false
			release := func() {
				if !released {
					released = true
					u.recycleBuffer(buf)
				}
			}
			handled := false

			if len(controls) > i && len(controls[i]) > 0 {
				if segSize, segCount := u.parseGROSegment(&msgs[i], controls[i]); segSize > 0 && segSize < payloadLen {
					if u.emitSegments(r, addr, payload, segSize, segCount, release) {
						handled = true
					} else if segCount > 1 {
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

			if !handled {
				r(addr, payload, release)
			}

			buffers[i] = u.borrowRxBuffer(desiredGroSize)
			setIovecBase(&msgs[i], buffers[i])
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
	shard := u.selectSendShard(addr)
	if shard == nil {
		return u.directWrite(b, addr)
	}
	return shard.write(b, addr)
}

func (u *StdConn) directWrite(b []byte, addr netip.AddrPort) error {
	if u.isV4 {
		return u.writeTo4(b, addr)
	}
	return u.writeTo6(b, addr)
}

func (u *StdConn) emitSegments(r EncReader, addr netip.AddrPort, payload []byte, segSize, segCount int, release func()) bool {
	if segSize <= 0 || segSize >= len(payload) {
		u.l.WithFields(logrus.Fields{
			"tag":         "gro-debug",
			"stage":       "emit",
			"reason":      "invalid_seg_size",
			"payload_len": len(payload),
			"seg_size":    segSize,
			"seg_count":   segCount,
		}).Debug("gro-debug skip emit")
		return false
	}

	totalLen := len(payload)
	if segCount <= 0 {
		segCount = (totalLen + segSize - 1) / segSize
	}
	if segCount <= 1 {
		u.l.WithFields(logrus.Fields{
			"tag":         "gro-debug",
			"stage":       "emit",
			"reason":      "single_segment",
			"payload_len": totalLen,
			"seg_size":    segSize,
			"seg_count":   segCount,
		}).Debug("gro-debug skip emit")
		return false
	}

	defer func() {
		if release != nil {
			release()
		}
	}()

	actualSegments := 0
	start := 0
	debugEnabled := u.l.IsLevelEnabled(logrus.DebugLevel)
	var firstHeader header.H
	var firstParsed bool
	var firstCounter uint64
	var firstRemote uint32

	for start < totalLen && actualSegments < segCount {
		end := start + segSize
		if end > totalLen {
			end = totalLen
		}

		segLen := end - start
		bufAny := u.groSegmentPool.Get()
		var segBuf []byte
		if bufAny == nil {
			segBuf = make([]byte, segLen)
		} else {
			segBuf = bufAny.([]byte)
			if cap(segBuf) < segLen {
				segBuf = make([]byte, segLen)
			}
		}
		segment := segBuf[:segLen]
		copy(segment, payload[start:end])

		if debugEnabled && !firstParsed {
			if err := firstHeader.Parse(segment); err == nil {
				firstParsed = true
				firstCounter = firstHeader.MessageCounter
				firstRemote = firstHeader.RemoteIndex
			} else {
				u.l.WithFields(logrus.Fields{
					"tag":         "gro-debug",
					"stage":       "emit",
					"event":       "parse_fail",
					"seg_index":   actualSegments,
					"seg_size":    segSize,
					"seg_count":   segCount,
					"payload_len": totalLen,
					"err":         err,
				}).Debug("gro-debug segment parse failed")
			}
		}

		start = end
		actualSegments++
		r(addr, segment, func() {
			u.groSegmentPool.Put(segBuf[:cap(segBuf)])
		})

		if debugEnabled && actualSegments == segCount && segLen < segSize {
			var tail header.H
			if err := tail.Parse(segment); err == nil {
				u.l.WithFields(logrus.Fields{
					"tag":             "gro-debug",
					"stage":           "emit",
					"event":           "tail_segment",
					"segment_len":     segLen,
					"remote_index":    tail.RemoteIndex,
					"message_counter": tail.MessageCounter,
				}).Debug("gro-debug tail segment metadata")
			}
		}

	}

	if u.groSegments != nil {
		u.groSegments.Inc(int64(actualSegments))
	}

	if debugEnabled && actualSegments > 0 {
		lastLen := segSize
		if tail := totalLen % segSize; tail != 0 {
			lastLen = tail
		}
		u.l.WithFields(logrus.Fields{
			"tag":           "gro-debug",
			"stage":         "emit",
			"event":         "success",
			"payload_len":   totalLen,
			"seg_size":      segSize,
			"seg_count":     segCount,
			"actual_segs":   actualSegments,
			"last_seg_len":  lastLen,
			"addr":          addr.String(),
			"first_remote":  firstRemote,
			"first_counter": firstCounter,
		}).Debug("gro-debug emit")
	}

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
	if len(u.sendShards) == 0 {
		u.initSendShards()
	}
	shardCount := c.GetInt("listen.send_shards", 0)
	u.resizeSendShards(shardCount)

	if !enable {
		if u.enableGSO {
			for _, shard := range u.sendShards {
				shard.mu.Lock()
				if shard.pendingSegments > 0 {
					if err := shard.flushPendingLocked(); err != nil {
						u.l.WithError(err).Warn("Failed to flush GSO buffers while disabling")
					}
				} else {
					shard.stopFlushTimerLocked()
				}
				buf := shard.pendingBuf
				shard.pendingBuf = nil
				shard.mu.Unlock()
				if buf != nil {
					u.releaseGSOBuf(buf)
				}
			}
			u.enableGSO = false
			u.l.Info("UDP GSO disabled")
		}
		u.setGroBufferSize(defaultGROReadBufferSize)
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
	if maxBytes > linuxMaxGSOBatchBytes {
		u.l.WithFields(logrus.Fields{
			"configured_bytes": maxBytes,
			"clamped_bytes":    linuxMaxGSOBatchBytes,
		}).Warn("listen.gso_max_bytes exceeds Linux UDP limit; clamping")
		maxBytes = linuxMaxGSOBatchBytes
	}

	flushTimeout := c.GetDuration("listen.gso_flush_timeout", defaultGSOFlushTimeout)
	if flushTimeout < 0 {
		flushTimeout = 0
	}

	u.enableGSO = true
	u.gsoMaxSegments = maxSegments
	u.gsoMaxBytes = maxBytes
	u.gsoFlushTimeout = flushTimeout
	bufSize := defaultGROReadBufferSize
	if u.gsoMaxBytes > bufSize {
		bufSize = u.gsoMaxBytes
	}
	u.setGroBufferSize(bufSize)

	for _, shard := range u.sendShards {
		shard.mu.Lock()
		if shard.pendingBuf != nil {
			u.releaseGSOBuf(shard.pendingBuf)
			shard.pendingBuf = nil
		}
		shard.pendingSegments = 0
		shard.pendingSegSize = 0
		shard.pendingAddr = netip.AddrPort{}
		shard.stopFlushTimerLocked()
		if len(shard.controlBuf) < unix.CmsgSpace(2) {
			shard.controlBuf = make([]byte, unix.CmsgSpace(2))
		}
		shard.mu.Unlock()
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
	// Attempt to unblock any outstanding sendmsg/sendmmsg calls so the shard
	// workers can drain promptly during shutdown. Ignoring errors here is fine
	// because some platforms/kernels may not support shutdown on UDP sockets.
	if err := unix.Shutdown(u.sysFd, unix.SHUT_WR); err != nil && err != unix.ENOTCONN && err != unix.EINVAL && err != unix.EBADF {
		u.l.WithError(err).Debug("Failed to shutdown UDP socket for close")
	}

	var flushErr error
	for _, shard := range u.sendShards {
		if shard == nil {
			continue
		}
		shard.mu.Lock()
		if shard.pendingSegments > 0 {
			if err := shard.flushPendingLocked(); err != nil && flushErr == nil {
				flushErr = err
			}
		} else {
			shard.stopFlushTimerLocked()
		}
		buf := shard.pendingBuf
		shard.pendingBuf = nil
		shard.mu.Unlock()
		if buf != nil {
			u.releaseGSOBuf(buf)
		}
		shard.stopSender()
	}

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
