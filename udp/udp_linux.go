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
	defaultGSOFlushTimeout   = 150 * time.Microsecond
	linuxMaxGSOBatchBytes    = 0xFFFF // Linux UDP GSO still limits the datagram payload to 64 KiB
	maxSendmmsgBatch         = 32
)

var (
	// Global mutex to serialize io_uring initialization across all sockets
	ioUringInitMu sync.Mutex
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

	gsoBatches           metrics.Counter
	gsoSegments          metrics.Counter
	gsoSingles           metrics.Counter
	groBatches           metrics.Counter
	groSegments          metrics.Counter
	gsoFallbacks         metrics.Counter
	gsoFallbackMu        sync.Mutex
	gsoFallbackReasons   map[string]*atomic.Int64
	gsoBatchTick         atomic.Int64
	gsoBatchSegmentsTick atomic.Int64
	gsoSingleTick        atomic.Int64
	groBatchTick         atomic.Int64
	groSegmentsTick      atomic.Int64

	ioState         atomic.Pointer[ioUringState]
	ioRecvState     atomic.Pointer[ioUringRecvState]
	ioActive        atomic.Bool
	ioRecvActive    atomic.Bool
	ioAttempted     atomic.Bool
	ioClosing       atomic.Bool
	ioUringHoldoff  atomic.Int64
	ioUringMaxBatch atomic.Int64

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

type batchSendItem struct {
	task        *sendTask
	addr        netip.AddrPort
	payload     []byte
	control     []byte
	msgFlags    uint32
	resultBytes int
	err         error
}

const sendShardQueueDepth = 128
const (
	ioUringDefaultMaxBatch      = 32
	ioUringMinMaxBatch          = 1
	ioUringMaxMaxBatch          = 4096
	ioUringDefaultHoldoff       = 25 * time.Microsecond
	ioUringMinHoldoff           = 0
	ioUringMaxHoldoff           = 500 * time.Millisecond
	ioUringHoldoffSpinThreshold = 50 * time.Microsecond
)

var ioUringSendmsgBatch = func(state *ioUringState, entries []ioUringBatchEntry) error {
	return state.SendmsgBatch(entries)
}

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

func clampIoUringBatchSize(requested int, ringEntries uint32) int {
	if requested < ioUringMinMaxBatch {
		requested = ioUringDefaultMaxBatch
	}
	if requested < ioUringMinMaxBatch {
		requested = ioUringMinMaxBatch
	}
	if requested > ioUringMaxMaxBatch {
		requested = ioUringMaxMaxBatch
	}
	if ringEntries > 0 && requested > int(ringEntries) {
		requested = int(ringEntries)
	}
	if requested < ioUringMinMaxBatch {
		requested = ioUringMinMaxBatch
	}
	return requested
}

func (s *sendShard) currentHoldoff() time.Duration {
	if s.parent == nil {
		return 0
	}
	holdoff := s.parent.ioUringHoldoff.Load()
	if holdoff < 0 {
		holdoff = 0
	}
	if holdoff <= 0 {
		return 0
	}
	return time.Duration(holdoff)
}

func (s *sendShard) currentMaxBatch() int {
	if s == nil || s.parent == nil {
		return ioUringDefaultMaxBatch
	}
	maxBatch := s.parent.ioUringMaxBatch.Load()
	if maxBatch <= 0 {
		return ioUringDefaultMaxBatch
	}
	if maxBatch > ioUringMaxMaxBatch {
		maxBatch = ioUringMaxMaxBatch
	}
	return int(maxBatch)
}

func (u *StdConn) initSendShards() {
	shardCount := runtime.GOMAXPROCS(0)
	if shardCount < 1 {
		shardCount = 1
	}
	u.resizeSendShards(shardCount)
}

func toIPv4Mapped(v4 [4]byte) [16]byte {
	return [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, v4[0], v4[1], v4[2], v4[3]}
}

func (u *StdConn) populateSockaddrInet6(sa6 *unix.RawSockaddrInet6, addr netip.Addr) {
	sa6.Family = unix.AF_INET6
	if addr.Is4() {
		// Convert IPv4 to IPv4-mapped IPv6 format for dual-stack socket
		sa6.Addr = toIPv4Mapped(addr.As4())
	} else {
		sa6.Addr = addr.As16()
	}
	sa6.Scope_id = 0
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

	// Give existing shard workers time to fully initialize before stopping
	// This prevents a race where we try to stop shards before they're ready
	if len(u.sendShards) > 0 {
		time.Sleep(time.Millisecond)
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

func isSocketCloseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, unix.EPIPE) || errors.Is(err, unix.ENOTCONN) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EBADF) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errno, ok := opErr.Err.(syscall.Errno); ok {
			switch errno {
			case unix.EPIPE, unix.ENOTCONN, unix.EINVAL, unix.EBADF:
				return true
			}
		}
	}
	return false
}

func (u *StdConn) recordGSOFallback(reason string) {
	if u == nil {
		return
	}
	if reason == "" {
		reason = "unknown"
	}
	if u.gsoFallbacks != nil {
		u.gsoFallbacks.Inc(1)
	}
	u.gsoFallbackMu.Lock()
	counter, ok := u.gsoFallbackReasons[reason]
	if !ok {
		counter = &atomic.Int64{}
		u.gsoFallbackReasons[reason] = counter
	}
	counter.Add(1)
	u.gsoFallbackMu.Unlock()
}

func (u *StdConn) recordGSOSingle(count int) {
	if u == nil || count <= 0 {
		return
	}
	if u.gsoSingles != nil {
		u.gsoSingles.Inc(int64(count))
	}
	u.gsoSingleTick.Add(int64(count))
}

func (u *StdConn) snapshotGSOFallbacks() map[string]int64 {
	u.gsoFallbackMu.Lock()
	defer u.gsoFallbackMu.Unlock()
	if len(u.gsoFallbackReasons) == 0 {
		return nil
	}
	out := make(map[string]int64, len(u.gsoFallbackReasons))
	for reason, counter := range u.gsoFallbackReasons {
		if counter == nil {
			continue
		}
		count := counter.Swap(0)
		if count != 0 {
			out[reason] = count
		}
	}
	return out
}

func (u *StdConn) logGSOTick() {
	u.gsoBatchTick.Store(0)
	u.gsoBatchSegmentsTick.Store(0)
	u.gsoSingleTick.Store(0)
	u.groBatchTick.Store(0)
	u.groSegmentsTick.Store(0)
	u.snapshotGSOFallbacks()
}

func (u *StdConn) borrowGSOBuf() []byte {
	size := u.gsoMaxBytes
	if size <= 0 {
		size = MTU
	}
	if v := u.gsoBufferPool.Get(); v != nil {
		buf := v.([]byte)
		if cap(buf) < size {
			u.gsoBufferPool.Put(buf[:0])
			return make([]byte, 0, size)
		}
		return buf[:0]
	}
	return make([]byte, 0, size)
}

func (u *StdConn) borrowIOBuf(size int) []byte {
	if size <= 0 {
		size = MTU
	}
	if v := u.gsoBufferPool.Get(); v != nil {
		buf := v.([]byte)
		if cap(buf) < size {
			u.gsoBufferPool.Put(buf[:0])
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

func (s *sendShard) submitTask(task *sendTask) error {
	if task == nil {
		return nil
	}
	if len(task.buf) == 0 {
		if task.owned && task.buf != nil && s.parent != nil {
			s.parent.releaseGSOBuf(task.buf)
		}
		return nil
	}

	if s.parent != nil && s.parent.ioClosing.Load() {
		if task.owned && task.buf != nil {
			s.parent.releaseGSOBuf(task.buf)
		}
		return &net.OpError{Op: "sendmsg", Err: net.ErrClosed}
	}

	queue := s.outQueue
	if queue != nil {
		sent := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					sent = false
				}
			}()
			select {
			case queue <- task:
				sent = true
			default:
			}
		}()
		if sent {
			return nil
		}
	}

	return s.processTask(task)
}

func (s *sendShard) senderLoop() {
	defer s.workerDone.Done()
	initialCap := s.currentMaxBatch()
	if initialCap <= 0 {
		initialCap = ioUringDefaultMaxBatch
	}
	batch := make([]*sendTask, 0, initialCap)
	var holdoffTimer *time.Timer
	var holdoffCh <-chan time.Time

	stopTimer := func() {
		if holdoffTimer == nil {
			return
		}
		if !holdoffTimer.Stop() {
			select {
			case <-holdoffTimer.C:
			default:
			}
		}
		holdoffTimer = nil
		holdoffCh = nil
	}

	resetTimer := func() {
		holdoff := s.currentHoldoff()
		if holdoff <= 0 {
			return
		}
		if holdoffTimer == nil {
			holdoffTimer = time.NewTimer(holdoff)
			holdoffCh = holdoffTimer.C
			return
		}
		if !holdoffTimer.Stop() {
			select {
			case <-holdoffTimer.C:
			default:
			}
		}
		holdoffTimer.Reset(holdoff)
		holdoffCh = holdoffTimer.C
	}

	flush := func() {
		if len(batch) == 0 {
			return
		}
		stopTimer()
		if err := s.processTasksBatch(batch); err != nil && s.parent != nil {
			s.parent.l.WithError(err).Debug("io_uring batch send encountered error")
		}
		for i := range batch {
			batch[i] = nil
		}
		batch = batch[:0]
	}

	for {
		if len(batch) == 0 {
			if s.parent != nil && s.parent.ioClosing.Load() {
				flush()
				stopTimer()
				return
			}
			task, ok := <-s.outQueue
			if !ok {
				flush()
				stopTimer()
				return
			}
			if task == nil {
				continue
			}
			batch = append(batch, task)
			maxBatch := s.currentMaxBatch()
			holdoff := s.currentHoldoff()
			if len(batch) >= maxBatch || holdoff <= 0 {
				flush()
				continue
			}
			if holdoff <= ioUringHoldoffSpinThreshold {
				deadline := time.Now().Add(holdoff)
				for {
					if len(batch) >= maxBatch {
						break
					}
					remaining := time.Until(deadline)
					if remaining <= 0 {
						break
					}
					select {
					case next, ok := <-s.outQueue:
						if !ok {
							flush()
							return
						}
						if next == nil {
							continue
						}
						if s.parent != nil && s.parent.ioClosing.Load() {
							flush()
							return
						}
						batch = append(batch, next)
					default:
						if remaining > 5*time.Microsecond {
							runtime.Gosched()
						}
					}
				}
				flush()
				continue
			}
			resetTimer()
			continue
		}

		select {
		case task, ok := <-s.outQueue:
			if !ok {
				flush()
				stopTimer()
				return
			}
			if task == nil {
				continue
			}
			if s.parent != nil && s.parent.ioClosing.Load() {
				flush()
				stopTimer()
				return
			}
			batch = append(batch, task)
			if len(batch) >= s.currentMaxBatch() {
				flush()
			} else if s.currentHoldoff() > 0 {
				resetTimer()
			}
		case <-holdoffCh:
			stopTimer()
			flush()
		}
	}
}

func (s *sendShard) processTask(task *sendTask) error {
	return s.processTasksBatch([]*sendTask{task})
}

func (s *sendShard) processTasksBatch(tasks []*sendTask) error {
	if len(tasks) == 0 {
		return nil
	}
	p := s.parent
	state := p.ioState.Load()
	var firstErr error
	if state != nil {
		if err := s.processTasksBatchIOUring(state, tasks); err != nil {
			firstErr = err
		}
	} else {
		for _, task := range tasks {
			if err := s.processTaskFallback(task); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	for _, task := range tasks {
		if task == nil {
			continue
		}
		if task.owned && task.buf != nil {
			p.releaseGSOBuf(task.buf)
		}
		task.buf = nil
	}
	return firstErr
}

func (s *sendShard) processTasksBatchIOUring(state *ioUringState, tasks []*sendTask) error {
	capEstimate := 0
	maxSeg := 1
	if s.parent != nil && s.parent.ioUringMaxBatch.Load() > 0 {
		maxSeg = int(s.parent.ioUringMaxBatch.Load())
	}
	for _, task := range tasks {
		if task == nil || len(task.buf) == 0 {
			continue
		}
		if task.segSize > 0 && task.segSize < len(task.buf) {
			capEstimate += (len(task.buf) + task.segSize - 1) / task.segSize
		} else {
			capEstimate++
		}
	}
	if capEstimate <= 0 {
		capEstimate = len(tasks)
	}
	if capEstimate > maxSeg {
		capEstimate = maxSeg
	}
	items := make([]*batchSendItem, 0, capEstimate)
	for _, task := range tasks {
		if task == nil || len(task.buf) == 0 {
			continue
		}
		useGSO := s.parent.enableGSO && task.segments > 1
		if useGSO {
			control := make([]byte, unix.CmsgSpace(2))
			hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
			setCmsgLen(hdr, 2)
			hdr.Level = unix.SOL_UDP
			hdr.Type = unix.UDP_SEGMENT
			dataOff := unix.CmsgLen(0)
			binary.NativeEndian.PutUint16(control[dataOff:dataOff+2], uint16(task.segSize))
			items = append(items, &batchSendItem{
				task:     task,
				addr:     task.addr,
				payload:  task.buf,
				control:  control,
				msgFlags: 0,
			})
			continue
		}

		segSize := task.segSize
		if segSize <= 0 || segSize >= len(task.buf) {
			items = append(items, &batchSendItem{
				task:    task,
				addr:    task.addr,
				payload: task.buf,
			})
			continue
		}

		for offset := 0; offset < len(task.buf); offset += segSize {
			end := offset + segSize
			if end > len(task.buf) {
				end = len(task.buf)
			}
			segment := task.buf[offset:end]
			items = append(items, &batchSendItem{
				task:    task,
				addr:    task.addr,
				payload: segment,
			})
		}
	}

	if len(items) == 0 {
		return nil
	}

	if err := s.parent.sendMsgIOUringBatch(state, items); err != nil {
		return err
	}

	var firstErr error
	for _, item := range items {
		if item.err != nil && firstErr == nil {
			firstErr = item.err
		}
	}
	if firstErr != nil {
		return firstErr
	}

	for _, task := range tasks {
		if task == nil {
			continue
		}
		if s.parent.enableGSO && task.segments > 1 {
			s.recordGSOMetrics(task)
		} else {
			s.parent.recordGSOSingle(task.segments)
		}
	}

	return nil
}

func (s *sendShard) processTaskFallback(task *sendTask) error {
	if task == nil || len(task.buf) == 0 {
		return nil
	}
	p := s.parent
	useGSO := p.enableGSO && task.segments > 1
	s.mu.Lock()
	defer s.mu.Unlock()
	if useGSO {
		if err := s.sendSegmentedLocked(task.buf, task.addr, task.segSize); err != nil {
			return err
		}
		s.recordGSOMetrics(task)
		return nil
	}
	if err := s.sendSequentialLocked(task.buf, task.addr, task.segSize); err != nil {
		return err
	}
	p.recordGSOSingle(task.segments)
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
	p.gsoBatchTick.Add(1)
	p.gsoBatchSegmentsTick.Add(int64(task.segments))
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
		p.recordGSOSingle(1)
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
		p.recordGSOSingle(1)
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

	s.mu.Unlock()
	err := s.submitTask(task)
	s.mu.Lock()
	return err
}

func (s *sendShard) enqueueImmediate(payload []byte, addr netip.AddrPort) error {
	if len(payload) == 0 {
		return nil
	}
	if !addr.IsValid() {
		return &net.OpError{Op: "sendmsg", Err: unix.EINVAL}
	}
	if s.parent != nil && s.parent.ioClosing.Load() {
		return &net.OpError{Op: "sendmsg", Err: net.ErrClosed}
	}

	buf := s.parent.borrowIOBuf(len(payload))
	buf = append(buf[:0], payload...)

	task := &sendTask{
		buf:      buf,
		addr:     addr,
		segSize:  len(payload),
		segments: 1,
		owned:    true,
	}
	if err := s.submitTask(task); err != nil {
		return err
	}
	return nil
}

func (s *sendShard) sendSegmentedIOUring(state *ioUringState, buf []byte, addr netip.AddrPort, segSize int) error {
	if state == nil || len(buf) == 0 {
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

	n, err := s.parent.sendMsgIOUring(state, addr, buf, control, 0)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return &net.OpError{Op: "sendmsg", Err: unix.EIO}
	}
	return nil
}

func (s *sendShard) sendSequentialIOUring(state *ioUringState, buf []byte, addr netip.AddrPort, segSize int) error {
	if state == nil || len(buf) == 0 {
		return nil
	}
	if segSize <= 0 {
		segSize = len(buf)
	}
	if segSize >= len(buf) {
		n, err := s.parent.sendMsgIOUring(state, addr, buf, nil, 0)
		if err != nil {
			return err
		}
		if n != len(buf) {
			return &net.OpError{Op: "sendmsg", Err: unix.EIO}
		}
		return nil
	}

	total := len(buf)
	offset := 0
	for offset < total {
		end := offset + segSize
		if end > total {
			end = total
		}
		segment := buf[offset:end]
		n, err := s.parent.sendMsgIOUring(state, addr, segment, nil, 0)
		if err != nil {
			return err
		}
		if n != len(segment) {
			return &net.OpError{Op: "sendmsg", Err: unix.EIO}
		}
		offset = end
	}
	return nil
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
		if !isSocketCloseError(err) {
			s.parent.l.WithError(err).Warn("Failed to flush GSO batch")
		}
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

	if af == unix.AF_INET6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0); err != nil {
			l.WithError(err).Warn("Failed to clear IPV6_V6ONLY on IPv6 UDP socket")
		} else if v6only, err := unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY); err == nil {
			l.WithField("v6only", v6only).Debug("Configured IPv6 UDP socket V6ONLY state")
		}
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
		sysFd:              fd,
		isV4:               ip.Is4(),
		l:                  l,
		batch:              batch,
		gsoMaxSegments:     defaultGSOMaxSegments,
		gsoMaxBytes:        defaultGSOMaxBytes,
		gsoFlushTimeout:    defaultGSOFlushTimeout,
		gsoBatches:         metrics.GetOrRegisterCounter("udp.gso.batches", nil),
		gsoSegments:        metrics.GetOrRegisterCounter("udp.gso.segments", nil),
		gsoSingles:         metrics.GetOrRegisterCounter("udp.gso.singles", nil),
		groBatches:         metrics.GetOrRegisterCounter("udp.gro.batches", nil),
		groSegments:        metrics.GetOrRegisterCounter("udp.gro.segments", nil),
		gsoFallbacks:       metrics.GetOrRegisterCounter("udp.gso.fallbacks", nil),
		gsoFallbackReasons: make(map[string]*atomic.Int64),
	}
	conn.ioUringHoldoff.Store(int64(ioUringDefaultHoldoff))
	conn.ioUringMaxBatch.Store(int64(ioUringDefaultMaxBatch))
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

	// Check if io_uring receive ring is available
	recvRing := u.ioRecvState.Load()
	useIoUringRecv := recvRing != nil && u.ioRecvActive.Load()

	u.l.WithFields(logrus.Fields{
		"batch":         u.batch,
		"io_uring_send": u.ioState.Load() != nil,
		"io_uring_recv": useIoUringRecv,
	}).Info("ListenOut starting")

	if useIoUringRecv {
		// Use dedicated io_uring receive ring
		u.l.Info("ListenOut: using io_uring receive path")

		// Pre-fill the receive queue now that we're ready to receive
		if err := recvRing.fillRecvQueue(); err != nil {
			u.l.WithError(err).Error("Failed to fill receive queue")
			return
		}

		for {
			// Receive packets from io_uring (wait=true blocks until at least one packet arrives)
			packets, err := recvRing.receivePackets(true)
			if err != nil {
				u.l.WithError(err).Error("io_uring receive failed")
				return
			}

			if len(packets) > 0 && u.l.IsLevelEnabled(logrus.DebugLevel) {
				totalBytes := 0
				groPackets := 0
				groSegments := 0
				for i := range packets {
					totalBytes += packets[i].N
					if packets[i].Controllen > 0 {
						if _, segCount := u.parseGROSegmentFromControl(packets[i].Control, packets[i].Controllen); segCount > 1 {
							groPackets++
							groSegments += segCount
						}
					}
				}
				fields := logrus.Fields{
					"entry_count":   len(packets),
					"payload_bytes": totalBytes,
				}
				if groPackets > 0 {
					fields["gro_packets"] = groPackets
					fields["gro_segments"] = groSegments
				}
				u.l.WithFields(fields).Debug("io_uring recv batch")
			}

			for _, pkt := range packets {
				// Extract address from RawSockaddrInet6
				if pkt.From.Family != unix.AF_INET6 {
					u.l.WithField("family", pkt.From.Family).Warn("Received packet with unexpected address family")
					continue
				}

				ip, _ = netip.AddrFromSlice(pkt.From.Addr[:])
				addr := netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&pkt.From.Port))[:]))
				payload := pkt.Data[:pkt.N]
				release := pkt.RecycleFunc
				released := false
				releaseOnce := func() {
					if !released {
						released = true
						release()
					}
				}

				// Check for GRO segments
				handled := false
				if pkt.Controllen > 0 && len(pkt.Control) > 0 {
					if segSize, segCount := u.parseGROSegmentFromControl(pkt.Control, pkt.Controllen); segSize > 0 && segSize < pkt.N {
						if segCount > 1 && u.l.IsLevelEnabled(logrus.DebugLevel) {
							u.l.WithFields(logrus.Fields{
								"segments":     segCount,
								"segment_size": segSize,
								"batch_bytes":  pkt.N,
								"remote_addr":  addr.String(),
							}).Debug("gro batch received")
						}
						if u.emitSegments(r, addr, payload, segSize, segCount, releaseOnce) {
							handled = true
						} else if segCount > 1 {
							u.l.WithFields(logrus.Fields{
								"tag":         "gro-debug",
								"stage":       "io_uring_recv",
								"reason":      "emit_failed",
								"payload_len": pkt.N,
								"seg_size":    segSize,
								"seg_count":   segCount,
							}).Debug("gro-debug fallback to single packet")
						}
					}
				}

				if !handled {
					r(addr, payload, releaseOnce)
				}
			}
		}
	}

	// Fallback path: use standard recvmsg
	u.l.Info("ListenOut: using standard recvmsg path")
	msgs, buffers, names, controls := u.PrepareRawMessages(u.batch)
	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	u.l.WithFields(logrus.Fields{
		"using_ReadSingle": u.batch == 1,
		"using_ReadMulti":  u.batch != 1,
	}).Info("ListenOut read function selected")

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

		u.l.Debug("ListenOut: about to call read(msgs)")
		n, err := read(msgs)
		if err != nil {
			u.l.WithError(err).Error("ListenOut: read(msgs) failed, exiting read loop")
			u.recycleBufferSet(buffers)
			return
		}
		u.l.WithField("packets_read", n).Debug("ListenOut: read(msgs) returned")

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
					if segCount > 1 && u.l.IsLevelEnabled(logrus.DebugLevel) {
						u.l.WithFields(logrus.Fields{
							"segments":     segCount,
							"segment_size": segSize,
							"batch_bytes":  payloadLen,
							"remote_addr":  addr.String(),
						}).Debug("gro batch received")
					}
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
func isEAgain(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errno, ok := opErr.Err.(syscall.Errno); ok {
			return errno == unix.EAGAIN || errno == unix.EWOULDBLOCK
		}
	}
	if errno, ok := err.(syscall.Errno); ok {
		return errno == unix.EAGAIN || errno == unix.EWOULDBLOCK
	}
	return false
}

func (u *StdConn) readSingleSyscall(msgs []rawMessage) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	for {
		n, _, errno := unix.Syscall6(
			unix.SYS_RECVMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&msgs[0].Hdr)),
			0,
			0,
			0,
			0,
		)
		if errno != 0 {
			err := syscall.Errno(errno)
			if err == unix.EINTR {
				continue
			}
			return 0, &net.OpError{Op: "recvmsg", Err: err}
		}
		msgs[0].Len = uint32(n)
		return 1, nil
	}
}

func (u *StdConn) readMultiSyscall(msgs []rawMessage) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	for {
		n, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(len(msgs)),
			unix.MSG_WAITFORONE,
			0,
			0,
		)
		if errno != 0 {
			err := syscall.Errno(errno)
			if err == unix.EINTR {
				continue
			}
			return 0, &net.OpError{Op: "recvmmsg", Err: err}
		}
		return int(n), nil
	}
}

func (u *StdConn) ReadSingle(msgs []rawMessage) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	u.l.Debug("ReadSingle called")

	state := u.ioState.Load()
	if state == nil {
		return u.readSingleSyscall(msgs)
	}

	u.l.Debug("ReadSingle: converting rawMessage to unix.Msghdr")
	hdr, iov, err := rawMessageToUnixMsghdr(&msgs[0])
	if err != nil {
		u.l.WithError(err).Error("ReadSingle: rawMessageToUnixMsghdr failed")
		return 0, &net.OpError{Op: "recvmsg", Err: err}
	}

	u.l.WithFields(logrus.Fields{
		"bufLen":  iov.Len,
		"nameLen": hdr.Namelen,
		"ctrlLen": hdr.Controllen,
	}).Debug("ReadSingle: calling state.Recvmsg")

	n, _, recvErr := state.Recvmsg(u.sysFd, &hdr, 0)
	if recvErr != nil {
		u.l.WithError(recvErr).Error("ReadSingle: state.Recvmsg failed")
		return 0, recvErr
	}

	u.l.WithFields(logrus.Fields{
		"bytesRead": n,
	}).Debug("ReadSingle: successfully received")

	updateRawMessageFromUnixMsghdr(&msgs[0], &hdr, n)
	runtime.KeepAlive(iov)
	runtime.KeepAlive(hdr)
	return 1, nil
}

func (u *StdConn) ReadMulti(msgs []rawMessage) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	u.l.WithField("batch_size", len(msgs)).Debug("ReadMulti called")

	state := u.ioState.Load()
	if state == nil {
		return u.readMultiSyscall(msgs)
	}

	count := 0
	for i := range msgs {
		hdr, iov, err := rawMessageToUnixMsghdr(&msgs[i])
		if err != nil {
			u.l.WithError(err).WithField("index", i).Error("ReadMulti: rawMessageToUnixMsghdr failed")
			if count > 0 {
				return count, nil
			}
			return 0, &net.OpError{Op: "recvmsg", Err: err}
		}

		flags := uint32(0)
		if i > 0 {
			flags = unix.MSG_DONTWAIT
		}

		u.l.WithFields(logrus.Fields{
			"index":  i,
			"flags":  flags,
			"bufLen": iov.Len,
		}).Debug("ReadMulti: calling state.Recvmsg")

		n, _, recvErr := state.Recvmsg(u.sysFd, &hdr, flags)
		if recvErr != nil {
			u.l.WithError(recvErr).WithFields(logrus.Fields{
				"index": i,
				"count": count,
			}).Debug("ReadMulti: state.Recvmsg error")
			if isEAgain(recvErr) && count > 0 {
				u.l.WithField("count", count).Debug("ReadMulti: EAGAIN with existing packets, returning")
				return count, nil
			}
			if count > 0 {
				return count, recvErr
			}
			return 0, recvErr
		}

		u.l.WithFields(logrus.Fields{
			"index":     i,
			"bytesRead": n,
		}).Debug("ReadMulti: packet received")

		updateRawMessageFromUnixMsghdr(&msgs[i], &hdr, n)
		runtime.KeepAlive(iov)
		runtime.KeepAlive(hdr)
		count++
	}

	u.l.WithField("total_count", count).Debug("ReadMulti: completed")
	return count, nil
}

func (u *StdConn) WriteTo(b []byte, ip netip.AddrPort) error {
	if len(b) == 0 {
		return nil
	}
	if u.ioClosing.Load() {
		return &net.OpError{Op: "sendmsg", Err: net.ErrClosed}
	}
	if u.enableGSO {
		return u.writeToGSO(b, ip)
	}
	if u.ioState.Load() != nil {
		if shard := u.selectSendShard(ip); shard != nil {
			if err := shard.enqueueImmediate(b, ip); err != nil {
				return err
			}
			return nil
		}
	}
	u.recordGSOSingle(1)
	return u.directWrite(b, ip)
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
		u.recordGSOSingle(1)
		return u.directWrite(b, addr)
	}
	return shard.write(b, addr)
}

func (u *StdConn) sendMsgIOUring(state *ioUringState, addr netip.AddrPort, payload []byte, control []byte, msgFlags uint32) (int, error) {
	if state == nil {
		return 0, &net.OpError{Op: "sendmsg", Err: syscall.EINVAL}
	}
	if len(payload) == 0 {
		return 0, nil
	}
	if !addr.IsValid() {
		return 0, &net.OpError{Op: "sendmsg", Err: unix.EINVAL}
	}
	if !u.ioAttempted.Load() {
		u.ioAttempted.Store(true)
		u.l.WithFields(logrus.Fields{
			"addr": addr.String(),
			"len":  len(payload),
			"ctrl": control != nil,
		}).Debug("io_uring send attempt")
	}
	u.l.WithFields(logrus.Fields{
		"addr": addr.String(),
		"len":  len(payload),
		"ctrl": control != nil,
	}).Debug("io_uring sendMsgIOUring invoked")

	var iov unix.Iovec
	iov.Base = &payload[0]
	setIovecLen(&iov, len(payload))

	var msg unix.Msghdr
	msg.Iov = &iov
	setMsghdrIovlen(&msg, 1)

	if len(control) > 0 {
		msg.Control = &control[0]
		msg.Controllen = controllen(len(control))
	}

	u.l.WithFields(logrus.Fields{
		"addr":           addr.String(),
		"payload_len":    len(payload),
		"ctrl_len":       len(control),
		"msg_iovlen":     msg.Iovlen,
		"msg_controllen": msg.Controllen,
	}).Debug("io_uring prepared msghdr")

	var (
		n   int
		err error
	)

	if u.isV4 {
		if !addr.Addr().Is4() {
			return 0, ErrInvalidIPv6RemoteForSocket
		}
		var sa4 unix.RawSockaddrInet4
		sa4.Family = unix.AF_INET
		sa4.Addr = addr.Addr().As4()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa4.Port))[:], addr.Port())
		msg.Name = (*byte)(unsafe.Pointer(&sa4))
		msg.Namelen = uint32(unsafe.Sizeof(sa4))
		u.l.WithFields(logrus.Fields{
			"addr":        addr.String(),
			"sa_family":   sa4.Family,
			"sa_port":     sa4.Port,
			"msg_namelen": msg.Namelen,
		}).Debug("io_uring sendmsg sockaddr v4")
		n, err = state.Sendmsg(u.sysFd, &msg, msgFlags, uint32(len(payload)))
		runtime.KeepAlive(sa4)
	} else {
		// For IPv6 sockets, always use RawSockaddrInet6, even for IPv4 addresses
		// (convert IPv4 to IPv4-mapped IPv6 format)
		var sa6 unix.RawSockaddrInet6
		u.populateSockaddrInet6(&sa6, addr.Addr())
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa6.Port))[:], addr.Port())
		msg.Name = (*byte)(unsafe.Pointer(&sa6))
		msg.Namelen = uint32(unsafe.Sizeof(sa6))
		u.l.WithFields(logrus.Fields{
			"addr":        addr.String(),
			"sa_family":   sa6.Family,
			"sa_port":     sa6.Port,
			"scope_id":    sa6.Scope_id,
			"msg_namelen": msg.Namelen,
			"is_v4":       addr.Addr().Is4(),
		}).Debug("io_uring sendmsg sockaddr v6")
		n, err = state.Sendmsg(u.sysFd, &msg, msgFlags, uint32(len(payload)))
		runtime.KeepAlive(sa6)
	}

	if err == nil && n == len(payload) {
		u.noteIoUringSuccess()
	}
	runtime.KeepAlive(payload)
	runtime.KeepAlive(control)
	u.logIoUringResult(addr, len(payload), n, err)
	if err == nil && n == 0 && len(payload) > 0 {
		syncWritten, syncErr := u.sendMsgSync(addr, payload, control, int(msgFlags))
		if syncErr == nil && syncWritten == len(payload) {
			u.l.WithFields(logrus.Fields{
				"addr":         addr.String(),
				"expected":     len(payload),
				"sync_written": syncWritten,
			}).Warn("io_uring returned short write; used synchronous sendmsg fallback")
			u.noteIoUringSuccess()
			u.logIoUringResult(addr, len(payload), syncWritten, syncErr)
			return syncWritten, nil
		}
		u.l.WithFields(logrus.Fields{
			"addr":         addr.String(),
			"expected":     len(payload),
			"sync_written": syncWritten,
			"sync_err":     syncErr,
		}).Warn("sync sendmsg result after io_uring short write")
	}
	return n, err
}

func (u *StdConn) sendMsgIOUringBatch(state *ioUringState, items []*batchSendItem) error {
	if u.ioClosing.Load() {
		for _, item := range items {
			if item != nil {
				item.err = &net.OpError{Op: "sendmsg", Err: net.ErrClosed}
			}
		}
		return &net.OpError{Op: "sendmsg", Err: net.ErrClosed}
	}
	if state == nil {
		return &net.OpError{Op: "sendmsg", Err: syscall.EINVAL}
	}
	if len(items) == 0 {
		return nil
	}

	results := make([]ioUringBatchResult, len(items))
	payloads := make([][]byte, len(items))
	controls := make([][]byte, len(items))
	entries := make([]ioUringBatchEntry, len(items))
	msgs := make([]unix.Msghdr, len(items))
	iovecs := make([]unix.Iovec, len(items))
	var sa4 []unix.RawSockaddrInet4
	var sa6 []unix.RawSockaddrInet6
	if u.isV4 {
		sa4 = make([]unix.RawSockaddrInet4, len(items))
	} else {
		sa6 = make([]unix.RawSockaddrInet6, len(items))
	}

	entryIdx := 0
	totalPayload := 0
	skipped := 0
	for i, item := range items {
		if item == nil || len(item.payload) == 0 {
			item.resultBytes = 0
			item.err = nil
			skipped++
			continue
		}

		addr := item.addr
		if !addr.IsValid() {
			item.err = &net.OpError{Op: "sendmsg", Err: unix.EINVAL}
			skipped++
			continue
		}
		if u.isV4 && !addr.Addr().Is4() {
			item.err = ErrInvalidIPv6RemoteForSocket
			skipped++
			continue
		}

		payload := item.payload
		payloads[i] = payload
		totalPayload += len(payload)

		iov := &iovecs[entryIdx]
		iov.Base = &payload[0]
		setIovecLen(iov, len(payload))

		msg := &msgs[entryIdx]
		msg.Iov = iov
		setMsghdrIovlen(msg, 1)

		if len(item.control) > 0 {
			controls[i] = item.control
			msg.Control = &item.control[0]
			msg.Controllen = controllen(len(item.control))
		}

		if u.isV4 {
			sa := &sa4[entryIdx]
			sa.Family = unix.AF_INET
			sa.Addr = addr.Addr().As4()
			binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], addr.Port())
			msg.Name = (*byte)(unsafe.Pointer(sa))
			msg.Namelen = uint32(unsafe.Sizeof(*sa))
		} else {
			sa := &sa6[entryIdx]
			sa.Family = unix.AF_INET6
			u.populateSockaddrInet6(sa, addr.Addr())
			binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], addr.Port())
			msg.Name = (*byte)(unsafe.Pointer(sa))
			msg.Namelen = uint32(unsafe.Sizeof(*sa))
		}

		entries[entryIdx] = ioUringBatchEntry{
			fd:         u.sysFd,
			msg:        msg,
			msgFlags:   item.msgFlags,
			payloadLen: uint32(len(payload)),
			result:     &results[i],
		}
		entryIdx++
	}

	if entryIdx == 0 {
		for _, payload := range payloads {
			runtime.KeepAlive(payload)
		}
		for _, control := range controls {
			runtime.KeepAlive(control)
		}
		var firstErr error
		for _, item := range items {
			if item != nil && item.err != nil {
				firstErr = item.err
				break
			}
		}
		return firstErr
	}

	if err := ioUringSendmsgBatch(state, entries[:entryIdx]); err != nil {
		for _, payload := range payloads {
			runtime.KeepAlive(payload)
		}
		for _, control := range controls {
			runtime.KeepAlive(control)
		}
		if len(sa4) > 0 {
			runtime.KeepAlive(sa4[:entryIdx])
		}
		if len(sa6) > 0 {
			runtime.KeepAlive(sa6[:entryIdx])
		}
		return err
	}

	if u.l.IsLevelEnabled(logrus.DebugLevel) {
		u.l.WithFields(logrus.Fields{
			"entry_count":   entryIdx,
			"skipped_items": skipped,
			"payload_bytes": totalPayload,
		}).Debug("io_uring batch submitted")
	}

	var firstErr error
	for i, item := range items {
		if item == nil || len(item.payload) == 0 {
			continue
		}
		if item.err != nil {
			if firstErr == nil {
				firstErr = item.err
			}
			continue
		}

		res := results[i]
		if res.err != nil {
			item.err = res.err
		} else if res.res < 0 {
			item.err = syscall.Errno(-res.res)
		} else if int(res.res) != len(item.payload) {
			item.err = fmt.Errorf("io_uring short write: wrote %d expected %d", res.res, len(item.payload))
		} else {
			item.err = nil
			item.resultBytes = int(res.res)
		}

		u.logIoUringResult(item.addr, len(item.payload), int(res.res), item.err)
		if item.err != nil && firstErr == nil {
			firstErr = item.err
		}
	}

	for _, payload := range payloads {
		runtime.KeepAlive(payload)
	}
	for _, control := range controls {
		runtime.KeepAlive(control)
	}
	if len(sa4) > 0 {
		runtime.KeepAlive(sa4[:entryIdx])
	}
	if len(sa6) > 0 {
		runtime.KeepAlive(sa6[:entryIdx])
	}

	if firstErr == nil {
		u.noteIoUringSuccess()
	}

	return firstErr
}

func (u *StdConn) sendMsgSync(addr netip.AddrPort, payload []byte, control []byte, msgFlags int) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	if u.isV4 {
		if !addr.Addr().Is4() {
			return 0, ErrInvalidIPv6RemoteForSocket
		}
		sa := &unix.SockaddrInet4{Port: int(addr.Port())}
		sa.Addr = addr.Addr().As4()
		return unix.SendmsgN(u.sysFd, payload, control, sa, msgFlags)
	}
	sa := &unix.SockaddrInet6{Port: int(addr.Port())}
	if addr.Addr().Is4() {
		sa.Addr = toIPv4Mapped(addr.Addr().As4())
	} else {
		sa.Addr = addr.Addr().As16()
	}
	if zone := addr.Addr().Zone(); zone != "" {
		if iface, err := net.InterfaceByName(zone); err == nil {
			sa.ZoneId = uint32(iface.Index)
		} else {
			u.l.WithFields(logrus.Fields{
				"addr": addr.Addr().String(),
				"zone": zone,
			}).WithError(err).Debug("io_uring failed to resolve IPv6 zone")
		}
	}
	return unix.SendmsgN(u.sysFd, payload, control, sa, msgFlags)
}

func (u *StdConn) directWrite(b []byte, addr netip.AddrPort) error {
	if len(b) == 0 {
		return nil
	}
	if !addr.IsValid() {
		return &net.OpError{Op: "sendmsg", Err: unix.EINVAL}
	}
	state := u.ioState.Load()
	u.l.WithFields(logrus.Fields{
		"addr":         addr.String(),
		"len":          len(b),
		"state_nil":    state == nil,
		"socket_v4":    u.isV4,
		"remote_is_v4": addr.Addr().Is4(),
		"remote_is_v6": addr.Addr().Is6(),
	}).Debug("io_uring directWrite invoked")
	if state == nil {
		written, err := u.sendMsgSync(addr, b, nil, 0)
		if err != nil {
			return err
		}
		if written != len(b) {
			return fmt.Errorf("sendmsg short write: wrote %d expected %d", written, len(b))
		}
		return nil
	}
	n, err := u.sendMsgIOUring(state, addr, b, nil, 0)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("io_uring short write: wrote %d expected %d", n, len(b))
	}
	return nil
}

func (u *StdConn) noteIoUringSuccess() {
	if u == nil {
		return
	}
	if u.ioActive.Load() {
		return
	}
	if u.ioActive.CompareAndSwap(false, true) {
		u.l.Debug("io_uring send path active")
	}
}

func (u *StdConn) logIoUringResult(addr netip.AddrPort, expected, written int, err error) {
	if u == nil {
		return
	}
	u.l.WithFields(logrus.Fields{
		"addr":         addr.String(),
		"expected":     expected,
		"written":      written,
		"err":          err,
		"socket_v4":    u.isV4,
		"remote_is_v4": addr.Addr().Is4(),
		"remote_is_v6": addr.Addr().Is6(),
	}).Debug("io_uring send result")
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

	if u.groBatches != nil {
		u.groBatches.Inc(1)
	}
	if u.groSegments != nil {
		u.groSegments.Inc(int64(actualSegments))
	}
	u.groBatchTick.Add(1)
	u.groSegmentsTick.Add(int64(actualSegments))

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
	return u.parseGROSegmentFromControl(control, ctrlLen)
}

func (u *StdConn) parseGROSegmentFromControl(control []byte, ctrlLen int) (int, int) {
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

func (u *StdConn) configureIOUring(enable bool, c *config.C) {
	if enable {
		if u.ioState.Load() != nil {
			return
		}

		// Serialize io_uring initialization globally to avoid kernel resource races
		ioUringInitMu.Lock()
		defer ioUringInitMu.Unlock()

		var configured uint32
		requestedBatch := ioUringDefaultMaxBatch
		if c != nil {
			entries := c.GetInt("listen.io_uring_entries", 0)
			if entries < 0 {
				entries = 0
			}
			configured = uint32(entries)
			holdoff := c.GetDuration("listen.io_uring_batch_holdoff", -1)
			if holdoff < 0 {
				holdoffVal := c.GetInt("listen.io_uring_batch_holdoff", int(ioUringDefaultHoldoff/time.Microsecond))
				holdoff = time.Duration(holdoffVal) * time.Microsecond
			}
			if holdoff < ioUringMinHoldoff {
				holdoff = ioUringMinHoldoff
			}
			if holdoff > ioUringMaxHoldoff {
				holdoff = ioUringMaxHoldoff
			}
			u.ioUringHoldoff.Store(int64(holdoff))
			requestedBatch = clampIoUringBatchSize(c.GetInt("listen.io_uring_max_batch", ioUringDefaultMaxBatch), 0)
		} else {
			u.ioUringHoldoff.Store(int64(ioUringDefaultHoldoff))
			requestedBatch = ioUringDefaultMaxBatch
		}
		if !u.enableGSO {
			if len(u.sendShards) != 1 {
				u.resizeSendShards(1)
			}
		}
		u.ioUringMaxBatch.Store(int64(requestedBatch))
		ring, err := newIoUringState(configured)
		if err != nil {
			u.l.WithError(err).Warn("Failed to enable io_uring; falling back to sendmmsg path")
			return
		}
		u.ioState.Store(ring)
		finalBatch := clampIoUringBatchSize(requestedBatch, ring.sqEntryCount)
		u.ioUringMaxBatch.Store(int64(finalBatch))
		fields := logrus.Fields{
			"entries":   ring.sqEntryCount,
			"max_batch": finalBatch,
		}
		if finalBatch != requestedBatch {
			fields["requested_batch"] = requestedBatch
		}
		u.l.WithFields(fields).Debug("io_uring ioState pointer initialized")
		desired := configured
		if desired == 0 {
			desired = defaultIoUringEntries
		}
		if ring.sqEntryCount < desired {
			fields["requested_entries"] = desired
			u.l.WithFields(fields).Warn("UDP io_uring send path enabled with reduced queue depth (ENOMEM)")
		} else {
			u.l.WithFields(fields).Debug("UDP io_uring send path enabled")
		}

		// Initialize dedicated receive ring with retry logic
		recvPoolSize := 128 // Number of receive operations to keep queued
		recvBufferSize := defaultGROReadBufferSize
		if recvBufferSize < MTU {
			recvBufferSize = MTU
		}

		var recvRing *ioUringRecvState
		maxRetries := 10
		retryDelay := 10 * time.Millisecond

		for attempt := 0; attempt < maxRetries; attempt++ {
			var err error
			recvRing, err = newIoUringRecvState(u.sysFd, configured, recvPoolSize, recvBufferSize)
			if err == nil {
				break
			}

			if attempt < maxRetries-1 {
				u.l.WithFields(logrus.Fields{
					"attempt": attempt + 1,
					"error":   err,
					"delay":   retryDelay,
				}).Warn("Failed to create io_uring receive ring, retrying")
				time.Sleep(retryDelay)
				retryDelay *= 2 // Exponential backoff
			} else {
				u.l.WithError(err).Error("Failed to create io_uring receive ring after retries; will use standard recvmsg")
			}
		}

		if recvRing != nil {
			u.ioRecvState.Store(recvRing)
			u.ioRecvActive.Store(true)
			u.l.WithFields(logrus.Fields{
				"entries":    recvRing.sqEntryCount,
				"poolSize":   recvPoolSize,
				"bufferSize": recvBufferSize,
			}).Info("UDP io_uring receive path enabled")
			// Note: receive queue will be filled on first receivePackets() call
		}

		return
	}

	if c != nil {
		if u.ioState.Load() != nil {
			u.l.Warn("Runtime disabling of io_uring is not supported; keeping existing ring active until shutdown")
		}
		holdoff := c.GetDuration("listen.io_uring_batch_holdoff", -1)
		if holdoff < 0 {
			holdoffVal := c.GetInt("listen.io_uring_batch_holdoff", int(ioUringDefaultHoldoff/time.Microsecond))
			holdoff = time.Duration(holdoffVal) * time.Microsecond
		}
		if holdoff < ioUringMinHoldoff {
			holdoff = ioUringMinHoldoff
		}
		if holdoff > ioUringMaxHoldoff {
			holdoff = ioUringMaxHoldoff
		}
		u.ioUringHoldoff.Store(int64(holdoff))
		requestedBatch := clampIoUringBatchSize(c.GetInt("listen.io_uring_max_batch", ioUringDefaultMaxBatch), 0)
		if ring := u.ioState.Load(); ring != nil {
			requestedBatch = clampIoUringBatchSize(requestedBatch, ring.sqEntryCount)
		}
		u.ioUringMaxBatch.Store(int64(requestedBatch))
		if !u.enableGSO {
			// io_uring uses a single shared ring with a global mutex,
			// so multiple shards cause severe lock contention.
			// Force 1 shard for optimal io_uring batching performance.
			if ring := u.ioState.Load(); ring != nil {
				if len(u.sendShards) != 1 {
					u.resizeSendShards(1)
				}
			} else {
				// No io_uring, allow config override
				shards := c.GetInt("listen.send_shards", 0)
				if shards <= 0 {
					shards = 1
				}
				if len(u.sendShards) != shards {
					u.resizeSendShards(shards)
				}
			}
		}
	}
}

func (u *StdConn) disableIOUring(reason error) {
	if ring := u.ioState.Swap(nil); ring != nil {
		if err := ring.Close(); err != nil {
			u.l.WithError(err).Warn("Failed to close io_uring state during disable")
		}
		if reason != nil {
			u.l.WithError(reason).Warn("Disabling io_uring send/receive path; falling back to sendmmsg/recvmmsg")
		} else {
			u.l.Warn("Disabling io_uring send/receive path; falling back to sendmmsg/recvmmsg")
		}
	}
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
	desiredShards := 0
	if c != nil {
		desiredShards = c.GetInt("listen.send_shards", 0)
	}

	// io_uring requires 1 shard due to shared ring mutex contention
	if u.ioState.Load() != nil {
		if desiredShards > 1 {
			u.l.WithField("requested_shards", desiredShards).Warn("listen.send_shards ignored because io_uring is enabled; forcing 1 send shard")
		}
		desiredShards = 1
	} else if !enable {
		if c != nil && desiredShards > 1 {
			u.l.WithField("requested_shards", desiredShards).Warn("listen.send_shards ignored because UDP GSO is disabled; forcing 1 send shard")
		}
		desiredShards = 1
	}

	// Only resize if actually changing shard count
	if len(u.sendShards) != desiredShards {
		u.resizeSendShards(desiredShards)
	}

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

	u.configureIOUring(c.GetBool("listen.use_io_uring", false), c)
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
	if !u.ioClosing.CompareAndSwap(false, true) {
		return nil
	}
	// Attempt to unblock any outstanding sendmsg/sendmmsg calls so the shard
	// workers can drain promptly during shutdown. Ignoring errors here is fine
	// because some platforms/kernels may not support shutdown on UDP sockets.
	if err := unix.Shutdown(u.sysFd, unix.SHUT_RDWR); err != nil && err != unix.ENOTCONN && err != unix.EINVAL && err != unix.EBADF {
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
	if ring := u.ioState.Swap(nil); ring != nil {
		if err := ring.Close(); err != nil && flushErr == nil {
			flushErr = err
		}
	}
	if recvRing := u.ioRecvState.Swap(nil); recvRing != nil {
		u.ioRecvActive.Store(false)
		if err := recvRing.Close(); err != nil && flushErr == nil {
			flushErr = err
		}
	}
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

	var stdConns []*StdConn
	for _, conn := range udpConns {
		if sc, ok := conn.(*StdConn); ok {
			stdConns = append(stdConns, sc)
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

		for _, sc := range stdConns {
			sc.logGSOTick()
		}
	}
}
