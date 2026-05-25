//go:build linux && !android && !e2e_testing && iouring

package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/randomizedcoder/giouring"
	"github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

// cqeWaitTimeout caps how long the recv goroutine blocks on the completion
// queue before checking for shutdown. 10ms keeps shutdown latency low and
// matches gosrt's recv timeout.
var cqeWaitTimeout = syscall.Timespec{Sec: 0, Nsec: 10 * 1000 * 1000}

// IoUringConn is a Conn implementation that drives the UDP socket via two
// io_uring rings (one for recv, one for send). The socket itself is the
// same kernel UDP socket the StdConn path uses — io_uring just replaces the
// recvmmsg(2) / sendmmsg(2) submission/completion plumbing. GSO/GRO/ECN
// behaviour is preserved: send carries UDP_SEGMENT and IP_TOS/IPV6_TCLASS
// cmsgs the same way the sendmmsg path does, recv parses UDP_GRO and ECN
// cmsgs on the kernel-supplied control buffer.
type IoUringConn struct {
	udpConn *net.UDPConn
	rawConn syscall.RawConn
	fd      int
	isV4    bool
	l       *slog.Logger
	batch   int

	gsoSupported     bool
	groSupported     bool
	ecnRecvSupported bool
	maxGSOSegments   int

	recvRing *giouring.Ring

	// recvSlots is sized at construction from IoUringOptions.RecvSlots.
	// The recv ring is single-writer (only ListenOut submits) so it
	// needs no synchronization beyond the goroutine boundary.
	recvSlots []ioRecvSlot

	// sendRings is the sharded send path. Each entry holds its own
	// giouring.Ring plus per-ring slot pool, sendFree channel, and mutex.
	// Concurrent senders distribute across rings via an atomic counter
	// (sendRingNext) with a TryLock scan in acquireSendRing — so the
	// per-ring mutex is only contended by the fraction of senders that
	// landed on the same ring at the same instant.
	sendRings    []sendRingState
	sendRingNext atomic.Uint32

	closeCh   chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool

	// listenWg tracks the ListenOut goroutine. Close.Wait blocks on it
	// (with a bounded timeout) so we don't tear down the recv ring while
	// a CQE pump is still touching it.
	listenWg sync.WaitGroup
}

// sendRingState is one shard of the multi-ring send path. Each shard
// owns a giouring.Ring, its own slot pool, a sendFree channel, and the
// mutex that serializes producers on this particular ring. See
// IoUringConn.sendRings and acquireSendRing for how shards are picked.
type sendRingState struct {
	ring     *giouring.Ring
	slots    []ioSendSlot
	sendFree chan int32

	// mu serializes GetSQE / Submit / WaitCQE on this ring. giouring's
	// helpers manipulate SQ and CQ head/tail pointers without atomics,
	// so the ring itself is not safe for concurrent producers. The mutex
	// also keeps the CQE drain unambiguous: with mu held no one else can
	// post, so every completion we drain belongs to this caller.
	mu sync.Mutex
}

// ioRecvSlot is one pre-allocated recv ring entry. Each slot owns its
// Msghdr/iovec/payload/cmsg/name scratch so the SQE can point at stable
// addresses for the lifetime of the connection. payload is a pooled
// 65535-byte buffer big enough to hold a maximally coalesced UDP_GRO
// superpacket.
type ioRecvSlot struct {
	msg     syscall.Msghdr
	iov     syscall.Iovec
	name    [unix.SizeofSockaddrInet6]byte
	cmsg    [ioUringCmsgScratchBytes]byte
	payload *ioRxBuffer
}

// ioSendSlot is one pre-allocated send ring entry. The payload buffer is a
// pooled rx-sized buffer; the caller's bytes are copied into it before
// submit so the caller can free their buffer immediately. cmsg holds the
// UDP_SEGMENT and IP_TOS/IPV6_TCLASS scratch with the same fixed-offset
// layout StdConn uses (writeCmsgSegSpace then writeCmsgEcnSpace).
type ioSendSlot struct {
	msg     syscall.Msghdr
	iov     syscall.Iovec
	name    [unix.SizeofSockaddrInet6]byte
	cmsg    [ioUringCmsgScratchBytes]byte
	payload *ioRxBuffer
}

// ioUringCmsgScratchBytes upper-bounds the per-slot cmsg buffer. Real usage
// on linux/amd64 is two cmsg headers totalling 48 bytes (CmsgSpace(2) for
// UDP_SEGMENT + CmsgSpace(4) for IP_TOS/IPV6_TCLASS on send; CmsgSpace(4)
// for UDP_GRO + CmsgSpace(4) for ECN on recv). 64 leaves headroom and lets
// us declare a fixed-size array field (Go requires array lengths to be
// constants — unix.CmsgSpace is a function call, not a const). The runtime
// check in NewIoUringListener verifies the real layouts fit.
const ioUringCmsgScratchBytes = 64

// NewIoUringListener opens a UDP socket and wires it to two io_uring rings.
// Build-tag-gated to `iouring`; main.go selects between this and the
// recvmmsg-based NewListener based on the runtime config flag. opts is
// normalised via validateIoUringOptions so non-power-of-two ring sizes,
// oversized slot counts, and zero/negative values get sensible defaults
// with a log warning rather than a hard error.
func NewIoUringListener(l *slog.Logger, ip netip.Addr, port int, multi bool, batch int, opts IoUringOptions) (Conn, error) {
	opts = validateIoUringOptions(opts, l)
	listen := netip.AddrPortFrom(ip, uint16(port))
	lc := net.ListenConfig{}
	if multi {
		lc.Control = setReusePort
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", listen.String())
	if err != nil {
		return nil, fmt.Errorf("unable to open socket: %w", err)
	}
	udpConn := pc.(*net.UDPConn)
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}

	// Sanity-check that ioUringCmsgScratchBytes covers the actual cmsg
	// layouts we'll write. If a future platform expands SizeofCmsghdr or
	// alignment, fail loudly at startup rather than silently truncating.
	if needSend := unix.CmsgSpace(2) + unix.CmsgSpace(4); needSend > ioUringCmsgScratchBytes {
		_ = udpConn.Close()
		return nil, fmt.Errorf("io_uring: send cmsg layout (%d) exceeds scratch (%d)", needSend, ioUringCmsgScratchBytes)
	}
	if needRecv := unix.CmsgSpace(udpGROCmsgPayload) + unix.CmsgSpace(4); needRecv > ioUringCmsgScratchBytes {
		_ = udpConn.Close()
		return nil, fmt.Errorf("io_uring: recv cmsg layout (%d) exceeds scratch (%d)", needRecv, ioUringCmsgScratchBytes)
	}

	c := &IoUringConn{
		udpConn:        udpConn,
		rawConn:        rawConn,
		l:              l,
		batch:          batch,
		maxGSOSegments: 1,
		closeCh:        make(chan struct{}),
	}

	// Cache the fd; the SQE prepare ops take an int fd directly and we'd
	// otherwise pay a rawConn.Control round-trip per submit.
	if err := rawConn.Control(func(fd uintptr) {
		c.fd = int(fd)
	}); err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("io_uring: failed to extract fd: %w", err)
	}

	af, err := c.getSockOptInt(unix.SO_DOMAIN)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	c.isV4 = af == unix.AF_INET

	c.probeGSO()
	if batch > 1 {
		c.probeGRO()
	}
	c.probeECNRecv()

	c.recvRing = giouring.NewRing()
	if err := c.recvRing.QueueInit(uint32(opts.RecvRingSize), 0); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("io_uring: recv ring QueueInit (size=%d): %w", opts.RecvRingSize, err)
	}

	c.recvSlots = make([]ioRecvSlot, opts.RecvSlots)
	for i := range c.recvSlots {
		c.recvSlots[i].payload = getRxBuffer()
	}

	c.sendRings = make([]sendRingState, opts.SendRings)
	for i := range c.sendRings {
		rs := &c.sendRings[i]
		rs.ring = giouring.NewRing()
		if err := rs.ring.QueueInit(uint32(opts.SendRingSize), 0); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("io_uring: send ring %d QueueInit (size=%d): %w", i, opts.SendRingSize, err)
		}
		rs.slots = make([]ioSendSlot, opts.SendSlots)
		rs.sendFree = make(chan int32, opts.SendSlots)
		for j := range rs.slots {
			rs.slots[j].payload = getRxBuffer()
			rs.sendFree <- int32(j)
		}
	}

	l.Info("udp: io_uring enabled",
		"recvRingSize", opts.RecvRingSize,
		"sendRingSize", opts.SendRingSize,
		"recvSlots", opts.RecvSlots,
		"sendSlots", opts.SendSlots,
		"sendRings", opts.SendRings,
		"gsoSupported", c.gsoSupported,
		"groSupported", c.groSupported,
		"ecnRecvSupported", c.ecnRecvSupported,
	)
	return c, nil
}

// acquireSendRing picks a send ring shard, locks its mutex, and returns
// the locked state. Caller must Unlock when done (typically via defer).
//
// Selection algorithm: an atomic counter (sendRingNext) gives a starting
// shard for round-robin, then we TryLock each shard in turn. If a shard
// is free we take it immediately — no head-of-line blocking on a hot
// ring. If every shard is currently held (rare at sane SendRings counts
// since the design assumes #rings >= #concurrent writers), we yield to
// the scheduler with runtime.Gosched and rescan. The yielded goroutine
// gives up its M and lets the actively-sending goroutines progress
// toward releasing a ring; we come back, scan, and one is free.
//
// This costs roughly 1 atomic add + 1 successful TryLock in the typical
// case, identical to pure round-robin. Under sustained contention the
// Gosched between scans keeps the loop cooperative — never a busy spin.
// TryLock is one of the few patterns sync.Mutex docs explicitly bless
// ("load-balance across shards").
func (c *IoUringConn) acquireSendRing() *sendRingState {
	n := uint32(len(c.sendRings))
	start := c.sendRingNext.Add(1) % n
	for {
		for i := range n {
			rs := &c.sendRings[(start+i)%n]
			if rs.mu.TryLock() {
				return rs
			}
		}
		// All shards held right now. Yield the M back to the scheduler
		// so the goroutines currently inside the critical section can
		// finish; one of them will release a ring before we resume.
		runtime.Gosched()
	}
}

func (c *IoUringConn) SupportsMultipleReaders() bool { return true }
func (c *IoUringConn) Rebind() error                 { return nil }

func (c *IoUringConn) LocalAddr() (netip.AddrPort, error) {
	a := c.udpConn.LocalAddr()
	switch v := a.(type) {
	case *net.UDPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("LocalAddr returned invalid IP address: %s", v.IP)
		}
		return netip.AddrPortFrom(addr, uint16(v.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

// probeGSO mirrors StdConn.prepareGSO. Inlined rather than embedded so the
// io_uring Conn does not pull in the full StdConn type with its sendmmsg
// scratch (which io_uring does not use).
func (c *IoUringConn) probeGSO() {
	c.maxGSOSegments = 63
	var probeErr error
	if err := c.rawConn.Control(func(fd uintptr) {
		probeErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, 0)
	}); err != nil {
		recordCapability("udp.gso.enabled", false)
		return
	}
	if probeErr != nil {
		recordCapability("udp.gso.enabled", false)
		return
	}
	var un unix.Utsname
	if err := unix.Uname(&un); err == nil {
		major, minor := parseRelease(string(un.Release[:]))
		if major > 5 || (major == 5 && minor >= 5) {
			c.maxGSOSegments = 127
		}
	}
	c.gsoSupported = true
	recordCapability("udp.gso.enabled", true)
}

func (c *IoUringConn) probeGRO() {
	var probeErr error
	if err := c.rawConn.Control(func(fd uintptr) {
		probeErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); err != nil {
		recordCapability("udp.gro.enabled", false)
		return
	}
	if probeErr != nil {
		recordCapability("udp.gro.enabled", false)
		return
	}
	c.groSupported = true
	recordCapability("udp.gro.enabled", true)
}

func (c *IoUringConn) probeECNRecv() {
	var v4err, v6err error
	if err := c.rawConn.Control(func(fd uintptr) {
		v4err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		if !c.isV4 {
			v6err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
		}
	}); err != nil {
		recordCapability("udp.ecn_rx.enabled", false)
		return
	}
	if c.isV4 {
		if v4err != nil {
			recordCapability("udp.ecn_rx.enabled", false)
			return
		}
		c.ecnRecvSupported = true
		recordCapability("udp.ecn_rx.enabled", true)
		return
	}
	if v6err != nil {
		recordCapability("udp.ecn_rx.enabled", false)
		return
	}
	c.ecnRecvSupported = true
	recordCapability("udp.ecn_rx.enabled", true)
	_ = errors.Join(v4err, v6err)
}

// armRecvSlot wires recvSlots[i].msg to point at its own iov/name/cmsg/
// payload scratch and submits an OpRecvmsg SQE bound to that slot. The
// SQE's user_data is the slot index, so the completion handler can route
// each CQE back to its slot without auxiliary tracking.
func (c *IoUringConn) armRecvSlot(i int) error {
	slot := &c.recvSlots[i]
	slot.iov.Base = &slot.payload[0]
	slot.iov.SetLen(int(ioUringRxBufferSize))

	slot.msg.Name = &slot.name[0]
	slot.msg.Namelen = uint32(len(slot.name))
	slot.msg.Iov = &slot.iov
	slot.msg.Iovlen = 1
	if c.groSupported || c.ecnRecvSupported {
		slot.msg.Control = &slot.cmsg[0]
		slot.msg.SetControllen(len(slot.cmsg))
	} else {
		slot.msg.Control = nil
		slot.msg.SetControllen(0)
	}
	slot.msg.Flags = 0

	sqe := c.recvRing.GetSQE()
	if sqe == nil {
		return fmt.Errorf("io_uring: recv ring full while arming slot %d", i)
	}
	sqe.PrepareRecvMsg(c.fd, &slot.msg, 0)
	sqe.SetData64(uint64(i))
	return nil
}

// ListenOut arms every recv slot, submits the initial batch, then drains
// the completion queue in a loop. On each CQE it parses cmsg + sockaddr,
// fans out per-segment via r, and re-arms the slot. flush() is called
// after each completion-drain pass so callers can drain per-batch
// accumulators (e.g. the TUN write coalescer).
func (c *IoUringConn) ListenOut(r EncReader, flush func()) error {
	if flush == nil {
		return errors.New("io_uring: ListenOut requires non-nil flush")
	}
	c.listenWg.Add(1)
	defer c.listenWg.Done()

	for i := range c.recvSlots {
		if err := c.armRecvSlot(i); err != nil {
			return err
		}
	}
	if _, err := c.recvRing.Submit(); err != nil {
		return fmt.Errorf("io_uring: initial recv submit: %w", err)
	}

	cqes := make([]*giouring.CompletionQueueEvent, len(c.recvSlots))
	for {
		if c.closed.Load() {
			return nil
		}

		// Block until at least one CQE is available or the timeout fires.
		// The returned CQE is the first; PeekBatchCQE harvests the rest in
		// the same pass.
		_, err := c.recvRing.WaitCQETimeout(&cqeWaitTimeout)
		if err != nil {
			if errors.Is(err, syscall.ETIME) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("io_uring: WaitCQETimeout: %w", err)
		}

		n := c.recvRing.PeekBatchCQE(cqes)
		if n == 0 {
			continue
		}

		for k := range n {
			if err := c.handleRecvCqe(cqes[k], r); err != nil {
				return err
			}
		}

		// Flush re-armed SQEs and any per-batch accumulator the caller owns.
		if _, err := c.recvRing.Submit(); err != nil {
			return fmt.Errorf("io_uring: recv resubmit: %w", err)
		}
		flush()
	}
}

// handleRecvCqe processes one recv completion: routes the slot, parses the
// kernel-supplied sockaddr/cmsg, fans the payload out per UDP_GRO segment
// size, and re-arms the slot. Extracted from ListenOut so the per-CQE work
// stays at moderate cyclomatic complexity. Returns a fatal error if the
// slot cannot be re-armed (ring exhaustion); transient per-packet errors
// are logged and the slot is still re-armed so the ring stays primed.
func (c *IoUringConn) handleRecvCqe(cqe *giouring.CompletionQueueEvent, r EncReader) error {
	slotIdx := int(cqe.UserData)
	res := cqe.Res
	c.recvRing.CQESeen(cqe)

	if slotIdx < 0 || slotIdx >= len(c.recvSlots) {
		c.l.Warn("io_uring: stray CQE", "user_data", cqe.UserData)
		return nil
	}
	slot := &c.recvSlots[slotIdx]

	if res < 0 {
		errno := syscall.Errno(-res)
		if errno != syscall.EAGAIN && errno != syscall.EINTR {
			c.l.Warn("io_uring: recvmsg CQE error", "errno", errno, "slot", slotIdx)
		}
		return c.armRecvSlot(slotIdx)
	}

	from, perr := parseSockaddrFromRaw(slot.name[:], slot.msg.Namelen, c.isV4)
	if perr != nil {
		c.l.Warn("io_uring: sockaddr parse failed", "error", perr, "slot", slotIdx)
		return c.armRecvSlot(slotIdx)
	}

	payload := slot.payload[:res]
	segSize := 0
	outerECN := byte(0)
	if c.groSupported || c.ecnRecvSupported {
		segSize, outerECN = parseRecvCmsgRaw(slot.msg.Control, int(slot.msg.Controllen), c.groSupported, c.ecnRecvSupported, c.isV4)
	}

	if segSize <= 0 || segSize >= len(payload) {
		r(from, payload, RxMeta{OuterECN: outerECN})
	} else {
		for off := 0; off < len(payload); off += segSize {
			end := off + segSize
			if end > len(payload) {
				end = len(payload)
			}
			r(from, payload[off:end], RxMeta{OuterECN: outerECN})
		}
	}

	return c.armRecvSlot(slotIdx)
}

// WriteTo sends a single packet via one of the send-ring shards. The
// shard is chosen by acquireSendRing (atomic round-robin + TryLock scan);
// the slot is then taken from that shard's sendFree channel. Synchronous:
// submit one SQE, wait for its CQE before returning. Concurrent senders
// landing on different shards see no contention.
func (c *IoUringConn) WriteTo(b []byte, addr netip.AddrPort) error {
	if c.closed.Load() {
		return net.ErrClosed
	}

	rs := c.acquireSendRing()
	defer rs.mu.Unlock()

	// Re-check after acquiring the ring mutex: Close may have run while
	// we were scanning for a free ring, in which case rs.ring is being
	// (or has been) torn down under our feet.
	if c.closed.Load() {
		return net.ErrClosed
	}

	slotIdx := <-rs.sendFree
	defer func() { rs.sendFree <- slotIdx }()

	slot := &rs.slots[slotIdx]
	copy(slot.payload[:], b)
	slot.iov.Base = &slot.payload[0]
	slot.iov.SetLen(len(b))

	nlen, err := writeSockaddr(slot.name[:], addr, c.isV4)
	if err != nil {
		return err
	}
	slot.msg.Name = &slot.name[0]
	slot.msg.Namelen = uint32(nlen)
	slot.msg.Iov = &slot.iov
	slot.msg.Iovlen = 1
	slot.msg.Control = nil
	slot.msg.SetControllen(0)
	slot.msg.Flags = 0

	sqe := rs.ring.GetSQE()
	if sqe == nil {
		return errors.New("io_uring: send ring full")
	}
	sqe.PrepareSendMsg(c.fd, &slot.msg, 0)
	sqe.SetData64(uint64(slotIdx))
	if _, err := rs.ring.Submit(); err != nil {
		return fmt.Errorf("io_uring: send submit: %w", err)
	}

	cqe, err := rs.ring.WaitCQE()
	if err != nil {
		return fmt.Errorf("io_uring: send wait: %w", err)
	}
	res := cqe.Res
	rs.ring.CQESeen(cqe)
	if res < 0 {
		return &net.OpError{Op: "sendmsg", Err: syscall.Errno(-res)}
	}
	return nil
}

// WriteBatch sends a batch of packets. Same coalescing strategy as
// StdConn.WriteBatch: same-dst, same-segsize, same-ecn consecutive packets
// fold into one sendmsg SQE carrying a UDP_SEGMENT cmsg. Synchronous batch:
// submit all SQEs, then drain N completions before returning.
//
// The send-ring mutex is acquired per chunk (one Submit + drain inside
// writeBatchChunk), so concurrent WriteTo / WriteBatch can interleave
// between chunks but not within them. The CQE drain therefore only ever
// sees this chunk's own completions, keeping slot-to-completion routing
// unambiguous.
func (c *IoUringConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort, ecns []byte) error {
	if len(bufs) != len(addrs) {
		return fmt.Errorf("WriteBatch: len(bufs)=%d != len(addrs)=%d", len(bufs), len(addrs))
	}
	if ecns != nil && len(ecns) != len(bufs) {
		return fmt.Errorf("WriteBatch: len(ecns)=%d != len(bufs)=%d", len(ecns), len(bufs))
	}
	if c.closed.Load() {
		return net.ErrClosed
	}

	i := 0
	for i < len(bufs) {
		if err := c.writeBatchChunk(bufs, addrs, ecns, &i); err != nil {
			return err
		}
	}
	return nil
}

// writeBatchChunk runs one mutex-guarded submit-and-drain pass over the
// suffix bufs[*i:]. It advances *i by the number of input packets actually
// dispatched. Extracted from WriteBatch so the mutex acquire/release is a
// single straight-line scope and the outer batch loop stays small.
//
// One shard is picked at the start and used for the whole chunk; the CQE
// drain therefore only sees this chunk's own completions. Concurrent
// WriteBatch calls land on different shards (or scan past held ones via
// TryLock), so the chunks themselves run in parallel.
func (c *IoUringConn) writeBatchChunk(bufs [][]byte, addrs []netip.AddrPort, ecns []byte, i *int) error {
	rs := c.acquireSendRing()
	defer rs.mu.Unlock()

	// Re-check after acquiring the ring mutex: Close may have torn down
	// rs.ring while we were waiting. See WriteTo for the analogous check.
	if c.closed.Load() {
		return net.ErrClosed
	}

	// Plan a batch of coalesced entries, draining sendFree slots as we
	// go. We cap the per-chunk submission to len(rs.slots) so the
	// synchronous completion drain at end-of-chunk is bounded.
	var entrySlots []int32
	for len(entrySlots) < len(rs.slots) && *i < len(bufs) {
		runLen, segSize := c.planRun(bufs, addrs, ecns, *i, c.maxGSOSegments)
		if runLen == 0 {
			break
		}

		var slotIdx int32
		select {
		case slotIdx = <-rs.sendFree:
		default:
			// Ring full; flush whatever we have first.
			if len(entrySlots) == 0 {
				// Pathological: zero in-flight but no free slot. Block.
				slotIdx = <-rs.sendFree
			} else {
				break
			}
		}
		slot := &rs.slots[slotIdx]

		// Concatenate the run into the slot's payload buffer. Total
		// bytes is bounded by maxGSOBytes (see planRun).
		off := 0
		for k := range runLen {
			b := bufs[*i+k]
			copy(slot.payload[off:], b)
			off += len(b)
		}
		slot.iov.Base = &slot.payload[0]
		slot.iov.SetLen(off)

		nlen, err := writeSockaddr(slot.name[:], addrs[*i], c.isV4)
		if err != nil {
			rs.sendFree <- slotIdx
			return err
		}
		slot.msg.Name = &slot.name[0]
		slot.msg.Namelen = uint32(nlen)
		slot.msg.Iov = &slot.iov
		slot.msg.Iovlen = 1

		var ecn byte
		if ecns != nil {
			ecn = ecns[*i]
		}
		c.encodeSendCmsg(slot, runLen, segSize, ecn)

		sqe := rs.ring.GetSQE()
		if sqe == nil {
			rs.sendFree <- slotIdx
			break
		}
		sqe.PrepareSendMsg(c.fd, &slot.msg, 0)
		sqe.SetData64(uint64(slotIdx))
		entrySlots = append(entrySlots, slotIdx)

		*i += runLen
	}

	if len(entrySlots) == 0 {
		return errors.New("io_uring: WriteBatch no progress")
	}

	if _, err := rs.ring.Submit(); err != nil {
		// Release any slots we didn't get to submit.
		for _, idx := range entrySlots {
			rs.sendFree <- idx
		}
		return fmt.Errorf("io_uring: send submit: %w", err)
	}

	// Drain N completions synchronously. The slot index is in user_data.
	var firstErr error
	for range entrySlots {
		cqe, err := rs.ring.WaitCQE()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		res := cqe.Res
		slotIdx := int32(cqe.UserData)
		rs.ring.CQESeen(cqe)
		rs.sendFree <- slotIdx
		if res < 0 && firstErr == nil {
			firstErr = &net.OpError{Op: "sendmsg", Err: syscall.Errno(-res)}
		}
	}
	return firstErr
}

// planRun is the io_uring equivalent of StdConn.planRun: it groups
// consecutive packets starting at start that can ride one UDP_SEGMENT-
// carrying sendmsg. Boundaries: changed destination, changed ECN, oversized
// segment, total payload exceeding maxGSOBytes, or running past iovBudget.
// A return of (1, segSize) means a plain datagram with no UDP_SEGMENT cmsg.
//
// Intentionally mirrors StdConn.planRun byte-for-byte — both methods own
// per-receiver state (gsoSupported, maxGSOSegments) so a shared free
// function would require parameter plumbing that obscures the receiver
// invariants. dupl finding suppressed below.
//
//nolint:dupl // see comment above; method on receiver, not a free fn.
func (c *IoUringConn) planRun(bufs [][]byte, addrs []netip.AddrPort, ecns []byte, start, iovBudget int) (int, int) {
	if start >= len(bufs) || iovBudget < 1 {
		return 0, 0
	}
	segSize := len(bufs[start])
	if !c.gsoSupported || segSize == 0 || segSize > maxGSOBytes {
		return 1, segSize
	}
	dst := addrs[start]
	var ecn byte
	if ecns != nil {
		ecn = ecns[start]
	}
	maxLen := c.maxGSOSegments
	if iovBudget < maxLen {
		maxLen = iovBudget
	}
	runLen := 1
	total := segSize
	for runLen < maxLen && start+runLen < len(bufs) {
		nextLen := len(bufs[start+runLen])
		if nextLen == 0 || nextLen > segSize {
			break
		}
		if addrs[start+runLen] != dst {
			break
		}
		if ecns != nil && ecns[start+runLen] != ecn {
			break
		}
		if total+nextLen > maxGSOBytes {
			break
		}
		total += nextLen
		runLen++
		if nextLen < segSize {
			break
		}
	}
	return runLen, segSize
}

// encodeSendCmsg writes the UDP_SEGMENT and IP_TOS/IPV6_TCLASS cmsg headers
// into slot.cmsg at the same fixed offsets StdConn.writeEntryCmsg uses, and
// points slot.msg.Control / Controllen at the active subset. runLen >= 2
// turns on the segment cmsg; ecn != 0 turns on the ECN cmsg.
func (c *IoUringConn) encodeSendCmsg(slot *ioSendSlot, runLen, segSize int, ecn byte) {
	useSeg := runLen >= 2 && c.gsoSupported
	useEcn := ecn != 0

	segSpace := unix.CmsgSpace(2)
	ecnSpace := unix.CmsgSpace(4)

	if useSeg {
		ch := (*unix.Cmsghdr)(unsafe.Pointer(&slot.cmsg[0]))
		ch.Level = unix.SOL_UDP
		ch.Type = unix.UDP_SEGMENT
		ch.SetLen(unix.CmsgLen(2))
		dataOff := unix.CmsgLen(0)
		binary.NativeEndian.PutUint16(slot.cmsg[dataOff:dataOff+2], uint16(segSize))
	}
	if useEcn {
		base := 0
		if useSeg {
			base = segSpace
		}
		ch := (*unix.Cmsghdr)(unsafe.Pointer(&slot.cmsg[base]))
		if c.isV4 {
			ch.Level = unix.IPPROTO_IP
			ch.Type = unix.IP_TOS
		} else {
			ch.Level = unix.IPPROTO_IPV6
			ch.Type = unix.IPV6_TCLASS
		}
		ch.SetLen(unix.CmsgLen(4))
		dataOff := base + unix.CmsgLen(0)
		binary.NativeEndian.PutUint32(slot.cmsg[dataOff:dataOff+4], uint32(ecn))
	}

	switch {
	case useSeg && useEcn:
		slot.msg.Control = &slot.cmsg[0]
		slot.msg.SetControllen(segSpace + ecnSpace)
	case useSeg:
		slot.msg.Control = &slot.cmsg[0]
		slot.msg.SetControllen(segSpace)
	case useEcn:
		slot.msg.Control = &slot.cmsg[0]
		slot.msg.SetControllen(ecnSpace)
	default:
		slot.msg.Control = nil
		slot.msg.SetControllen(0)
	}
}

// parseSockaddrFromRaw decodes the kernel-supplied sockaddr bytes (v4 or v6)
// into a netip.AddrPort. Mirrors StdConn's getFrom but reads directly from
// the slot's name buffer rather than a per-message names slice.
func parseSockaddrFromRaw(name []byte, namelen uint32, isV4 bool) (netip.AddrPort, error) {
	if isV4 {
		if namelen < unix.SizeofSockaddrInet4 {
			return netip.AddrPort{}, fmt.Errorf("short v4 sockaddr (%d bytes)", namelen)
		}
		ip, ok := netip.AddrFromSlice(name[4:8])
		if !ok {
			return netip.AddrPort{}, errors.New("invalid v4 ip in sockaddr")
		}
		port := binary.BigEndian.Uint16(name[2:4])
		return netip.AddrPortFrom(ip.Unmap(), port), nil
	}
	if namelen < unix.SizeofSockaddrInet6 {
		return netip.AddrPort{}, fmt.Errorf("short v6 sockaddr (%d bytes)", namelen)
	}
	ip, ok := netip.AddrFromSlice(name[8:24])
	if !ok {
		return netip.AddrPort{}, errors.New("invalid v6 ip in sockaddr")
	}
	port := binary.BigEndian.Uint16(name[2:4])
	return netip.AddrPortFrom(ip.Unmap(), port), nil
}

// parseRecvCmsgRaw walks ancillary data once and extracts the UDP_GRO
// gso_size and outer ECN codepoint. Equivalent to StdConn.parseRecvCmsg but
// takes the control buffer pointer directly rather than a *msghdr — io_uring
// uses syscall.Msghdr whose Control is *byte and we already have it on hand.
func parseRecvCmsgRaw(control *byte, controllen int, wantGRO, wantECN bool, isV4 bool) (gso int, ecn byte) {
	if controllen < unix.SizeofCmsghdr || control == nil {
		return 0, 0
	}
	ctrl := unsafe.Slice(control, controllen)
	off := 0
	for off+unix.SizeofCmsghdr <= len(ctrl) {
		ch := (*unix.Cmsghdr)(unsafe.Pointer(&ctrl[off]))
		clen := int(ch.Len)
		if clen < unix.SizeofCmsghdr || off+clen > len(ctrl) {
			break
		}
		dataOff := off + unix.CmsgLen(0)
		dataEnd := off + clen
		switch {
		case wantGRO && ch.Level == unix.SOL_UDP && ch.Type == unix.UDP_GRO:
			if dataEnd-dataOff >= 4 {
				gso = int(int32(binary.NativeEndian.Uint32(ctrl[dataOff : dataOff+4])))
			}
		case wantECN && isV4 && ch.Level == unix.IPPROTO_IP && ch.Type == unix.IP_TOS:
			if dataEnd > dataOff {
				ecn = ctrl[dataOff] & 0x03
			}
		case wantECN && !isV4 && ch.Level == unix.IPPROTO_IPV6 && ch.Type == unix.IPV6_TCLASS:
			if dataEnd-dataOff >= 4 {
				tclass := binary.NativeEndian.Uint32(ctrl[dataOff : dataOff+4])
				ecn = byte(tclass & 0x03)
			}
		}
		// CmsgSpace aligns; advance by aligned length, not raw clen.
		step := cmsgAlignLen(clen)
		if step <= 0 {
			break
		}
		off += step
	}
	return gso, ecn
}

// cmsgAlignLen rounds clen up to the alignment unix.CmsgSpace would. The
// kernel/userland always aligns cmsg headers to sizeof(long) boundaries, so
// the next header's offset is the aligned length of the prior header.
func cmsgAlignLen(clen int) int {
	const alignTo = int(unsafe.Sizeof(uintptr(0)))
	return (clen + alignTo - 1) & ^(alignTo - 1)
}

func (c *IoUringConn) getSockOptInt(opt int) (int, error) {
	if c.rawConn == nil {
		return 0, errors.New("no UDP connection")
	}
	var out int
	var opErr error
	err := c.rawConn.Control(func(fd uintptr) {
		out, opErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	})
	if err != nil {
		return 0, err
	}
	return out, opErr
}

func (c *IoUringConn) setSockOptInt(opt int, n int) error {
	if c.rawConn == nil {
		return errors.New("no UDP connection")
	}
	var opErr error
	err := c.rawConn.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, opt, n)
	})
	if err != nil {
		return err
	}
	return opErr
}

func (c *IoUringConn) ReloadConfig(cfg *config.C) {
	b := cfg.GetInt("listen.read_buffer", 0)
	if b > 0 {
		if err := c.setSockOptInt(unix.SO_RCVBUFFORCE, b); err != nil {
			c.l.Error("Failed to set listen.read_buffer", "error", err)
		}
	}
	b = cfg.GetInt("listen.write_buffer", 0)
	if b > 0 {
		if err := c.setSockOptInt(unix.SO_SNDBUFFORCE, b); err != nil {
			c.l.Error("Failed to set listen.write_buffer", "error", err)
		}
	}
	b = cfg.GetInt("listen.so_mark", 0)
	if b > 0 {
		if err := c.setSockOptInt(unix.SO_MARK, b); err != nil {
			c.l.Error("Failed to set listen.so_mark", "error", err)
		}
	}
}

// Close tears down the rings and the underlying socket. Safe to call
// while senders are mid-WriteTo: the close flag is set first, then we
// drain each send ring under its mutex so no in-flight Submit/WaitCQE
// can race with QueueExit. ListenOut similarly observes the close flag
// at its next WaitCQETimeout cycle (~10ms) and exits; we wait on
// listenWg (bounded) before tearing down the recv ring.
func (c *IoUringConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeCh)
	})

	// Wait for ListenOut to observe c.closed and return. Bounded by a
	// generous timeout in case the goroutine is wedged in something we
	// don't control; the worst case is a recv-ring teardown racing the
	// listener, which we've at least narrowed to a vanishingly small
	// window.
	listenDone := make(chan struct{})
	go func() { c.listenWg.Wait(); close(listenDone) }()
	select {
	case <-listenDone:
	case <-time.After(500 * time.Millisecond):
		// Fall through; recv-ring teardown is best-effort if the
		// listener never finished.
	}

	if c.recvRing != nil {
		c.recvRing.QueueExit()
		c.recvRing = nil
	}

	// Drain each send ring under its mutex so any concurrent WriteTo /
	// writeBatchChunk that already acquired the ring runs to completion
	// before we unmap its SQ/CQ. New entrants will see c.closed after
	// they grab the mutex (the re-check in WriteTo / writeBatchChunk)
	// and bail with net.ErrClosed.
	for i := range c.sendRings {
		rs := &c.sendRings[i]
		rs.mu.Lock()
		if rs.ring != nil {
			rs.ring.QueueExit()
			rs.ring = nil
		}
		for j := range rs.slots {
			putRxBuffer(rs.slots[j].payload)
			rs.slots[j].payload = nil
		}
		rs.mu.Unlock()
	}
	for i := range c.recvSlots {
		putRxBuffer(c.recvSlots[i].payload)
		c.recvSlots[i].payload = nil
	}
	if c.udpConn != nil {
		err := c.udpConn.Close()
		c.udpConn = nil
		return err
	}
	return nil
}
