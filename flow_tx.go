package nebula

import (
	"errors"
	"net/netip"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/tio"
)

var errFlowSegmentOverrun = errors.New("superpacket has more segments than counters reserved for it")

// txItem is one firewall-approved inside packet (or superpacket) with everything needed to encrypt it. A nonzero
// counter is the first of the segs counters reserved for it on ci, relayCounter the same on the relay tunnel when
// relayHI is set. Zero counters are allocated per segment while encrypting, as inline sends do.
type txItem struct {
	pkt          tio.Packet
	hostinfo     *HostInfo
	ci           *ConnectionState
	remote       netip.AddrPort
	segs         uint64
	counter      uint64
	relayHI      *HostInfo
	relay        *Relay
	relayCounter uint64
}

// prepareTxItem does the per-packet work sendInsideMessage does before it encrypts, and resolves where the packet goes.
func (f *Interface) prepareTxItem(it *txItem, hostinfo *HostInfo, pkt tio.Packet) bool {
	ci := hostinfo.ConnectionState
	if ci.eKey == nil {
		return false
	}

	f.recordOutbound(hostinfo)
	it.pkt, it.hostinfo, it.ci = pkt, hostinfo, ci
	it.remote = hostinfo.GetRemote()
	if it.remote.IsValid() {
		return true
	}

	it.relayHI, it.relay = f.findRelay(hostinfo)
	if it.relayHI == nil || it.relay == nil {
		return false
	}
	it.remote = it.relayHI.GetRemote()
	return true
}

// encryptTxItem segments and encrypts it into sb, for inline and staged sends alike.
func (f *Interface) encryptTxItem(it *txItem, nb []byte, sb *batch.SendBatch) {
	reserved := it.counter != 0
	c, rc, end := it.counter, it.relayCounter, it.counter+it.segs
	err := tio.SegmentSuperpacket(it.pkt, func(seg []byte) error {
		if reserved && c >= end {
			// More segments than counters reserved for them, never encrypt past the reservation
			return errFlowSegmentOverrun
		}
		if it.relayHI == nil {
			// header + plaintext + AEAD tag (16 bytes for both AES-GCM and ChaCha20-Poly1305)
			if out := f.encryptTxSegment(it, c, seg, nb, sb.Reserve(header.Len+len(seg)+16)); out != nil {
				sb.Commit(out, it.remote)
			}
		} else {
			f.encryptTxSegmentVia(it, c, rc, seg, nb, sb)
		}
		if reserved {
			c++
			rc++
		}
		return nil
	})
	if err != nil {
		it.hostinfo.logger(f.l).Error("Failed to segment superpacket for send", "error", err)
	}
}

// encryptTxSegment encrypts one segment into out with counter c, or with the next counter of the tunnel when c is
// zero. It returns nil when encryption failed, which is already logged.
func (f *Interface) encryptTxSegment(it *txItem, c uint64, seg, nb, out []byte) []byte {
	if c != 0 {
		// Reserved counters are unique, so the encryption needs no lock
		return f.encryptMessage(header.Message, 0, it.hostinfo, it.ci, c, seg, nb, out, it.remote)
	}
	if noiseutil.EncryptLockNeeded {
		it.ci.writeLock.Lock()
	}
	c = it.ci.messageCounter.Add(1)
	out = f.encryptMessage(header.Message, 0, it.hostinfo, it.ci, c, seg, nb, out, it.remote)
	if noiseutil.EncryptLockNeeded {
		it.ci.writeLock.Unlock()
	}
	return out
}

// encryptTxSegmentVia encrypts one segment for the relayed tunnel, then wraps it for the relay with counter rc, both
// allocated on demand when zero like encryptTxSegment does.
func (f *Interface) encryptTxSegmentVia(it *txItem, c, rc uint64, seg, nb []byte, sb *batch.SendBatch) {
	//relay header + header + plaintext + AEAD tag + relay tag
	scratch := sb.Reserve(len(seg) + header.MaxOverhead)
	out := f.encryptTxSegment(it, c, seg, nb, scratch[header.Len:])
	if out == nil {
		return
	}
	toSend, err := f.prepareSendVia(it.relayHI, it.relay, out, nb, scratch, true, rc)
	if err != nil {
		return
	}
	remote := it.remote
	if rc == 0 {
		// Unreserved sends follow the relay's current remote, like sendNoMetrics
		remote = it.relayHI.GetRemote()
	}
	sb.Commit(toSend, remote)
}

// segmentCount reports how many segments tio.SegmentSuperpacket will cut pkt into, without touching its bytes.
func segmentCount(pkt tio.Packet) uint64 {
	if !pkt.GSO.IsSuperpacket() {
		return 1
	}
	n := (len(pkt.Bytes) - int(pkt.GSO.HdrLen) + int(pkt.GSO.Size) - 1) / int(pkt.GSO.Size)
	return uint64(max(n, 1))
}

// txTunnel accumulates one tunnel's counter needs across a batch so the batch reserves them with one atomic add.
type txTunnel struct {
	ci        *ConnectionState
	hostinfo  *HostInfo
	n         uint64
	base      uint64
	exhausted bool
}

// txReserver turns one tun read into txItems with message counters reserved for them. Only the reader goroutine
// collects and reserves counters.
type txReserver struct {
	f       *Interface
	tunnels []txTunnel
}

// collect runs the filter over pkts and appends the sendable ones to items, tallying each tunnel's counter needs.
func (r *txReserver) collect(items []txItem, pkts []tio.Packet, fwPacket *firewall.ParsedPacket, rejectBuf []byte, q int, localCache firewall.ConntrackCache) []txItem {
	f := r.f
	r.tunnels = r.tunnels[:0]
	for _, pkt := range pkts {
		hostinfo := f.filterInsidePacket(pkt, fwPacket, rejectBuf, q, localCache)
		if hostinfo == nil {
			continue
		}
		var it txItem
		if !f.prepareTxItem(&it, hostinfo, pkt) {
			continue
		}
		it.segs = segmentCount(pkt)
		it.counter = r.need(it.hostinfo, it.ci, it.segs)
		if it.relayHI != nil {
			// The relay bookkeeping inline sends do per segment in prepareSendVia, once per item
			f.connectionManager.OutNoRebind(it.relayHI)
			f.connectionManager.RelayUsed(it.relay.LocalIndex)
			it.relayCounter = r.need(it.relayHI, it.relayHI.ConnectionState, it.segs)
		}
		items = append(items, it)
	}
	return items
}

// need adds n counters to ci's tally for this batch and returns the offset of the first one within it.
func (r *txReserver) need(hostinfo *HostInfo, ci *ConnectionState, n uint64) uint64 {
	t := r.tunnel(ci)
	if t == nil {
		r.tunnels = append(r.tunnels, txTunnel{ci: ci, hostinfo: hostinfo})
		t = &r.tunnels[len(r.tunnels)-1]
	}
	off := t.n
	t.n += n
	return off
}

// tunnel finds ci's tally, a batch rarely touches more than a couple of tunnels so a scan beats a map.
func (r *txReserver) tunnel(ci *ConnectionState) *txTunnel {
	for i := range r.tunnels {
		if r.tunnels[i].ci == ci {
			return &r.tunnels[i]
		}
	}
	return nil
}

// reserve takes the counters collect tallied and stamps them onto items, dropping the items of any tunnel whose
// counter is exhausted. It returns the items that are left.
func (r *txReserver) reserve(items []txItem) []txItem {
	f := r.f
	// One atomic add per tunnel reserves the whole batch's counters before any worker sees it, so counter order on a
	// tunnel is dispatch order, which is the order the batches are flushed in. Reservation and the sender's order are
	// both taken on the reader goroutine, so there is no window for another batch to slip in between.
	for i := range r.tunnels {
		t := &r.tunnels[i]
		end := t.ci.messageCounter.Add(t.n)
		t.base = end - t.n + 1
		if end >= RejectAfterMessages {
			t.ci.messageCounter.Store(RejectAfterMessages)
			t.exhausted = true
			f.messageMetrics.TxExhausted(int64(t.n))
			if t.base <= RejectAfterMessages {
				t.hostinfo.logger(f.l).Error("Dropping outbound packets, tunnel message counter is exhausted")
			}
		}
	}

	n := 0
	for _, it := range items {
		t := r.tunnel(it.ci)
		if t.exhausted {
			continue
		}
		it.counter += t.base
		if it.relayHI != nil {
			rt := r.tunnel(it.relayHI.ConnectionState)
			if rt.exhausted {
				continue
			}
			it.relayCounter += rt.base
		}
		items[n] = it
		n++
	}
	clear(items[n:])
	return items[:n]
}

// handoffQueue is a tun queue that can give up the buffer its last Read filled. SwapRxBuf(nil) allocates a
// correctly sized replacement; later swaps recycle the buffers handed back.
type handoffQueue interface {
	tio.Queue
	SwapRxBuf([]byte) []byte
}

const stagedTxSlots = 8

// txSlot is one staged batch. The reader fills items, a worker encrypts them into sb and signals done, and the
// ordered sender flushes sb.
type txSlot struct {
	f     *Interface
	items []txItem
	// buf owns the queue receive buffer the items point into, swapped out at dispatch
	buf  []byte
	sb   *batch.SendBatch
	done chan struct{}
	// reserved is how many counters the batch reserved, for the reader's maxReserved budget
	reserved uint64
}

func (s *txSlot) run(nb []byte) {
	for i := range s.items {
		s.f.encryptTxItem(&s.items[i], nb, s.sb)
	}
	s.done <- struct{}{}
}

// stagedTx is the staged transmit pipeline of one tun reader. Everything but the workers and the sender runs on the
// reader goroutine.
type stagedTx struct {
	txReserver
	q         int
	cpu       int // reader CPU
	senderCPU int // -1 leaves the sender within its inherited affinity
	queue     handoffQueue
	pool      *flowPool

	// free holds the reader's idle slots. A dispatched slot goes to the workers and, in the same order, to the
	// sender on ordered; the sender gives it back on returned once it is on the wire.
	free       []*txSlot
	ordered    chan *txSlot
	returned   chan *txSlot
	inFlight   int
	senderDone chan struct{}
	// reserved is the counters held by in-flight slots, maxReserved this reader's half-window share
	reserved    uint64
	maxReserved uint64

	readBusy, encryptBusy, sendBusy metrics.Counter
	metricBatches                   metrics.Counter
}

// newStagedTx needs a queue that hands over whole read batches, the offload (TSO/USO) queue on linux. On any other
// queue a read is one packet, and staging it would cost a handoff per packet.
func newStagedTx(f *Interface, queue handoffQueue, q int) *stagedTx {
	p := &stagedTx{
		txReserver:    txReserver{f: f, tunnels: make([]txTunnel, 0, 4)},
		q:             q,
		senderCPU:     -1,
		queue:         queue,
		ordered:       make(chan *txSlot, stagedTxSlots),
		returned:      make(chan *txSlot, stagedTxSlots),
		senderDone:    make(chan struct{}),
		maxReserved:   (ReplayWindow / 2) / uint64(max(f.routines, 1)),
		readBusy:      stageBusy("tx_read", q),
		encryptBusy:   stageBusy("tx_encrypt", q),
		sendBusy:      stageBusy("tx_send", q),
		metricBatches: metrics.GetOrRegisterCounter("flow.tx.batches", nil),
	}
	if f.pinThreads {
		p.cpu = f.threadCPU(q)
		// Only an explicit list pins the sender, and never onto its reader's CPU, where the two would serialise.
		// Automatic placement by queue index can put a busy sender on a slow core; unpinned, the scheduler moves it.
		if n := len(f.cpuAffinity); n > 0 && f.cpuAffinity[(q+1)%n] != p.cpu {
			p.senderCPU = f.cpuAffinity[(q+1)%n]
		}
	}
	p.pool = newFlowPool(f.staged.workers, stagedTxSlots, p.encryptBusy)

	// Ciphertext adds per-segment headers and tags; the arena can grow for small segments.
	buf := queue.SwapRxBuf(nil)
	bufSize := len(buf)
	for i := range stagedTxSlots {
		if i > 0 {
			buf = make([]byte, bufSize)
		}
		p.free = append(p.free, &txSlot{
			f:    f,
			buf:  buf,
			sb:   batch.NewSendBatch(f.writers[q], 4*batch.SendBatchCap, bufSize+bufSize/4),
			done: make(chan struct{}, 1),
		})
	}
	go p.sender()
	return p
}

// run is listenIn's loop with the staged pipeline: read, then hand each batch on, until the queue fails.
func (p *stagedTx) run(fwPacket *firewall.ParsedPacket, rejectBuf []byte, conntrackCache *firewall.ConntrackCacheTicker) error {
	defer p.close()
	if p.f.pinThreads {
		p.f.pinThreadToCPU(p.q, p.cpu)
	}
	for {
		pkts, err := p.queue.Read()
		if err != nil {
			return err
		}
		t := time.Now()
		stall := p.handle(pkts, fwPacket, rejectBuf, conntrackCache.Get())
		p.readBusy.Inc(int64(time.Since(t) - stall))
	}
}

// handle takes one tun read through the pipeline. It returns once the batch is queued, or sent when the reader sent
// it itself, with how long it waited for the sender.
func (p *stagedTx) handle(pkts []tio.Packet, fwPacket *firewall.ParsedPacket, rejectBuf []byte, localCache firewall.ConntrackCache) time.Duration {
	p.reap()

	slot, stall := p.acquire()
	items := p.collect(slot.items[:0], pkts, fwPacket, rejectBuf, p.q, localCache)
	if len(items) == 0 {
		slot.items = items
		p.free = append(p.free, slot)
		return stall
	}

	var total uint64
	for _, t := range p.tunnels {
		total += t.n
	}
	// Over this reader's share of the window, wait for its oldest batches to go out first. A lone batch always goes.
	if p.inFlight > 0 && p.reserved+total > p.maxReserved {
		t := time.Now()
		for p.inFlight > 0 && p.reserved+total > p.maxReserved {
			p.release(<-p.returned)
		}
		stall += time.Since(t)
	}
	items = p.reserve(items)
	slot.items = items
	if len(items) == 0 {
		p.free = append(p.free, slot)
		return stall
	}

	// The packets now live in the slot, and the queue reads into the slot's old buffer
	slot.buf = p.queue.SwapRxBuf(slot.buf)

	slot.reserved = total
	p.reserved += total
	p.inFlight++
	p.metricBatches.Inc(1)
	// Counters were reserved above on this goroutine and the slot takes its place in the sender's order right here,
	// before any other batch can, so the sender puts them on the wire in counter order.
	p.ordered <- slot
	p.pool.jobs <- slot
	return stall
}

// acquire returns an idle slot, waiting for the sender to give one back when all of them are in flight, and how long
// it waited.
func (p *stagedTx) acquire() (*txSlot, time.Duration) {
	var stall time.Duration
	if len(p.free) == 0 {
		t := time.Now()
		p.release(<-p.returned)
		stall = time.Since(t)
	}
	s := p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	return s, stall
}

// reap takes back every slot the sender has finished with, without waiting.
func (p *stagedTx) reap() {
	for {
		select {
		case s := <-p.returned:
			p.release(s)
		default:
			return
		}
	}
}

func (p *stagedTx) release(s *txSlot) {
	p.reserved -= s.reserved
	s.reserved = 0
	p.inFlight--
	p.free = append(p.free, s)
}

// sender is the ordered send stage: it puts each batch on the wire once its worker is done, in dispatch order.
func (p *stagedTx) sender() {
	defer close(p.senderDone)
	if p.senderCPU >= 0 {
		p.f.pinThreadToCPU(p.q, p.senderCPU)
	}
	for s := range p.ordered {
		<-s.done
		t := time.Now()
		if p.f.closed.Load() {
			// The sockets are gone, a flush would only log errors
			s.sb.Reset()
		} else {
			p.f.flushSendBatch(s.sb, p.q)
		}
		p.sendBusy.Inc(int64(time.Since(t)))
		clear(s.items)
		s.items = s.items[:0]
		p.returned <- s
	}
}

// close sends everything still in flight, in order, and stops the sender and the workers.
func (p *stagedTx) close() {
	close(p.ordered)
	<-p.senderDone
	p.pool.close()
}
