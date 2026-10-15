package nebula

import (
	"net/netip"
	"sync"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
)

// handoffConn is a udp conn that receives in batches of a fixed shape, so staged receive can have replacement buffers
// ready for every batch it keeps.
type handoffConn interface {
	ListenOut(udp.EncReader, func([][]byte) [][]byte) error
	HandoffShape() (n, size int)
}

const stagedRxSlots = 6
const rxChunkMin = 16

// rxItem is one received packet. A data packet for an established tunnel has ci set; out and err are written by
// whoever decrypts it.
type rxItem struct {
	packet  []byte
	ci      *ConnectionState
	counter uint64
	via     netip.AddrPort
	out     []byte
	err     error
}

// rxChunk is a contiguous run of a batch's items for one worker to decrypt.
type rxChunk struct {
	items []rxItem
	done  chan struct{}
}

// decryptRxItems decrypts the data packets among items in place, skipping the replays checkReplays marked. Recording
// the counters is left to readOutsidePackets on the writer, which also handles the packets without a tunnel.
func decryptRxItems(items []rxItem, nb []byte) {
	for i := range items {
		it := &items[i]
		if it.ci == nil || it.err != nil {
			continue
		}
		it.out, it.err = it.ci.decryptPacket(it.counter, it.packet, nb)
	}
}

// rxBatch is one recvmmsg batch moving through the staged receive pipeline.
type rxBatch struct {
	// items is every packet of the batch in arrival order. Data packets are decrypted by a worker; anything else is
	// handled whole by the writer, in its place.
	items []rxItem
	// bufs is the set of recvmmsg buffers the items point into, owned by the batch from handoff until it is reused.
	bufs [][]byte
	// chunks are the decrypt jobs, nChunks of them in use. With none the writer decrypts the batch itself.
	chunks  []rxChunk
	nChunks int
}

func (b *rxBatch) reset() {
	clear(b.items)
	b.items = b.items[:0]
	for i := range b.nChunks {
		b.chunks[i].items = nil
	}
	b.nChunks = 0
}

// stagedRx is the staged receive pipeline of one udp listener. deliver and handoff run on the listener goroutine.
type stagedRx struct {
	f *Interface
	q int
	// jobs feeds the decrypt workers. The listener is the only producer and closes it once the writer has drained.
	jobs    chan *rxChunk
	workers sync.WaitGroup
	// h and hostmapCache are the listener's own. wrxc is the commit context: the writer's, or the listener's while
	// nothing is in flight.
	h            *header.H
	hostmapCache map[uint32]*HostInfo
	wrxc         *rxContext

	cur        *rxBatch
	free       []*rxBatch
	ordered    chan *rxBatch
	returned   chan *rxBatch
	inFlight   int
	writerDone chan struct{}

	metricBatches metrics.Counter
	metricInline  metrics.Counter
}

func newStagedRx(f *Interface, q int, wrxc *rxContext) *stagedRx {
	p := &stagedRx{
		f:             f,
		q:             q,
		h:             &header.H{},
		hostmapCache:  map[uint32]*HostInfo{},
		wrxc:          wrxc,
		ordered:       make(chan *rxBatch, stagedRxSlots),
		returned:      make(chan *rxBatch, stagedRxSlots),
		writerDone:    make(chan struct{}),
		metricBatches: metrics.GetOrRegisterCounter("flow.rx.batches", nil),
		metricInline:  metrics.GetOrRegisterCounter("flow.rx.inline", nil),
	}
	n := f.staged.workers
	p.jobs = make(chan *rxChunk, stagedRxSlots*2*n)
	for range n {
		p.workers.Go(p.decrypt)
	}
	for range stagedRxSlots {
		// Two chunks per worker, so the writer can start committing while the workers are still on the rest
		b := &rxBatch{items: make([]rxItem, 0, 256), chunks: make([]rxChunk, 2*n)}
		for i := range b.chunks {
			b.chunks[i].done = make(chan struct{}, 1)
		}
		p.free = append(p.free, b)
	}
	p.cur = p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	go p.writer()
	return p
}

// decrypt is a worker: it decrypts the chunks it is handed and signals each one done.
func (p *stagedRx) decrypt() {
	nb := make([]byte, 12)
	for c := range p.jobs {
		decryptRxItems(c.items, nb)
		c.done <- struct{}{}
	}
}

// listen runs the conn's receive loop through the pipeline until it fails, then drains the pipeline. The conn hands
// its buffers over, so a batch moves between stages without a copy.
func (p *stagedRx) listen(li handoffConn) error {
	// The first batch reads into the conn's own buffers; every other one brings its own
	n, size := li.HandoffShape()
	for _, b := range p.free {
		b.bufs = make([][]byte, n)
		for i := range b.bufs {
			b.bufs[i] = make([]byte, size)
		}
	}
	defer p.close()
	return li.ListenOut(p.deliver, p.handoff)
}

// deliver is the listener's per-packet work: classify the packet and add it to the current batch. Nothing here
// decrypts or touches the tun.
func (p *stagedRx) deliver(via netip.AddrPort, packet []byte) {
	it := rxItem{packet: packet, via: via}
	p.classify(&it)
	p.cur.items = append(p.cur.items, it)
}

// classify fills in the tunnel for a plain data packet of an established, non-relayed tunnel, leaving anything else
// for the writer to handle whole. It is speculative: readOutsidePackets resolves the tunnel again on the writer and
// uses the worker's result only when it is still the same one.
func (p *stagedRx) classify(it *rxItem) {
	f := p.f
	h := p.h
	packet := it.packet
	if h.Parse(packet) != nil || h.Version != header.Version || h.Type != header.Message || h.Subtype != header.MessageNone {
		return
	}
	if f.myVpnNetworksTable.Contains(it.via.Addr()) {
		return
	}
	hostinfo := f.hostMap.QueryIndexCached(h.RemoteIndex, p.hostmapCache)
	if hostinfo == nil || hostinfo.ConnectionState == nil {
		return
	}
	ci := hostinfo.ConnectionState
	if len(packet) < header.Len+ci.dKey.Overhead() {
		return
	}
	it.ci, it.counter = ci, h.MessageCounter
}

// handoff ends a batch: the batch takes bufs, and the conn reads the next batch into the buffers of the next free
// batch.
func (p *stagedRx) handoff(bufs [][]byte) [][]byte {
	p.cur.bufs = bufs
	p.endBatch()
	return p.cur.bufs
}

// endBatch hands the batch to the workers and the ordered writer, then takes a free batch.
func (p *stagedRx) endBatch() {
	clear(p.hostmapCache)
	p.reap()
	b := p.cur
	n := len(b.items)
	if n == 0 {
		b.reset()
		return
	}
	p.checkReplays(b.items)

	if p.inFlight == 0 && n < p.f.staged.inlineBelow {
		// The writer is idle with nothing in flight, so the listener may commit with its context and flush the tun
		p.metricInline.Inc(1)
		p.process(b, p.wrxc)
		b.reset()
		return
	}

	parts := min(len(b.chunks), n/rxChunkMin)
	p.metricBatches.Inc(1)
	if parts > 0 {
		size := (n + parts - 1) / parts
		for off := 0; off < n; off += size {
			c := &b.chunks[b.nChunks]
			c.items = b.items[off:min(off+size, n)]
			b.nChunks++
		}
	}
	// The jobs go out before the batch does: once the writer has it, it may finish and reset it at any moment
	for i := range b.nChunks {
		p.jobs <- &b.chunks[i]
	}
	p.inFlight++
	p.ordered <- b

	if len(p.free) == 0 {
		// Every batch is in flight, wait for the writer: the socket buffer absorbs the backlog meanwhile
		p.release(<-p.returned)
	}
	p.cur = p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
}

// checkReplays marks the replays among items before anything decrypts them, as Decrypt checks before it decrypts,
// taking each tunnel's lock once per run of its packets rather than once per packet. The window only moves forward
// until the writer records these counters, so a stale check can only let a replay through to acceptDecrypted, which
// rejects it.
func (p *stagedRx) checkReplays(items []rxItem) {
	for i := 0; i < len(items); {
		ci := items[i].ci
		if ci == nil {
			i++
			continue
		}
		ci.decryptLock.Lock()
		for ; i < len(items) && items[i].ci == ci; i++ {
			if !ci.window.Check(p.f.l, items[i].counter) {
				items[i].err = ErrAlreadySeen
			}
		}
		ci.decryptLock.Unlock()
	}
}

// reap takes back every batch the writer has finished with, without waiting.
func (p *stagedRx) reap() {
	for {
		select {
		case b := <-p.returned:
			p.release(b)
		default:
			return
		}
	}
}

func (p *stagedRx) release(b *rxBatch) {
	p.inFlight--
	p.free = append(p.free, b)
}

// process is the ordered stage for one batch: decrypt whatever no worker is decrypting, commit every item in arrival
// order, and flush the tun batcher.
func (p *stagedRx) process(b *rxBatch, rxc *rxContext) {
	if b.nChunks == 0 {
		decryptRxItems(b.items, rxc.nb)
		p.commit(b.items, rxc)
	} else {
		// Commit chunk by chunk, so the commit overlaps the workers still on later chunks
		for i := range b.nChunks {
			c := &b.chunks[i]
			<-c.done
			p.commit(c.items, rxc)
		}
	}
	p.f.flushOutside(rxc)
}

// commit runs every item through readOutsidePackets in arrival order, handing it the worker's result for a data
// packet, exactly as inline receive handles them.
func (p *stagedRx) commit(items []rxItem, rxc *rxContext) {
	for i := range items {
		it := &items[i]
		if it.ci != nil {
			rxc.decrypted = it
		}
		p.f.readOutsidePackets(ViaSender{UdpAddr: it.via}, it.packet, rxc)
		rxc.decrypted = nil
	}
}

// writer is the ordered receive stage: window, firewall, coalescer and tun write, one batch at a time in arrival
// order.
func (p *stagedRx) writer() {
	defer close(p.writerDone)
	for b := range p.ordered {
		if p.f.closed.Load() {
			// The tun is going away, a write would only log errors. Still wait out the workers on the batch.
			for i := range b.nChunks {
				<-b.chunks[i].done
			}
		} else {
			p.process(b, p.wrxc)
		}
		b.reset()
		p.returned <- b
	}
}

// close commits anything still in flight, in order, and stops the writer and the workers.
func (p *stagedRx) close() {
	if len(p.cur.items) > 0 {
		p.endBatch()
	}
	close(p.ordered)
	<-p.writerDone
	close(p.jobs)
	p.workers.Wait()
}
