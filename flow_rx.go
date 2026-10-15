package nebula

import (
	"net/netip"
	"sync"
	"sync/atomic"

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
	// chunks are the decrypt jobs, nChunks of them in use.
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
	f    *Interface
	q    int
	conn handoffConn
	// jobs feeds the decrypt workers. The listener is the only producer and closes it once the writer has drained.
	jobs    chan *rxChunk
	workers sync.WaitGroup
	// h and hostmapCache are the listener's own. wrxc is the commit context: the writer's, or the listener's while
	// nothing is in flight.
	h            *header.H
	hostmapCache map[uint32]*HostInfo
	wrxc         *rxContext

	// cur is the batch the listener is filling. The others wait in free, or travel to the writer on ordered and come
	// back through free; inFlight counts those, and the writer drops it only once it is done with a batch.
	cur        *rxBatch
	free       chan *rxBatch
	ordered    chan *rxBatch
	inFlight   atomic.Int32
	writerDone chan struct{}

	metricBatches metrics.Counter
	metricInline  metrics.Counter
}

func newStagedRx(f *Interface, q int, wrxc *rxContext, conn handoffConn) *stagedRx {
	p := &stagedRx{
		f:             f,
		q:             q,
		conn:          conn,
		h:             &header.H{},
		hostmapCache:  map[uint32]*HostInfo{},
		wrxc:          wrxc,
		free:          make(chan *rxBatch, stagedRxSlots),
		ordered:       make(chan *rxBatch, stagedRxSlots),
		writerDone:    make(chan struct{}),
		metricBatches: metrics.GetOrRegisterCounter("flow.rx.batches", nil),
		metricInline:  metrics.GetOrRegisterCounter("flow.rx.inline", nil),
	}
	n := f.staged.workers
	p.jobs = make(chan *rxChunk, stagedRxSlots*2*n)
	for range n {
		p.workers.Go(p.decrypt)
	}
	bufs, size := conn.HandoffShape()
	for i := range stagedRxSlots {
		// Two chunks per worker, so the writer can start committing while the workers are still on the rest
		b := &rxBatch{items: make([]rxItem, 0, 256), chunks: make([]rxChunk, 2*n)}
		for j := range b.chunks {
			b.chunks[j].done = make(chan struct{}, 1)
		}
		if i == 0 {
			// The first batch reads into the conn's own buffers; every other one brings its own
			p.cur = b
			continue
		}
		b.bufs = make([][]byte, bufs)
		for j := range b.bufs {
			b.bufs[j] = make([]byte, size)
		}
		p.free <- b
	}
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
func (p *stagedRx) listen() error {
	defer p.close()
	return p.conn.ListenOut(p.deliver, p.handoff)
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
	b := p.cur
	n := len(b.items)
	if n == 0 {
		b.reset()
		return
	}
	p.checkReplays(b.items)

	if p.inFlight.Load() == 0 && n < p.f.staged.inlineBelow {
		// The writer is idle with nothing in flight, so the listener may commit with its context and flush the tun
		p.metricInline.Inc(1)
		p.processInline(b, p.wrxc)
		b.reset()
		return
	}

	parts := max(1, min(len(b.chunks), n/rxChunkMin))
	size := (n + parts - 1) / parts
	for off := 0; off < n; off += size {
		c := &b.chunks[b.nChunks]
		c.items = b.items[off:min(off+size, n)]
		b.nChunks++
	}
	// The jobs go out before the batch does: once the writer has it, it may finish and reset it at any moment
	for i := range b.nChunks {
		p.jobs <- &b.chunks[i]
	}
	p.metricBatches.Inc(1)
	p.inFlight.Add(1)
	p.ordered <- b
	// With every batch in flight this waits for the writer, the socket buffer absorbs the backlog meanwhile
	p.cur = <-p.free
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

// processInline decrypts and commits a batch on the calling goroutine, then flushes the tun.
func (p *stagedRx) processInline(b *rxBatch, rxc *rxContext) {
	decryptRxItems(b.items, rxc.nb)
	p.commit(b.items, rxc)
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

// writer is the ordered receive stage: it commits each batch chunk by chunk as the workers finish them, so the commit
// overlaps the workers still on later chunks, then flushes the tun and returns the batch.
func (p *stagedRx) writer() {
	defer close(p.writerDone)
	for b := range p.ordered {
		// Once the tun is going away a write would only log errors, so only wait out the workers
		closed := p.f.closed.Load()
		for i := range b.nChunks {
			c := &b.chunks[i]
			<-c.done
			if !closed {
				p.commit(c.items, p.wrxc)
			}
		}
		if !closed {
			p.f.flushOutside(p.wrxc)
		}
		b.reset()
		p.inFlight.Add(-1)
		p.free <- b
	}
}

// close stops the writer once it has committed everything in flight, in order, then the workers.
func (p *stagedRx) close() {
	close(p.ordered)
	<-p.writerDone
	close(p.jobs)
	p.workers.Wait()
}
