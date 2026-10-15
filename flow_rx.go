package nebula

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
)

// handoffConn is a udp conn that can hand each received batch over. The callback returns replacement buffers with
// the same count and at least the same lengths.
type handoffConn interface {
	ListenOutHandoff(udp.EncReader, func([][]byte) [][]byte) error
}

const rxChunkMin = 16

// rxItem is one received packet. A data packet for an established tunnel has ci set; out and err are written by
// whoever decrypts it.
type rxItem struct {
	packet   []byte
	hostinfo *HostInfo
	ci       *ConnectionState
	counter  uint64
	via      netip.AddrPort
	out      []byte
	err      error
}

// rxChunk is a contiguous run of a batch's items for one worker to decrypt.
type rxChunk struct {
	items []rxItem
	done  chan struct{}
}

func (c *rxChunk) run(nb []byte) {
	decryptRxItems(c.items, nb)
	c.done <- struct{}{}
}

// decryptRxItems decrypts the data packets among items in place. The replay window is left to the ordered stage, as
// are packets without a tunnel and the known replays precheck marked.
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
	data  int
	// bufs is the set of recvmmsg buffers the items point into, owned by the batch from handoff until it is reused.
	bufs [][]byte
	// chunks are the decrypt jobs, nChunks of them in use. With none the writer decrypts the batch itself.
	chunks  []rxChunk
	nChunks int
}

func (b *rxBatch) reset() {
	clear(b.items)
	b.items = b.items[:0]
	b.data = 0
	for i := range b.nChunks {
		b.chunks[i].items = nil
	}
	b.nChunks = 0
}

// stagedRx is the staged receive pipeline of one udp listener. deliver and handoff run on the listener goroutine.
type stagedRx struct {
	f    *Interface
	q    int
	pool *flowPool
	// h and hostmapCache are the listener's own. wrxc is the commit context: the writer's, or the listener's while
	// nothing is in flight.
	h            *header.H
	hostmapCache map[uint32]*HostInfo
	wrxc         *rxContext

	started    time.Time
	cur        *rxBatch
	free       []*rxBatch
	ordered    chan *rxBatch
	returned   chan *rxBatch
	inFlight   int
	writerDone chan struct{}

	readBusy, decryptBusy, writeBusy metrics.Counter
	metricBatches                    metrics.Counter
	metricInline                     metrics.Counter
}

func newStagedRx(f *Interface, q int, wrxc *rxContext) *stagedRx {
	p := &stagedRx{
		f:             f,
		q:             q,
		h:             &header.H{},
		hostmapCache:  map[uint32]*HostInfo{},
		wrxc:          wrxc,
		ordered:       make(chan *rxBatch, f.staged.rxSlots),
		returned:      make(chan *rxBatch, f.staged.rxSlots),
		writerDone:    make(chan struct{}),
		readBusy:      stageBusy("rx_read", q),
		decryptBusy:   stageBusy("rx_decrypt", q),
		writeBusy:     stageBusy("rx_write", q),
		metricBatches: metrics.GetOrRegisterCounter("flow.rx.batches", nil),
		metricInline:  metrics.GetOrRegisterCounter("flow.rx.inline", nil),
	}
	workers := f.staged.workers
	p.pool = newFlowPool(workers, f.staged.rxSlots*2*workers, p.decryptBusy)
	for range f.staged.rxSlots {
		// Two chunks per worker, so the writer can start committing while the workers are still on the rest
		b := &rxBatch{items: make([]rxItem, 0, 256), chunks: make([]rxChunk, 2*workers)}
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

// listen runs the conn's receive loop through the pipeline until it fails, then drains the pipeline. The conn hands
// its buffers over, so a batch moves between stages without a copy.
func (p *stagedRx) listen(li handoffConn) error {
	defer p.close()
	return li.ListenOutHandoff(p.deliver, p.handoff)
}

// deliver is the listener's per-packet work: classify the packet and add it to the current batch. Nothing here
// decrypts or touches the tun.
func (p *stagedRx) deliver(via netip.AddrPort, packet []byte) {
	if p.started.IsZero() {
		p.started = time.Now()
	}
	b := p.cur
	it := rxItem{packet: packet, via: via}
	p.classify(&it)
	if it.ci != nil {
		b.data++
	}
	b.items = append(b.items, it)
}

// classify fills in the tunnel for a plain data packet of an established, non-relayed tunnel, leaving anything else
// for the writer to handle whole. The replay pre-check waits for the end of the batch, see precheck.
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
	it.hostinfo, it.ci, it.counter = hostinfo, ci, h.MessageCounter
}

// precheck marks obvious replays before anything decrypts them, like ConnectionState.Decrypt does, taking each
// tunnel's lock once per run of its packets rather than once per packet: the writer takes the same lock for its
// window updates, from another core. The writer checks again when it commits. The window only moves forward in
// between, so a stale check here can only let a replay through to that second check. Marked packets keep their
// place: an earlier RecvError may delete their tunnel, and inline receive then replies with a RecvError rather than
// dropping a replay.
func (p *stagedRx) precheck(b *rxBatch) {
	f := p.f
	items := b.items
	for i := 0; i < len(items); {
		ci := items[i].ci
		if ci == nil {
			i++
			continue
		}
		ci.decryptLock.Lock()
		for ; i < len(items) && items[i].ci == ci; i++ {
			if ci.window.Check(f.l, items[i].counter) {
				continue
			}
			b.data--
			items[i].err = ErrAlreadySeen
		}
		ci.decryptLock.Unlock()
	}
}

// handoff ends a batch: the batch takes bufs, and the conn reads the next batch into the buffers of the next free
// batch.
func (p *stagedRx) handoff(bufs [][]byte) [][]byte {
	p.cur.bufs = bufs
	p.endBatch()
	if !p.started.IsZero() {
		p.readBusy.Inc(int64(time.Since(p.started)))
		p.started = time.Time{}
	}
	b := p.cur
	if len(b.bufs) != len(bufs) || len(b.bufs[0]) < len(bufs[0]) {
		b.bufs = make([][]byte, len(bufs))
		for i := range b.bufs {
			b.bufs[i] = make([]byte, len(bufs[0]))
		}
	}
	return b.bufs
}

// endBatch hands the batch to the workers and the ordered writer, then takes a free batch.
func (p *stagedRx) endBatch() {
	clear(p.hostmapCache)
	p.reap()
	b := p.cur
	p.precheck(b)
	n := len(b.items)
	if n == 0 {
		b.reset()
		return
	}

	if p.inFlight == 0 && n < p.f.staged.inlineBelow {
		// The writer is idle with nothing in flight, so the listener may commit with its context and flush the tun
		p.metricInline.Inc(1)
		p.process(b, p.wrxc)
		b.reset()
		return
	}

	parts := min(len(b.chunks), b.data/rxChunkMin)
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
		p.pool.jobs <- &b.chunks[i]
	}
	p.inFlight++
	p.ordered <- b

	if len(p.free) == 0 {
		// Every batch is in flight, wait for the writer: the socket buffer absorbs the backlog meanwhile. The wait is
		// downstream backpressure, not listener busy time.
		t := time.Now()
		p.release(<-p.returned)
		p.started = p.started.Add(time.Since(t))
	}
	p.cur = p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
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
// order, and flush the tun batcher. It reports how long it waited on workers.
func (p *stagedRx) process(b *rxBatch, rxc *rxContext) time.Duration {
	var waited time.Duration
	if b.nChunks == 0 {
		decryptRxItems(b.items, rxc.nb)
		p.commit(b.items, rxc)
	} else {
		// Commit chunk by chunk, so the commit overlaps the workers still on later chunks
		for i := range b.nChunks {
			c := &b.chunks[i]
			select {
			case <-c.done:
			default:
				t := time.Now()
				<-c.done
				waited += time.Since(t)
			}
			p.commit(c.items, rxc)
		}
	}
	p.f.flushOutside(rxc)
	return waited
}

// commit runs the ordered stage over items in arrival order. A non-data packet goes through readOutsidePackets in
// its place, a run of data packets on one tunnel through commitRun.
func (p *stagedRx) commit(items []rxItem, rxc *rxContext) {
	for i := 0; i < len(items); {
		ci := items[i].ci
		if ci == nil {
			p.f.readOutsidePackets(ViaSender{UdpAddr: items[i].via}, items[i].packet, rxc)
			i++
			continue
		}
		j := i + 1
		for j < len(items) && items[j].ci == ci {
			j++
		}
		p.commitRun(items[i:j], rxc)
		i = j
	}
}

// commitRun commits a run of decrypted data packets on one tunnel. The window updates go first, under one lock, then
// the rest; handling a data packet never touches the window, so that is the same as one packet at a time.
func (p *stagedRx) commitRun(run []rxItem, rxc *rxContext) {
	f := p.f
	ci := run[0].ci
	// Classification is speculative: earlier control packets may have removed this tunnel. Resolve it through the
	// writer's batch-local cache, exactly where inline processing would, before touching replay state.
	index := binary.BigEndian.Uint32(run[0].packet[4:8])
	hostinfo := f.hostMap.QueryIndexCached(index, rxc.hostmapCache)
	if hostinfo != run[0].hostinfo || hostinfo.ConnectionState != ci {
		if hostinfo == nil {
			for i := range run {
				f.maybeSendRecvError(run[i].via, index)
			}
		}
		return
	}

	ci.decryptLock.Lock()
	for i := range run {
		// A packet that failed to decrypt does not touch the window, like ConnectionState.Decrypt
		if run[i].err == nil && !ci.window.Update(f.l, run[i].counter) {
			run[i].err = ErrAlreadySeen
		}
	}
	ci.decryptLock.Unlock()
	for i := range run {
		it := &run[i]
		if f.finishOutsideDecrypt(it.hostinfo, ViaSender{UdpAddr: it.via}, it.counter, it.err) {
			f.handleOutsideMessagePacket(it.hostinfo, it.counter, it.out, rxc)
		}
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
			t := time.Now()
			waited := p.process(b, p.wrxc)
			p.writeBusy.Inc(int64(time.Since(t) - waited))
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
	p.pool.close()
}
