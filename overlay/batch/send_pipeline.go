//go:build darwin || send_pipeline

package batch

import (
	"sync"
)

// SendPipeline splits encrypt from send. The producer (a tun reader) encrypts packets into one SendBatch while a
// sender goroutine writes the other, and they swap whenever the sender is free. The sender takes everything the
// producer committed since its last take, so packets that arrive during a write leave together in the next
// WriteBatch, and the reader returns to the tun while the kernel is still sending.
//
// The producer holds the batch for one packet at a time (Begin, reserve and commit, End) so the sender can take the
// batch between any two packets, never while a reserved slot is still being written.
//
// Ownership: the producer touches its batch only between Begin and End, and the sender swaps batches only under
// the same lock, so a slot the producer reserved is never sent half written. A batch goes back to the producer
// only after its WriteBatch returned and it was emptied, so no slot is reused before its send completes.
//
// Memory is bounded at two batches. When the producer fills its batch while the sender is still writing the other,
// Begin waits for the swap. That slows the tun reader instead of dropping, as the unpipelined path does.
//
// Order: a single sender writes batches in the order they were filled, each in commit order, so every peer's
// packets leave in the order their message counters were taken.
type SendPipeline struct {
	out      batchWriter
	cap      int
	maxWrite int
	onWrite  func(queued, written int, err error)

	mu   sync.Mutex
	cond sync.Cond
	cur  *SendBatch // the producer's batch, guarded by mu
	gen  uint64     // swaps so far, guarded by mu

	ready chan struct{} // cap 1: cur may have packets for the sender
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
}

// NewSendPipeline starts a pipeline over two batches of batchCap slots and arenaSize arena bytes each. It writes
// to out at most maxWrite packets per WriteBatch. If onWrite is not nil, it is called on the sender goroutine
// after every WriteBatch with how many packets that call was given, how many went out, and its error. Close stops
// the pipeline.
func NewSendPipeline(out batchWriter, batchCap, arenaSize, maxWrite int, onWrite func(queued, written int, err error)) *SendPipeline {
	batchCap = max(batchCap, 1)
	p := &SendPipeline{
		out:      out,
		cap:      batchCap,
		maxWrite: max(maxWrite, 1),
		onWrite:  onWrite,
		cur:      NewSendBatch(out, batchCap, arenaSize),
		ready:    make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	p.cond.L = &p.mu
	go p.run(NewSendBatch(out, batchCap, arenaSize))
	return p
}

// Begin returns a batch with room for at least one more packet. The batch stays the producer's until End. If the
// batch is full, Begin first waits for the sender to swap it out. Producer only.
func (p *SendPipeline) Begin() *SendBatch {
	p.mu.Lock()
	if p.cur.Len() >= p.cap {
		g := p.gen
		p.wake()
		for p.gen == g {
			p.cond.Wait()
		}
	}
	return p.cur
}

// End gives up the batch Begin returned. With wake set it also tells the sender the batch has packets for it, which
// the producer does once a run of packets is in (the end of a tun read) rather than per packet, so the sender takes
// the run whole when it is idle. A sender still writing takes the batch when it finishes, woken or not.
func (p *SendPipeline) End(wake bool) {
	n := p.cur.Len()
	p.mu.Unlock()
	if wake && n > 0 {
		p.wake()
	}
}

func (p *SendPipeline) wake() {
	select {
	case p.ready <- struct{}{}:
	default:
	}
}

// Close writes whatever the producer left in its batch, stops the sender, and waits for it. The producer calls it,
// outside Begin/End, once it is done. Safe to call more than once.
func (p *SendPipeline) Close() {
	p.once.Do(func() { close(p.stop) })
	<-p.done
}

func (p *SendPipeline) run(mine *SendBatch) {
	defer close(p.done)
	for {
		stopping := false
		select {
		case <-p.ready:
		case <-p.stop:
			stopping = true
		}
		// Keep taking whatever the producer committed during the last write, without waiting to be woken, so a
		// busy sender goes straight from one write to the next and each write carries everything that built up.
		// Once stopping, the producer is done and this writes what it left.
		for p.take(&mine) {
			p.write(mine)
		}
		if stopping {
			return
		}
	}
}

// take swaps the producer's batch for the empty *mine if the producer's has packets, and reports whether it did.
func (p *SendPipeline) take(mine **SendBatch) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur.Len() == 0 {
		return false
	}
	*mine, p.cur = p.cur, *mine
	p.gen++
	p.cond.Broadcast()
	return true
}

// write sends b's packets, maxWrite at a time, then empties b.
func (p *SendPipeline) write(b *SendBatch) {
	for off := 0; off < len(b.bufs); {
		n := min(p.maxWrite, len(b.bufs)-off)
		written, err := p.out.WriteBatch(b.bufs[off:off+n], b.dsts[off:off+n])
		if p.onWrite != nil {
			p.onWrite(n, written, err)
		}
		off += n
	}
	b.recycle()
}

// recycle empties b without writing it. SendPipeline uses it because it writes a batch's packets itself.
func (b *SendBatch) recycle() {
	clear(b.bufs)
	b.bufs = b.bufs[:0]
	b.dsts = b.dsts[:0]
	b.arena.Reset()
}
