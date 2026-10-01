package batch

import "net/netip"

const SendBatchCap = 128

// batchWriter is the minimal subset of udp.Conn needed by SendBatch to flush.
type batchWriter interface {
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error)
}

// SendBatch accumulates encrypted UDP packets and flushes them via WriteBatch.
// One SendBatch is owned by each listenIn goroutine; no locking is needed.
// Slots are backed by an Arena (see its docs)
type SendBatch struct {
	out  batchWriter
	bufs [][]byte
	dsts []netip.AddrPort
	// arena backs the slots. borrowed means someone else owns it and Flush must
	// leave it alone.
	arena    *Arena
	borrowed bool
}

// NewSendBatch makes a SendBatch with batchCap slots and an arenaSize byte buffer for slices to back those slots
func NewSendBatch(out batchWriter, batchCap, arenaSize int) *SendBatch {
	return newSendBatch(out, batchCap, NewArena(arenaSize), false)
}

// NewSendBatchSharedArena makes a SendBatch that borrows arena rather than
// allocating one. Several batches over different sockets can then split a single
// slab, which is what multiport lanes need: the slab is the expensive part of a
// SendBatch and one routine may hold a batch per lane. Flush leaves the arena
// alone, so the owner must Reset it once every batch sharing it is drained.
func NewSendBatchSharedArena(out batchWriter, batchCap int, arena *Arena) *SendBatch {
	return newSendBatch(out, batchCap, arena, true)
}

func newSendBatch(out batchWriter, batchCap int, arena *Arena, borrowed bool) *SendBatch {
	return &SendBatch{
		out:      out,
		bufs:     make([][]byte, 0, batchCap),
		dsts:     make([]netip.AddrPort, 0, batchCap),
		arena:    arena,
		borrowed: borrowed,
	}
}

func (b *SendBatch) Reserve(sz int) []byte {
	return b.arena.Reserve(sz)
}

// Len reports how many packets are queued for the next Flush. Callers use
// it to flush incrementally once a full sendmmsg batch has accumulated,
// bounding how long the first packet of a large read batch waits.
func (b *SendBatch) Len() int { return len(b.bufs) }

func (b *SendBatch) Commit(pkt []byte, dst netip.AddrPort) {
	b.bufs = append(b.bufs, pkt)
	b.dsts = append(b.dsts, dst)
}

// Flush writes every queued packet and reports how many actually went out. A short count means some destinations
// were undeliverable; the batch is drained either way.
func (b *SendBatch) Flush() (int, error) {
	var err error
	written := 0
	if len(b.bufs) > 0 {
		written, err = b.out.WriteBatch(b.bufs, b.dsts)
	}
	clear(b.bufs)
	b.bufs = b.bufs[:0]
	b.dsts = b.dsts[:0]
	if !b.borrowed {
		b.arena.Reset()
	}
	return written, err
}
