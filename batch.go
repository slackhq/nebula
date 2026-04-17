package nebula

import "net/netip"

// sendBatchCap is the maximum number of encrypted packets accumulated before a
// flush is forced. TSO superpackets segment to at most ~45 packets on
// reasonable MTUs, so 128 leaves headroom without bloating the backing
// allocation.
const sendBatchCap = 128

// sendBatch accumulates encrypted UDP packets for a single sendmmsg flush.
// One sendBatch is owned by each listenIn goroutine; no locking is needed.
// The backing storage holds up to batchCap packets of slotCap bytes each;
// bufs and dsts are parallel slices of committed slots.
type sendBatch struct {
	bufs     [][]byte
	dsts     []netip.AddrPort
	backing  []byte
	slotCap  int
	batchCap int
	nextSlot int
}

func newSendBatch(batchCap, slotCap int) *sendBatch {
	return &sendBatch{
		bufs:     make([][]byte, 0, batchCap),
		dsts:     make([]netip.AddrPort, 0, batchCap),
		backing:  make([]byte, batchCap*slotCap),
		slotCap:  slotCap,
		batchCap: batchCap,
	}
}

// Next returns a zero-length slice with slotCap capacity over the next unused
// slot's backing bytes. The caller writes into the returned slice and then
// calls Commit with the final length and destination. Next returns nil when
// the batch is full.
func (b *sendBatch) Next() []byte {
	if b.nextSlot >= b.batchCap {
		return nil
	}
	start := b.nextSlot * b.slotCap
	return b.backing[start : start : start+b.slotCap]
}

// Commit records the slot just returned by Next as a packet of length n
// destined for dst.
func (b *sendBatch) Commit(n int, dst netip.AddrPort) {
	start := b.nextSlot * b.slotCap
	b.bufs = append(b.bufs, b.backing[start:start+n])
	b.dsts = append(b.dsts, dst)
	b.nextSlot++
}

// Reset clears committed slots; backing storage is retained for reuse.
func (b *sendBatch) Reset() {
	b.bufs = b.bufs[:0]
	b.dsts = b.dsts[:0]
	b.nextSlot = 0
}

// Len returns the number of committed packets.
func (b *sendBatch) Len() int {
	return len(b.bufs)
}

// Cap returns the maximum number of slots in the batch.
func (b *sendBatch) Cap() int {
	return b.batchCap
}
