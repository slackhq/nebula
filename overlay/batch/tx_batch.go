package batch

import "net/netip"

const SendBatchCap = 128

// SendBatch accumulates encrypted UDP packets for potential TX offloading.
// One SendBatch is owned by each listenIn goroutine; no locking is needed.
// The backing storage holds up to batchCap packets of slotCap bytes each;
// bufs and dsts are parallel slices of committed slots.
type SendBatch struct {
	bufs     [][]byte
	dsts     []netip.AddrPort
	backing  []byte
	slotCap  int
	batchCap int
	nextSlot int
}

func NewSendBatch(batchCap, slotCap int) *SendBatch {
	return &SendBatch{
		bufs:     make([][]byte, 0, batchCap),
		dsts:     make([]netip.AddrPort, 0, batchCap),
		backing:  make([]byte, batchCap*slotCap),
		slotCap:  slotCap,
		batchCap: batchCap,
	}
}

func (b *SendBatch) Next() []byte {
	if b.nextSlot >= b.batchCap {
		return nil
	}
	start := b.nextSlot * b.slotCap
	return b.backing[start : start : start+b.slotCap] //set len to 0 but cap to slotCap
}

func (b *SendBatch) Commit(n int, dst netip.AddrPort) {
	start := b.nextSlot * b.slotCap
	b.bufs = append(b.bufs, b.backing[start:start+n])
	b.dsts = append(b.dsts, dst)
	b.nextSlot++
}

func (b *SendBatch) Reset() {
	b.bufs = b.bufs[:0]
	b.dsts = b.dsts[:0]
	b.nextSlot = 0
}

func (b *SendBatch) Len() int {
	return len(b.bufs)
}

func (b *SendBatch) Cap() int {
	return b.batchCap
}

func (b *SendBatch) Get() ([][]byte, []netip.AddrPort) {
	return b.bufs, b.dsts
}
