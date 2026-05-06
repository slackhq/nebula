package batch

import "net/netip"

const SendBatchCap = 128

// batchWriter is the minimal subset of udp.Conn needed by SendBatch to flush.
type batchWriter interface {
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort, outerECNs []byte) error
}

// SendBatch accumulates encrypted UDP packets and flushes them via WriteBatch.
// One SendBatch is owned by each listenIn goroutine; no locking is needed.
// The backing arena grows on demand: when there isn't room for the next slot
// we allocate a fresh backing array. Already-committed slices keep referencing
// the old array and remain valid until Flush drops them.
type SendBatch struct {
	out     batchWriter
	bufs    [][]byte
	dsts    []netip.AddrPort
	ecns    []byte
	backing []byte
}

func NewSendBatch(out batchWriter, batchCap, slotCap int) *SendBatch {
	return &SendBatch{
		out:     out,
		bufs:    make([][]byte, 0, batchCap),
		dsts:    make([]netip.AddrPort, 0, batchCap),
		ecns:    make([]byte, 0, batchCap),
		backing: make([]byte, 0, batchCap*slotCap),
	}
}

func (b *SendBatch) Reserve(sz int) []byte {
	if len(b.backing)+sz > cap(b.backing) {
		// Grow: allocate a fresh backing. Already-committed slices still
		// reference the old array and remain valid until Flush drops them.
		newCap := max(cap(b.backing)*2, sz)
		b.backing = make([]byte, 0, newCap)
	}
	start := len(b.backing)
	b.backing = b.backing[:start+sz]
	return b.backing[start : start+sz : start+sz]
}

func (b *SendBatch) Commit(pkt []byte, dst netip.AddrPort, outerECN byte) {
	b.bufs = append(b.bufs, pkt)
	b.dsts = append(b.dsts, dst)
	b.ecns = append(b.ecns, outerECN)
}

func (b *SendBatch) Flush() error {
	var err error
	if len(b.bufs) > 0 {
		err = b.out.WriteBatch(b.bufs, b.dsts, b.ecns)
	}
	clear(b.bufs)
	b.bufs = b.bufs[:0]
	b.dsts = b.dsts[:0]
	b.ecns = b.ecns[:0]
	b.backing = b.backing[:0]
	return err
}
