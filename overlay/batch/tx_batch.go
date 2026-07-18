package batch

import "net/netip"

const SendBatchCap = 128

// batchWriter is the minimal subset of udp.Conn needed by SendBatch to flush.
type batchWriter interface {
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort, outerECNs []byte) error
}

// SendBatch accumulates encrypted UDP packets and flushes them via WriteBatch.
// One SendBatch is owned by each listenIn goroutine; no locking is needed.
// Slots are backed by an Arena (see its docs)
type SendBatch struct {
	out   batchWriter
	bufs  [][]byte
	dsts  []netip.AddrPort
	ecns  []byte
	arena *Arena
}

// NewSendBatch makes a SendBatch with batchCap slots and an arenaSize byte buffer for slices to back those slots
func NewSendBatch(out batchWriter, batchCap, arenaSize int) *SendBatch {
	return &SendBatch{
		out:   out,
		bufs:  make([][]byte, 0, batchCap),
		dsts:  make([]netip.AddrPort, 0, batchCap),
		ecns:  make([]byte, 0, batchCap),
		arena: NewArena(arenaSize),
	}
}

func (b *SendBatch) Reserve(sz int) []byte {
	return b.arena.Reserve(sz)
}

// Len reports how many packets are queued for the next Flush. Callers use
// it to flush incrementally once a full sendmmsg batch has accumulated,
// bounding how long the first packet of a large read batch waits.
func (b *SendBatch) Len() int { return len(b.bufs) }

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
	b.arena.Reset()
	return err
}
