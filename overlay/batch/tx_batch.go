package batch

import "net/netip"

const SendBatchCap = 128

// batchWriter is the minimal subset of udp.Conn needed by SendBatch to flush.
type batchWriter interface {
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error)
}

// SendBatch accumulates encrypted UDP packets and flushes them via WriteBatch.
// Each reader goroutine owns its own SendBatch; no locking is needed.
// Slots can borrow receive buffers or be backed by an Arena (see its docs).
type SendBatch struct {
	out   batchWriter
	bufs  [][]byte
	dsts  []netip.AddrPort
	arena *Arena

	// ports sends packets committed with CommitPort from their multiport send port, see tx_batch_ports.go
	ports sendPorts
}

// NewSendBatch makes a SendBatch with batchCap slots and an arenaSize byte buffer for slices to back those slots
func NewSendBatch(out batchWriter, batchCap, arenaSize int) *SendBatch {
	return &SendBatch{
		out:   out,
		bufs:  make([][]byte, 0, batchCap),
		dsts:  make([]netip.AddrPort, 0, batchCap),
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

func (b *SendBatch) Commit(pkt []byte, dst netip.AddrPort) {
	b.bufs = append(b.bufs, pkt)
	b.dsts = append(b.dsts, dst)
	if b.ports.mixed {
		b.addRun(0)
	}
}

// Flush writes every queued packet and reports how many actually went out. A short count means some destinations
// were undeliverable; the batch is drained either way.
func (b *SendBatch) Flush() (int, error) {
	var err error
	written := 0
	if b.ports.mixed {
		written, err = b.flushPorts()
	} else if len(b.bufs) > 0 {
		written, err = b.out.WriteBatch(b.bufs, b.dsts)
	}
	clear(b.bufs)
	b.bufs = b.bufs[:0]
	b.dsts = b.dsts[:0]
	b.ports.reset()
	b.arena.Reset()
	return written, err
}
