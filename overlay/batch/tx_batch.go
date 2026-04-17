package batch

import (
	"net/netip"

	"github.com/slackhq/nebula/udp"
)

const SendBatchCap = 128

// DefaultSendBatchArenaCap is the recommended arena capacity for a
// standalone SendBatch: 128 slots × (udp.MTU + 32) ≈ 1.1 MiB. The +32 covers
// the nebula header + AEAD tag tacked onto each plaintext segment.
const DefaultSendBatchArenaCap = SendBatchCap * (udp.MTU + 32)

// batchWriter is the minimal subset of udp.Conn needed by SendBatch to flush.
type batchWriter interface {
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort, outerECNs []byte) error
}

// SendBatch accumulates encrypted UDP packets and flushes them via WriteBatch.
// One SendBatch is owned by each listenIn goroutine; no locking is needed.
// Slot bytes are borrowed from the injected Arena and remain valid until
// Flush, which Resets the arena.
type SendBatch struct {
	out   batchWriter
	bufs  [][]byte
	dsts  []netip.AddrPort
	ecns  []byte
	arena *Arena
}

// NewSendBatch makes a SendBatch with batchCap slots backed by arena.
func NewSendBatch(out batchWriter, batchCap int, arena *Arena) *SendBatch {
	return &SendBatch{
		out:   out,
		bufs:  make([][]byte, 0, batchCap),
		dsts:  make([]netip.AddrPort, 0, batchCap),
		ecns:  make([]byte, 0, batchCap),
		arena: arena,
	}
}

func (b *SendBatch) Reserve(sz int) []byte {
	return b.arena.Reserve(sz)
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
	b.arena.Reset()
	return err
}
