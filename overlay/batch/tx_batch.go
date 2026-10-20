package batch

import "net/netip"

const SendBatchCap = 128

// FailureHeadLen is how much of a refused packet a Failure keeps, nebula's header, which says whose packet it was
const FailureHeadLen = 16

// batchWriter is the minimal subset of udp.Conn needed by SendBatch to flush.
type batchWriter interface {
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort, failed func(i int, err error)) (int, error)
}

// Failure is a packet the underlay would not send
type Failure struct {
	// Head is the start of the packet, zero padded if the packet was shorter
	Head [FailureHeadLen]byte
	Dst  netip.AddrPort
	Err  error
}

// SendBatch accumulates encrypted UDP packets and flushes them via WriteBatch.
// Each reader goroutine owns its own SendBatch; no locking is needed.
// Slots can borrow receive buffers or be backed by an Arena (see its docs).
type SendBatch struct {
	out   batchWriter
	bufs  [][]byte
	dsts  []netip.AddrPort
	arena *Arena

	failures []Failure
	// recordFailure is bound once so handing it to WriteBatch does not allocate on every Flush
	recordFailure func(i int, err error)
}

// NewSendBatch makes a SendBatch with batchCap slots and an arenaSize byte buffer for slices to back those slots
func NewSendBatch(out batchWriter, batchCap, arenaSize int) *SendBatch {
	b := &SendBatch{
		out:   out,
		bufs:  make([][]byte, 0, batchCap),
		dsts:  make([]netip.AddrPort, 0, batchCap),
		arena: NewArena(arenaSize),
	}
	b.recordFailure = b.failed
	return b
}

func (b *SendBatch) failed(i int, err error) {
	f := Failure{Dst: b.dsts[i], Err: err}
	copy(f.Head[:], b.bufs[i])
	b.failures = append(b.failures, f)
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
// were undeliverable, Failures says which; the batch is drained either way.
func (b *SendBatch) Flush() (int, error) {
	clear(b.failures)
	b.failures = b.failures[:0]

	var err error
	written := 0
	if len(b.bufs) > 0 {
		written, err = b.out.WriteBatch(b.bufs, b.dsts, b.recordFailure)
	}
	clear(b.bufs)
	b.bufs = b.bufs[:0]
	b.dsts = b.dsts[:0]
	b.arena.Reset()
	return written, err
}

// Failures returns every packet the last Flush could not send, in the order they were committed. Valid until the
// next Flush.
func (b *SendBatch) Failures() []Failure {
	return b.failures
}
