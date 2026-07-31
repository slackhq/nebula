package batch

import "net/netip"

type RxBatcher interface {
	// Commit commits pkt to be flushed by the batch. The caller must keep pkt valid until the next Flush, and not re-use it.
	Commit(pkt []byte) error
	// Flush emits every queued packet. The guarantee is per-flow DATA order:
	// a flow's payload-bearing packets are never reordered relative to each
	// other. Cross-flow and cross-lane order is not preserved, and two shapes
	// may legally be overtaken by later same-flow data: pure ACKs (by design,
	// stale ACKs are ignored) and unparseable shapes such as fragments (an
	// accepted tradeoff; see MultiCoalescer).
	// Returns the first error observed; keeps draining so one bad packet doesn't hold up the rest.
	// After Flush returns, committed payload slices may be recycled.
	Flush() error
}

type TxBatcher interface {
	// Reserve creates a pkt to borrow
	Reserve(sz int) []byte
	// Commit borrows pkt and records its destination. The caller must
	// keep pkt valid until the next Flush.
	Commit(pkt []byte, dst netip.AddrPort)
	// Flush emits every queued packet via the underlying batch writer in arrival order and reports how many were
	// actually written. A short count means some destinations were undeliverable, not that the batch failed.
	// After Flush returns, borrowed payload slices may be recycled.
	Flush() (int, error)
}
