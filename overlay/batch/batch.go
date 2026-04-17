package batch

import "net/netip"

type RxBatcher interface {
	// Reserve creates a pkt to borrow
	Reserve(sz int) []byte
	// Commit borrows pkt. The caller must keep pkt valid until the next Flush
	Commit(pkt []byte) error
	// Flush emits every queued packet in arrival order. Returns the
	// first error observed; keeps draining so one bad packet doesn't hold up
	// the rest. After Flush returns, borrowed payload slices may be recycled.
	Flush() error
}

type TxBatcher interface {
	// Reserve creates a pkt to borrow
	Reserve(sz int) []byte
	// Commit borrows pkt and records its destination plus the 2-bit
	// IP-level ECN codepoint to set on the outer (carrier) header. The
	// caller must keep pkt valid until the next Flush. Pass 0 (Not-ECT)
	// to leave the outer ECN field unset.
	Commit(pkt []byte, dst netip.AddrPort, outerECN byte)
	// Flush emits every queued packet via the underlying batch writer in
	// arrival order. Returns the first error observed. After Flush returns,
	// borrowed payload slices may be recycled.
	Flush() error
}
