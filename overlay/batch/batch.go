package batch

import "net/netip"

type RxBatcher interface {
	// Reserve creates a pkt to borrow
	Reserve(sz int) []byte
	// Commit borrows pkt. The caller must keep pkt valid until the next Flush.
	// Walks IP+L4 headers itself; prefer CommitInbound when the caller already
	// has an RxParsed in hand from ParsePacket.
	Commit(pkt []byte) error
	// CommitInbound is Commit with a hint produced by ParsePacket, so the
	// batcher can skip the IP+L4 re-parse. Borrowed slice contract is the
	// same as Commit. Implementations that don't coalesce may delegate to
	// Commit.
	CommitInbound(pkt []byte, parsed *RxParsed) error
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
	// arrival order. Returns an errors.Join of one or more errors. After Flush returns,
	// borrowed payload slices may be recycled.
	Flush() error
}
