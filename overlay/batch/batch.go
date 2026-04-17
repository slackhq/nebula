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
	// Next returns a zero-length slice with slotCap capacity over the next unused
	// slot's backing bytes. The caller writes into the returned slice and then
	// calls Commit with the final length and destination. Next returns nil when
	// the batch is full.
	Next() []byte
	// Commit records the slot just returned by Next as a packet of length n
	// destined for dst.
	Commit(n int, dst netip.AddrPort)
	// Reset clears committed slots; backing storage is retained for reuse.
	Reset()
	// Len returns the number of committed packets.
	Len() int
	// Cap returns the maximum number of slots in the batch.
	Cap() int
	// Get returns the buffers needed to send the batch
	Get() ([][]byte, []netip.AddrPort)
}
