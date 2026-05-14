package batch

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
