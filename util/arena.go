package util

// Arena is an injectable byte-slab that hands out non-overlapping borrowed
// slices via Reserve and releases them in bulk via Reset.
//
// Arena is not safe for concurrent use.
//
// Reserve borrows; the slice is valid until the next Reset. The slab grows
// (by allocating a fresh, larger backing array) if a Reserve doesn't fit;
// pre-size the arena via NewArena to avoid that path on the hot path.
type Arena struct {
	buf []byte
}

// NewArena returns an Arena with a pre-allocated backing of the given capacity
func NewArena(capacity int) *Arena {
	return &Arena{buf: make([]byte, 0, capacity)}
}

// Reserve hands out a non-overlapping sz-byte slice from the arena. If the
// request doesn't fit the current backing, a fresh, larger backing is
// allocated; already-borrowed slices reference the old backing and remain
// valid until Reset.
func (a *Arena) Reserve(sz int) []byte {
	if len(a.buf)+sz > cap(a.buf) {
		newCap := max(cap(a.buf)*2, sz)
		a.buf = make([]byte, 0, newCap)
	}
	start := len(a.buf)
	a.buf = a.buf[:start+sz]
	return a.buf[start : start+sz : start+sz]
}

// Reset releases every slice handed out since the last Reset. Callers must
// not use any previously-borrowed slice after this returns. The underlying
// backing array is retained so subsequent Reserves don't re-allocate.
func (a *Arena) Reset() {
	a.buf = a.buf[:0]
}
