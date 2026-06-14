package pq

// Wipe best-effort zeroes key material we control. Go gives no
// guaranteed secure erase (the GC may have copied the backing array),
// but zeroing our reachable copies still shrinks the window in which
// a heap dump or swap page contains live PSKs. Long-lived provider
// snapshots are intentionally NOT wiped — they are the working set
// for future handshakes; the boundary is documented in the operator
// guide.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
