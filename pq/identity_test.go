package pq

import "testing"

func TestNoopIdentityCodec(t *testing.T) {
	var c IdentityCodec = NoopIdentityCodec{}
	if got := c.Encode(nil, 0, 0); got != nil {
		t.Fatalf("Noop Encode = %v, want nil", got)
	}
	// Decode of anything is a no-op that must report ok=false and not panic.
	hash, a, b, ok := c.Decode([]byte{1, 2, 3})
	if ok || hash != nil || a != 0 || b != 0 {
		t.Fatalf("Noop Decode = (%v, %d, %d, %v), want (nil, 0, 0, false)", hash, a, b, ok)
	}
}
