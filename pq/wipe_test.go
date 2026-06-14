package pq

import "testing"

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
	Wipe(nil) // must not panic
}
