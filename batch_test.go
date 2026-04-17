package nebula

import (
	"net/netip"
	"testing"
)

func TestSendBatchBookkeeping(t *testing.T) {
	b := newSendBatch(4, 32)
	if b.Len() != 0 || b.Cap() != 4 {
		t.Fatalf("fresh batch: len=%d cap=%d", b.Len(), b.Cap())
	}

	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	for i := 0; i < 4; i++ {
		slot := b.Next()
		if slot == nil {
			t.Fatalf("slot %d: Next returned nil before cap", i)
		}
		if cap(slot) != 32 || len(slot) != 0 {
			t.Fatalf("slot %d: got len=%d cap=%d want len=0 cap=32", i, len(slot), cap(slot))
		}
		// Write a marker byte.
		slot = append(slot, byte(i), byte(i+1), byte(i+2))
		b.Commit(len(slot), ap)
	}
	if b.Next() != nil {
		t.Fatalf("Next should return nil when full")
	}
	if b.Len() != 4 {
		t.Fatalf("Len=%d want 4", b.Len())
	}
	for i, buf := range b.bufs {
		if len(buf) != 3 || buf[0] != byte(i) {
			t.Errorf("buf %d: %x", i, buf)
		}
		if b.dsts[i] != ap {
			t.Errorf("dst %d: got %v want %v", i, b.dsts[i], ap)
		}
	}

	// Reset returns empty and Next works again.
	b.Reset()
	if b.Len() != 0 {
		t.Fatalf("after Reset Len=%d want 0", b.Len())
	}
	slot := b.Next()
	if slot == nil || cap(slot) != 32 {
		t.Fatalf("after Reset Next nil or wrong cap: %v cap=%d", slot == nil, cap(slot))
	}
}

func TestBatchSegmentable(t *testing.T) {
	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	other := netip.MustParseAddrPort("10.0.0.2:4242")

	mk := func(addrs []netip.AddrPort, sizes []int) *sendBatch {
		b := newSendBatch(len(addrs), 64)
		for i, a := range addrs {
			s := b.Next()
			for j := 0; j < sizes[i]; j++ {
				s = append(s, byte(j))
			}
			b.Commit(len(s), a)
		}
		return b
	}

	t.Run("uniform same dst", func(t *testing.T) {
		b := mk([]netip.AddrPort{ap, ap, ap}, []int{10, 10, 10})
		seg, ok := batchSegmentable(b)
		if !ok || seg != 10 {
			t.Fatalf("got seg=%d ok=%v", seg, ok)
		}
	})

	t.Run("last segment short ok", func(t *testing.T) {
		b := mk([]netip.AddrPort{ap, ap, ap}, []int{10, 10, 4})
		seg, ok := batchSegmentable(b)
		if !ok || seg != 10 {
			t.Fatalf("got seg=%d ok=%v", seg, ok)
		}
	})

	t.Run("mixed dst rejected", func(t *testing.T) {
		b := mk([]netip.AddrPort{ap, other, ap}, []int{10, 10, 10})
		if _, ok := batchSegmentable(b); ok {
			t.Fatalf("expected rejection for mixed dst")
		}
	})

	t.Run("mid-batch short rejected", func(t *testing.T) {
		b := mk([]netip.AddrPort{ap, ap, ap}, []int{10, 4, 10})
		if _, ok := batchSegmentable(b); ok {
			t.Fatalf("expected rejection for short mid-batch")
		}
	})

	t.Run("mid-batch longer rejected", func(t *testing.T) {
		b := mk([]netip.AddrPort{ap, ap, ap}, []int{10, 11, 10})
		if _, ok := batchSegmentable(b); ok {
			t.Fatalf("expected rejection for longer mid-batch")
		}
	})

	t.Run("last longer rejected", func(t *testing.T) {
		b := mk([]netip.AddrPort{ap, ap, ap}, []int{10, 10, 11})
		if _, ok := batchSegmentable(b); ok {
			t.Fatalf("expected rejection for longer last segment")
		}
	})

	t.Run("first zero rejected", func(t *testing.T) {
		b := mk([]netip.AddrPort{ap, ap}, []int{0, 10})
		if _, ok := batchSegmentable(b); ok {
			t.Fatalf("expected rejection for zero first")
		}
	})
}

func TestSendBatchSlotsDoNotOverlap(t *testing.T) {
	b := newSendBatch(3, 8)
	ap := netip.MustParseAddrPort("10.0.0.1:80")

	// Fill three slots, each with its own sentinel byte.
	for i := 0; i < 3; i++ {
		s := b.Next()
		s = append(s, byte(0xA0+i), byte(0xB0+i))
		b.Commit(len(s), ap)
	}

	for i, buf := range b.bufs {
		if buf[0] != byte(0xA0+i) || buf[1] != byte(0xB0+i) {
			t.Errorf("slot %d corrupted: %x", i, buf)
		}
	}
}
