package batch

import (
	"net/netip"
	"testing"
)

func TestSendBatchBookkeeping(t *testing.T) {
	b := NewSendBatch(4, 32)
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

func TestSendBatchSlotsDoNotOverlap(t *testing.T) {
	b := NewSendBatch(3, 8)
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
