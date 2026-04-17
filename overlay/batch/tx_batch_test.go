package batch

import (
	"net/netip"
	"testing"
)

type fakeBatchWriter struct {
	bufs  [][]byte
	addrs []netip.AddrPort
	ecns  []byte
}

func (w *fakeBatchWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort, ecns []byte) error {
	// Snapshot — SendBatch.Flush nils its slot pointers right after WriteBatch
	// returns, so tests must capture data before that happens.
	w.bufs = make([][]byte, len(bufs))
	for i, b := range bufs {
		cp := make([]byte, len(b))
		copy(cp, b)
		w.bufs[i] = cp
	}
	w.addrs = append(w.addrs[:0], addrs...)
	w.ecns = append(w.ecns[:0], ecns...)
	return nil
}

func TestSendBatchReserveCommitFlush(t *testing.T) {
	fw := &fakeBatchWriter{}
	b := NewSendBatch(fw, 4, 32)

	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	for i := 0; i < 4; i++ {
		slot := b.Reserve(32)
		if cap(slot) != 32 {
			t.Fatalf("slot %d: cap=%d want 32", i, cap(slot))
		}
		pkt := append(slot[:0], byte(i), byte(i+1), byte(i+2))
		b.Commit(pkt, ap, 0)
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(fw.bufs) != 4 {
		t.Fatalf("WriteBatch got %d bufs want 4", len(fw.bufs))
	}
	for i, buf := range fw.bufs {
		if len(buf) != 3 || buf[0] != byte(i) {
			t.Errorf("buf %d: %x", i, buf)
		}
		if fw.addrs[i] != ap {
			t.Errorf("addr %d: got %v want %v", i, fw.addrs[i], ap)
		}
	}

	// Flush again with nothing committed — should be a no-op.
	fw.bufs = nil
	if err := b.Flush(); err != nil {
		t.Fatalf("empty Flush: %v", err)
	}
	if fw.bufs != nil {
		t.Fatalf("empty Flush triggered WriteBatch")
	}

	// Reuse after Flush.
	slot := b.Reserve(32)
	if cap(slot) != 32 {
		t.Fatalf("after Flush Reserve wrong cap: %d", cap(slot))
	}
}

func TestSendBatchSlotsDoNotOverlap(t *testing.T) {
	fw := &fakeBatchWriter{}
	b := NewSendBatch(fw, 3, 8)
	ap := netip.MustParseAddrPort("10.0.0.1:80")

	for i := 0; i < 3; i++ {
		s := b.Reserve(8)
		pkt := append(s[:0], byte(0xA0+i), byte(0xB0+i))
		b.Commit(pkt, ap, 0)
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	for i, buf := range fw.bufs {
		if buf[0] != byte(0xA0+i) || buf[1] != byte(0xB0+i) {
			t.Errorf("slot %d corrupted: %x", i, buf)
		}
	}
}

func TestSendBatchGrowPreservesCommitted(t *testing.T) {
	fw := &fakeBatchWriter{}
	// Tiny initial backing forces a grow on the second Reserve.
	b := NewSendBatch(fw, 1, 4)
	ap := netip.MustParseAddrPort("10.0.0.1:80")

	s1 := b.Reserve(4)
	pkt1 := append(s1[:0], 0x11, 0x22, 0x33, 0x44)
	b.Commit(pkt1, ap, 0)

	s2 := b.Reserve(8) // exceeds remaining cap, triggers grow
	pkt2 := append(s2[:0], 0xA, 0xB, 0xC, 0xD, 0xE)
	b.Commit(pkt2, ap, 0)

	// pkt1 must still be intact even though backing reallocated.
	if pkt1[0] != 0x11 || pkt1[3] != 0x44 {
		t.Fatalf("first packet corrupted by grow: %x", pkt1)
	}

	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(fw.bufs) != 2 {
		t.Fatalf("got %d bufs want 2", len(fw.bufs))
	}
	if fw.bufs[0][0] != 0x11 || fw.bufs[0][3] != 0x44 {
		t.Errorf("first packet on the wire: %x", fw.bufs[0])
	}
	if fw.bufs[1][0] != 0xA || fw.bufs[1][4] != 0xE {
		t.Errorf("second packet on the wire: %x", fw.bufs[1])
	}
}
