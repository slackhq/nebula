package batch

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

type fakeBatchWriter struct {
	bufs  [][]byte
	addrs []netip.AddrPort
}

func (w *fakeBatchWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort, _ func(int, error)) (int, error) {
	// Snapshot — SendBatch.Flush nils its slot pointers right after WriteBatch
	// returns, so tests must capture data before that happens.
	w.bufs = make([][]byte, len(bufs))
	for i, b := range bufs {
		cp := make([]byte, len(b))
		copy(cp, b)
		w.bufs[i] = cp
	}
	w.addrs = append(w.addrs[:0], addrs...)
	return len(bufs), nil
}

func TestSendBatchReserveCommitFlush(t *testing.T) {
	fw := &fakeBatchWriter{}
	b := NewSendBatch(fw, 4, 32)

	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	for i := range 4 {
		slot := b.Reserve(32)
		if cap(slot) != 32 {
			t.Fatalf("slot %d: cap=%d want 32", i, cap(slot))
		}
		pkt := append(slot[:0], byte(i), byte(i+1), byte(i+2))
		b.Commit(pkt, ap, 0)
	}
	if _, err := b.Flush(); err != nil {
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
	if _, err := b.Flush(); err != nil {
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

	for i := range 3 {
		s := b.Reserve(8)
		pkt := append(s[:0], byte(0xA0+i), byte(0xB0+i))
		b.Commit(pkt, ap, 0)
	}
	if _, err := b.Flush(); err != nil {
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

	if _, err := b.Flush(); err != nil {
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

// failingBatchWriter refuses every packet whose first byte is in refuse
type failingBatchWriter struct {
	refuse map[byte]error
}

func (w *failingBatchWriter) WriteBatch(bufs [][]byte, _ []netip.AddrPort, failed func(int, error)) (int, error) {
	written := 0
	for i, b := range bufs {
		if err, ok := w.refuse[b[0]]; ok {
			failed(i, err)
			continue
		}
		written++
	}
	return written, nil
}

func TestSendBatchReportsFailedTags(t *testing.T) {
	errNoRoute := errors.New("no route")
	fw := &failingBatchWriter{refuse: map[byte]error{2: errNoRoute, 3: errNoRoute}}

	b := NewSendBatch(fw, 4, 64)

	dsts := []netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.1:4242"),
		netip.MustParseAddrPort("[fd00::2]:4242"),
		netip.MustParseAddrPort("[fd00::3]:4242"),
		netip.MustParseAddrPort("10.0.0.4:4242"),
	}
	for i, dst := range dsts {
		pkt := append(b.Reserve(8)[:0], byte(i+1))
		b.Commit(pkt, dst, uint32(100+i))
	}

	written, err := b.Flush()
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if written != 2 {
		t.Errorf("written = %d, want 2", written)
	}
	want := []Failure{{101, dsts[1], errNoRoute}, {102, dsts[2], errNoRoute}}
	if got := b.Failures(); !slices.Equal(got, want) {
		t.Errorf("failures = %v, want %v", got, want)
	}

	// Tags do not leak into the next flush
	b.Commit(append(b.Reserve(8)[:0], 2), dsts[0], 7)
	if _, err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if want := []Failure{{7, dsts[0], errNoRoute}}; !slices.Equal(b.Failures(), want) {
		t.Errorf("second flush failures = %v, want %v", b.Failures(), want)
	}

	// A clean flush forgets the last one's failures
	b.Commit(append(b.Reserve(8)[:0], 1), dsts[0], 8)
	if _, err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := b.Failures(); len(got) != 0 {
		t.Errorf("clean flush failures = %v, want none", got)
	}
}
