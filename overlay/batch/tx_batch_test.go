package batch

import (
	"net/netip"
	"testing"
)

type fakeBatchWriter struct {
	bufs  [][]byte
	addrs []netip.AddrPort
}

func (w *fakeBatchWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
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
		b.Commit(pkt, ap)
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
		b.Commit(pkt, ap)
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
	b.Commit(pkt1, ap)

	s2 := b.Reserve(8) // exceeds remaining cap, triggers grow
	pkt2 := append(s2[:0], 0xA, 0xB, 0xC, 0xD, 0xE)
	b.Commit(pkt2, ap)

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

type recordingBatchWriter struct {
	calls [][]byte
}

func (w *recordingBatchWriter) WriteBatch(bufs [][]byte, _ []netip.AddrPort) (int, error) {
	var run []byte
	for _, b := range bufs {
		run = append(run, b[0])
	}
	w.calls = append(w.calls, run)
	return len(bufs), nil
}

func TestSendBatchCommitPort(t *testing.T) {
	base := &recordingBatchWriter{}
	ports := map[uint16]*recordingBatchWriter{1: {}, 2: {}}
	b := NewSendBatch(base, 8, 0)
	b.SetPortWriter(func(port uint16) BatchWriter { return ports[port] })

	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	for i, port := range []uint16{0, 2, 1, 2, 0, 1} {
		b.CommitPort([]byte{byte(i)}, ap, port)
	}
	n, err := b.Flush()
	if err != nil || n != 6 {
		t.Fatalf("Flush: n=%d err=%v", n, err)
	}

	// Each port gets one WriteBatch holding its packets in commit order
	check := func(name string, w *recordingBatchWriter, want []byte) {
		t.Helper()
		if len(w.calls) != 1 || string(w.calls[0]) != string(want) {
			t.Errorf("%s: got %v want one call of %v", name, w.calls, want)
		}
	}
	check("base", base, []byte{0, 4})
	check("port 1", ports[1], []byte{2, 5})
	check("port 2", ports[2], []byte{1, 3})

	// The next flush without nonzero ports goes straight to the base writer
	base.calls = nil
	b.CommitPort([]byte{9}, ap, 0)
	b.Commit([]byte{10}, ap)
	if _, err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	check("base second flush", base, []byte{9, 10})
}

func TestSendBatchCommitPortAllocs(t *testing.T) {
	base := noopBatchWriter{}
	b := NewSendBatch(base, 128, 0)
	b.SetPortWriter(func(uint16) BatchWriter { return base })
	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	pkt := []byte{1}

	allocs := testing.AllocsPerRun(100, func() {
		for i := range 128 {
			b.CommitPort(pkt, ap, uint16(i%100))
		}
		_, _ = b.Flush()
	})
	if allocs != 0 {
		t.Fatalf("multiport flush allocated %v times per run", allocs)
	}
}

type noopBatchWriter struct{}

func (noopBatchWriter) WriteBatch(bufs [][]byte, _ []netip.AddrPort) (int, error) {
	return len(bufs), nil
}

func TestSendBatchCommitPortBackfillPastCap(t *testing.T) {
	base := &recordingBatchWriter{}
	other := &recordingBatchWriter{}
	b := NewSendBatch(base, 2, 0)
	b.SetPortWriter(func(uint16) BatchWriter { return other })

	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	// Commit past the batch cap on port 0 before the first nonzero port
	for i := range 3 {
		b.Commit([]byte{byte(i)}, ap)
	}
	b.CommitPort([]byte{3}, ap, 1)
	b.Commit([]byte{4}, ap)
	if n, err := b.Flush(); err != nil || n != 5 {
		t.Fatalf("Flush: n=%d err=%v", n, err)
	}
	if len(base.calls) != 1 || string(base.calls[0]) != string([]byte{0, 1, 2, 4}) {
		t.Errorf("base got %v", base.calls)
	}
	if len(other.calls) != 1 || string(other.calls[0]) != string([]byte{3}) {
		t.Errorf("port 1 got %v", other.calls)
	}
}

func TestSendBatchCommitPortOrders(t *testing.T) {
	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	tests := []struct {
		name  string
		ports []uint16
	}{
		// Every port in one run, sent straight from the batch
		{"grouped", []uint16{3, 3, 0, 0, 7, 9, 9}},
		// Ports split across runs and past 255, both radix passes
		{"scattered wide", []uint16{300, 5, 300, 256, 5, 0, 256, 300, 1, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writers := map[uint16]*recordingBatchWriter{0: {}}
			b := NewSendBatch(writers[0], 4, 0)
			b.SetPortWriter(func(port uint16) BatchWriter {
				if writers[port] == nil {
					writers[port] = &recordingBatchWriter{}
				}
				return writers[port]
			})

			want := map[uint16][]byte{}
			for i, port := range tt.ports {
				b.CommitPort([]byte{byte(i)}, ap, port)
				want[port] = append(want[port], byte(i))
			}
			if n, err := b.Flush(); err != nil || n != len(tt.ports) {
				t.Fatalf("Flush: n=%d err=%v", n, err)
			}
			for port, w := range writers {
				if len(w.calls) != 1 || string(w.calls[0]) != string(want[port]) {
					t.Errorf("port %d: got %v want one call of %v", port, w.calls, want[port])
				}
			}
			if len(writers) != len(want) {
				t.Errorf("wrote to %d ports, want %d", len(writers), len(want))
			}
		})
	}
}
