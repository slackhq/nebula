//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// makeNebulaPkt returns a buffer whose [8:16] bytes encode the given
// counter big-endian, the rest left zero. Anything shorter than 16 bytes
// would yield counter 0; tests use this to simulate well-formed nebula
// headers (the rxReorderBuffer doesn't care about anything else).
func makeNebulaPkt(cnt uint64, payLen int) []byte {
	if payLen < 16 {
		payLen = 16
	}
	b := make([]byte, payLen)
	binary.BigEndian.PutUint64(b[8:16], cnt)
	return b
}

func srcOf(addr string, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(addr), port)
}

func TestRxReorderBuffer_LonePassesThrough(t *testing.T) {
	r := newRxReorderBuffer(8)
	pkt := makeNebulaPkt(42, 100)
	r.addEntry(srcOf("1.1.1.1", 4242), pkt, 0, 0x02)

	if got := len(r.buf); got != 1 {
		t.Fatalf("want 1 entry, got %d", got)
	}
	if r.buf[0].cnt != 42 {
		t.Errorf("counter=%d want 42", r.buf[0].cnt)
	}
	if r.buf[0].ecn != 0x02 {
		t.Errorf("ecn=%#x want 0x02", r.buf[0].ecn)
	}
	if len(r.buf[0].buf) != 100 {
		t.Errorf("buf len=%d want 100", len(r.buf[0].buf))
	}
}

func TestRxReorderBuffer_SegSizeGEPayloadIsLone(t *testing.T) {
	// segSize >= len(payload) means the kernel did not coalesce this slot.
	r := newRxReorderBuffer(8)
	pkt := makeNebulaPkt(7, 50)
	r.addEntry(srcOf("1.1.1.1", 1), pkt, 50, 0)
	if got := len(r.buf); got != 1 {
		t.Fatalf("segSize==len: want 1 entry, got %d", got)
	}
	r.reset()
	r.addEntry(srcOf("1.1.1.1", 1), pkt, 60, 0)
	if got := len(r.buf); got != 1 {
		t.Fatalf("segSize>len: want 1 entry, got %d", got)
	}
}

func TestRxReorderBuffer_GROSplitExactMultiple(t *testing.T) {
	// 3 segments of 80 bytes each, packed into one 240-byte GRO superpacket.
	const segSize = 80
	const numSeg = 3
	pkt := make([]byte, segSize*numSeg)
	for i := range numSeg {
		off := i * segSize
		binary.BigEndian.PutUint64(pkt[off+8:off+16], uint64(100+i))
	}

	r := newRxReorderBuffer(8)
	r.addEntry(srcOf("2.2.2.2", 5555), pkt, segSize, 0x03)
	if got := len(r.buf); got != numSeg {
		t.Fatalf("want %d segments, got %d", numSeg, got)
	}
	for i, seg := range r.buf {
		if seg.cnt != uint64(100+i) {
			t.Errorf("seg %d: cnt=%d want %d", i, seg.cnt, 100+i)
		}
		if len(seg.buf) != segSize {
			t.Errorf("seg %d: buf len=%d want %d", i, len(seg.buf), segSize)
		}
		if seg.ecn != 0x03 {
			t.Errorf("seg %d: ecn=%#x want 0x03 (uniform across GRO)", i, seg.ecn)
		}
	}
}

func TestRxReorderBuffer_GROSplitShortFinal(t *testing.T) {
	// 200-byte payload, segSize=80 → segments of 80, 80, 40.
	const segSize = 80
	pkt := make([]byte, 200)
	binary.BigEndian.PutUint64(pkt[8:16], 1)
	binary.BigEndian.PutUint64(pkt[80+8:80+16], 2)
	binary.BigEndian.PutUint64(pkt[160+8:160+16], 3)

	r := newRxReorderBuffer(8)
	r.addEntry(srcOf("3.3.3.3", 1), pkt, segSize, 0)
	if got := len(r.buf); got != 3 {
		t.Fatalf("want 3 segments, got %d", got)
	}
	wantLens := []int{80, 80, 40}
	for i, seg := range r.buf {
		if len(seg.buf) != wantLens[i] {
			t.Errorf("seg %d: len=%d want %d", i, len(seg.buf), wantLens[i])
		}
	}
}

func TestRxReorderBuffer_SortGroupsBySrcThenCounter(t *testing.T) {
	r := newRxReorderBuffer(8)
	a := srcOf("1.1.1.1", 1)
	b := srcOf("2.2.2.2", 1)
	// Insert deliberately scrambled.
	r.addEntry(a, makeNebulaPkt(3, 16), 0, 0)
	r.addEntry(b, makeNebulaPkt(1, 16), 0, 0)
	r.addEntry(a, makeNebulaPkt(1, 16), 0, 0)
	r.addEntry(b, makeNebulaPkt(2, 16), 0, 0)
	r.addEntry(a, makeNebulaPkt(2, 16), 0, 0)

	r.sortStable()

	want := []struct {
		src netip.AddrPort
		cnt uint64
	}{
		{a, 1}, {a, 2}, {a, 3}, {b, 1}, {b, 2},
	}
	if got := len(r.buf); got != len(want) {
		t.Fatalf("len=%d want %d", got, len(want))
	}
	for i, w := range want {
		if r.buf[i].src != w.src || r.buf[i].cnt != w.cnt {
			t.Errorf("idx %d: got %v/%d want %v/%d",
				i, r.buf[i].src, r.buf[i].cnt, w.src, w.cnt)
		}
	}
}

func TestRxReorderBuffer_SortStableAcrossPorts(t *testing.T) {
	// Same source addr but different ports — must group by port.
	r := newRxReorderBuffer(8)
	addr := netip.MustParseAddr("4.4.4.4")
	p1 := netip.AddrPortFrom(addr, 1)
	p2 := netip.AddrPortFrom(addr, 2)
	r.addEntry(p2, makeNebulaPkt(10, 16), 0, 0)
	r.addEntry(p1, makeNebulaPkt(20, 16), 0, 0)
	r.addEntry(p2, makeNebulaPkt(5, 16), 0, 0)

	r.sortStable()

	// Expect: p1/20 then p2/5 then p2/10.
	if r.buf[0].src.Port() != 1 || r.buf[1].src.Port() != 2 || r.buf[2].src.Port() != 2 {
		t.Fatalf("port order broken: %v %v %v",
			r.buf[0].src.Port(), r.buf[1].src.Port(), r.buf[2].src.Port())
	}
	if r.buf[1].cnt != 5 || r.buf[2].cnt != 10 {
		t.Errorf("counter order in p2: %d %d (want 5 10)", r.buf[1].cnt, r.buf[2].cnt)
	}
}

func TestRxReorderBuffer_DeliverInOrderAndNilsRefs(t *testing.T) {
	r := newRxReorderBuffer(4)
	a := srcOf("5.5.5.5", 1)
	r.addEntry(a, makeNebulaPkt(2, 32), 0, 0x01)
	r.addEntry(a, makeNebulaPkt(1, 32), 0, 0x01)
	r.sortStable()

	var seenCnts []uint64
	var seenECN []byte
	r.deliver(func(src netip.AddrPort, buf []byte, meta RxMeta) {
		seenCnts = append(seenCnts, binary.BigEndian.Uint64(buf[8:16]))
		seenECN = append(seenECN, meta.OuterECN)
	})

	if len(seenCnts) != 2 || seenCnts[0] != 1 || seenCnts[1] != 2 {
		t.Errorf("delivery order broken: %v", seenCnts)
	}
	if seenECN[0] != 0x01 || seenECN[1] != 0x01 {
		t.Errorf("ecn passed wrong: %v", seenECN)
	}
	for i := range r.buf {
		if r.buf[i].buf != nil {
			t.Errorf("buf[%d].buf not nil after deliver", i)
		}
	}
}

func TestRxReorderBuffer_ResetIsReusable(t *testing.T) {
	r := newRxReorderBuffer(2)
	r.addEntry(srcOf("6.6.6.6", 1), makeNebulaPkt(1, 16), 0, 0)
	r.addEntry(srcOf("6.6.6.6", 1), makeNebulaPkt(2, 16), 0, 0)
	r.reset()
	if got := len(r.buf); got != 0 {
		t.Fatalf("after reset len=%d want 0", got)
	}
	r.addEntry(srcOf("6.6.6.6", 1), makeNebulaPkt(7, 16), 0, 0)
	if r.buf[0].cnt != 7 {
		t.Errorf("after reset+add: cnt=%d want 7", r.buf[0].cnt)
	}
}
