package nebula

import (
	"encoding/binary"
	"testing"
)

// A minimal stub writer that records each plain Write and each WriteGSO
// call without touching a real TUN fd.
type fakeTunWriter struct {
	gsoEnabled bool
	writes     [][]byte
	gsoWrites  []fakeGSOWrite
}

type fakeGSOWrite struct {
	pkt       []byte
	gsoSize   uint16
	isV6      bool
	hdrLen    uint16
	csumStart uint16
}

func (w *fakeTunWriter) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	w.writes = append(w.writes, buf)
	return len(p), nil
}

func (w *fakeTunWriter) WriteGSO(pkt []byte, gsoSize uint16, isV6 bool, hdrLen, csumStart uint16) error {
	buf := make([]byte, len(pkt))
	copy(buf, pkt)
	w.gsoWrites = append(w.gsoWrites, fakeGSOWrite{pkt: buf, gsoSize: gsoSize, isV6: isV6, hdrLen: hdrLen, csumStart: csumStart})
	return nil
}

func (w *fakeTunWriter) GSOSupported() bool { return w.gsoEnabled }

// buildTCPv4 constructs a minimal IPv4+TCP packet with the given payload,
// seq, and flags. Assumes no IP options and a 20-byte TCP header.
func buildTCPv4(seq uint32, flags byte, payload []byte) []byte {
	const ipHdrLen = 20
	const tcpHdrLen = 20
	total := ipHdrLen + tcpHdrLen + len(payload)
	pkt := make([]byte, total)

	// IPv4 header.
	pkt[0] = 0x45 // version 4, IHL 5
	pkt[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], 0)      // id
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = 64                                  // TTL
	pkt[9] = ipProtoTCP
	// csum left zero — coalescer recomputes on emit.
	copy(pkt[12:16], []byte{10, 0, 0, 1}) // src
	copy(pkt[16:20], []byte{10, 0, 0, 2}) // dst

	// TCP header.
	binary.BigEndian.PutUint16(pkt[20:22], 1000) // sport
	binary.BigEndian.PutUint16(pkt[22:24], 2000) // dport
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	binary.BigEndian.PutUint32(pkt[28:32], 12345) // ack
	pkt[32] = 0x50                                // data offset = 5 << 4
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 0xffff) // window
	// tcp csum zero
	// urgent zero

	copy(pkt[40:], payload)
	return pkt
}

const (
	tcpAck    = 0x10
	tcpPsh    = 0x08
	tcpSyn    = 0x02
	tcpFin    = 0x01
	tcpAckPsh = tcpAck | tcpPsh
)

func TestCoalescerPassthroughWhenGSOUnavailable(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: false}
	c := newTCPCoalescer(w)
	pkt := buildTCPv4(1000, tcpAck, []byte("hello"))
	if err := c.Add(pkt); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("want single plain write, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerNonTCPPassthrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	// ICMP packet: proto=1.
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[9] = 1
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	if err := c.Add(pkt); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("ICMP should pass through unchanged")
	}
}

func TestCoalescerSeedThenFlushAlone(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	pkt := buildTCPv4(1000, tcpAck, make([]byte, 1000))
	if err := c.Add(pkt); err != nil {
		t.Fatal(err)
	}
	// No flush yet — still pending.
	if len(w.writes) != 0 || len(w.gsoWrites) != 0 {
		t.Fatalf("unexpected output before flush")
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Single segment — should use plain write, not gso.
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("single-seg flush: writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerCoalescesAdjacentACKs(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	pay := make([]byte, 1200)
	if err := c.Add(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4(2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4(3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write, got %d (plain=%d)", len(w.gsoWrites), len(w.writes))
	}
	g := w.gsoWrites[0]
	if g.gsoSize != 1200 {
		t.Errorf("gsoSize=%d want 1200", g.gsoSize)
	}
	if g.hdrLen != 40 {
		t.Errorf("hdrLen=%d want 40", g.hdrLen)
	}
	if g.csumStart != 20 {
		t.Errorf("csumStart=%d want 20", g.csumStart)
	}
	if len(g.pkt) != 40+3*1200 {
		t.Errorf("superpacket len=%d want %d", len(g.pkt), 40+3*1200)
	}
	// IP total length should reflect superpacket.
	if tot := binary.BigEndian.Uint16(g.pkt[2:4]); int(tot) != len(g.pkt) {
		t.Errorf("ip total_length=%d want %d", tot, len(g.pkt))
	}
}

func TestCoalescerRejectsSeqGap(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	pay := make([]byte, 1200)
	if err := c.Add(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// seq should be 2200; use 3000 to simulate a gap.
	if err := c.Add(buildTCPv4(3000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// First packet should have been flushed as a plain write (single seg),
	// then second packet seeded and flushed likewise.
	if len(w.writes) != 2 || len(w.gsoWrites) != 0 {
		t.Fatalf("seq gap: want 2 plain writes got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerRejectsFlagMismatch(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	pay := make([]byte, 1200)
	if err := c.Add(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// SYN flag — not admissible at all. Should flush first packet + plain-write second.
	syn := buildTCPv4(2200, tcpSyn|tcpAck, pay)
	if err := c.Add(syn); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 2 || len(w.gsoWrites) != 0 {
		t.Fatalf("flag mismatch: want 2 plain writes got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerRejectsFIN(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	fin := buildTCPv4(1000, tcpAck|tcpFin, []byte("x"))
	if err := c.Add(fin); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("FIN should be passthrough, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerShortLastSegmentClosesChain(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	full := make([]byte, 1200)
	half := make([]byte, 500)
	if err := c.Add(buildTCPv4(1000, tcpAck, full)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4(2200, tcpAck, half)); err != nil {
		t.Fatal(err)
	}
	// Next full-size would have to start at 2700 but chain is closed —
	// should flush + seed.
	if err := c.Add(buildTCPv4(2700, tcpAck, full)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Expect: one gso write (first two coalesced) + one plain write (the
	// third, flushed alone).
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write got %d", len(w.gsoWrites))
	}
	if len(w.writes) != 1 {
		t.Fatalf("want 1 plain write got %d", len(w.writes))
	}
	if w.gsoWrites[0].gsoSize != 1200 {
		t.Errorf("gsoSize=%d want 1200", w.gsoWrites[0].gsoSize)
	}
	if got, want := len(w.gsoWrites[0].pkt), 40+1200+500; got != want {
		t.Errorf("super len=%d want %d", got, want)
	}
}

func TestCoalescerPSHFinalizesChain(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	pay := make([]byte, 1200)
	if err := c.Add(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Last full-size segment with PSH — admitted but chain is now closed.
	if err := c.Add(buildTCPv4(2200, tcpAckPsh, pay)); err != nil {
		t.Fatal(err)
	}
	// Further full-size would not coalesce.
	if err := c.Add(buildTCPv4(3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write got %d", len(w.gsoWrites))
	}
	if len(w.writes) != 1 {
		t.Fatalf("want 1 plain write got %d", len(w.writes))
	}
}

func TestCoalescerRejectsDifferentFlow(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	pay := make([]byte, 1200)
	p1 := buildTCPv4(1000, tcpAck, pay)
	p2 := buildTCPv4(2200, tcpAck, pay)
	// Mutate p2's source port to break flow match.
	binary.BigEndian.PutUint16(p2[20:22], 9999)
	if err := c.Add(p1); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(p2); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Both flushed as plain writes.
	if len(w.writes) != 2 || len(w.gsoWrites) != 0 {
		t.Fatalf("diff flow: writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerRejectsIPOptions(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	pay := make([]byte, 500)
	pkt := buildTCPv4(1000, tcpAck, pay)
	// Bump IHL to 6 to simulate 4 bytes of IP options. Don't actually add
	// bytes — parser should bail before it matters.
	pkt[0] = 0x46
	if err := c.Add(pkt); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("IP options should passthrough, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerCapBySegments(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTCPCoalescer(w)
	pay := make([]byte, 512) // small so we can fit many before byte cap
	seq := uint32(1000)
	for i := 0; i < tcpCoalesceMaxSegs+5; i++ {
		if err := c.Add(buildTCPv4(seq, tcpAck, pay)); err != nil {
			t.Fatal(err)
		}
		seq += uint32(len(pay))
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// We expect the first tcpCoalesceMaxSegs to form one gso, then 5 more:
	// The 5 follow-ons seed a new super that completes as another gso if >=2,
	// or a mix. Just assert we never exceed the cap per super.
	for _, g := range w.gsoWrites {
		segs := (len(g.pkt) - int(g.hdrLen)) / int(g.gsoSize)
		if rem := (len(g.pkt) - int(g.hdrLen)) % int(g.gsoSize); rem != 0 {
			segs++
		}
		if segs > tcpCoalesceMaxSegs {
			t.Fatalf("super exceeded seg cap: %d > %d", segs, tcpCoalesceMaxSegs)
		}
	}
}
