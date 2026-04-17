package coalesce

import (
	"encoding/binary"
	"testing"
)

// fakeTunWriter records plain Writes and WriteGSO calls without touching a
// real TUN fd. WriteGSO preserves the split between hdr and borrowed pays
// so tests can inspect each independently.
type fakeTunWriter struct {
	gsoEnabled bool
	writes     [][]byte
	gsoWrites  []fakeGSOWrite
}

type fakeGSOWrite struct {
	hdr       []byte
	pays      [][]byte
	gsoSize   uint16
	isV6      bool
	csumStart uint16
}

// total returns hdrLen + sum of pay lens.
func (g fakeGSOWrite) total() int {
	n := len(g.hdr)
	for _, p := range g.pays {
		n += len(p)
	}
	return n
}

// payLen sums the pays.
func (g fakeGSOWrite) payLen() int {
	var n int
	for _, p := range g.pays {
		n += len(p)
	}
	return n
}

func (w *fakeTunWriter) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	w.writes = append(w.writes, buf)
	return len(p), nil
}

func (w *fakeTunWriter) WriteGSO(hdr []byte, pays [][]byte, gsoSize uint16, isV6 bool, csumStart uint16) error {
	hcopy := make([]byte, len(hdr))
	copy(hcopy, hdr)
	paysCopy := make([][]byte, len(pays))
	for i, p := range pays {
		pc := make([]byte, len(p))
		copy(pc, p)
		paysCopy[i] = pc
	}
	w.gsoWrites = append(w.gsoWrites, fakeGSOWrite{
		hdr:       hcopy,
		pays:      paysCopy,
		gsoSize:   gsoSize,
		isV6:      isV6,
		csumStart: csumStart,
	})
	return nil
}

func (w *fakeTunWriter) GSOSupported() bool { return w.gsoEnabled }

// buildTCPv4 constructs a minimal IPv4+TCP packet with the given payload,
// seq, and flags. Assumes no IP options and a 20-byte TCP header.
func buildTCPv4(seq uint32, flags byte, payload []byte) []byte {
	return buildTCPv4Ports(1000, 2000, seq, flags, payload)
}

// buildTCPv4Ports is buildTCPv4 with caller-specified ports so tests can
// build distinct flows.
func buildTCPv4Ports(sport, dport uint16, seq uint32, flags byte, payload []byte) []byte {
	const ipHdrLen = 20
	const tcpHdrLen = 20
	total := ipHdrLen + tcpHdrLen + len(payload)
	pkt := make([]byte, total)

	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = ipProtoTCP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})

	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	binary.BigEndian.PutUint32(pkt[28:32], 12345)
	pkt[32] = 0x50
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 0xffff)

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
	c := NewTCPCoalescer(w)
	pkt := buildTCPv4(1000, tcpAck, []byte("hello"))
	if err := c.Add(pkt); err != nil {
		t.Fatal(err)
	}
	// No sync write — passthrough is deferred to Flush.
	if len(w.writes) != 0 || len(w.gsoWrites) != 0 {
		t.Fatalf("no Add-time writes: got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("want single plain write, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerNonTCPPassthrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[9] = 1
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	if err := c.Add(pkt); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("ICMP should pass through unchanged")
	}
}

func TestCoalescerSeedThenFlushAlone(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	pkt := buildTCPv4(1000, tcpAck, make([]byte, 1000))
	if err := c.Add(pkt); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 0 || len(w.gsoWrites) != 0 {
		t.Fatalf("unexpected output before flush")
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Single-segment flush now goes through WriteGSO with GSO_NONE
	// (virtio NEEDS_CSUM lets the kernel fill in the L4 csum).
	if len(w.gsoWrites) != 1 || len(w.writes) != 0 {
		t.Fatalf("single-seg flush: writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
	g := w.gsoWrites[0]
	if g.total() != 40+1000 {
		t.Errorf("super total=%d want %d", g.total(), 40+1000)
	}
	if g.payLen() != 1000 {
		t.Errorf("payLen=%d want 1000", g.payLen())
	}
}

func TestCoalescerCoalescesAdjacentACKs(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
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
	if len(g.hdr) != 40 {
		t.Errorf("hdrLen=%d want 40", len(g.hdr))
	}
	if g.csumStart != 20 {
		t.Errorf("csumStart=%d want 20", g.csumStart)
	}
	if len(g.pays) != 3 {
		t.Errorf("pay count=%d want 3", len(g.pays))
	}
	if g.total() != 40+3*1200 {
		t.Errorf("superpacket len=%d want %d", g.total(), 40+3*1200)
	}
	if tot := binary.BigEndian.Uint16(g.hdr[2:4]); int(tot) != g.total() {
		t.Errorf("ip total_length=%d want %d", tot, g.total())
	}
}

func TestCoalescerRejectsSeqGap(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	pay := make([]byte, 1200)
	if err := c.Add(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4(3000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Each packet flushes as its own single-segment WriteGSO now.
	if len(w.gsoWrites) != 2 || len(w.writes) != 0 {
		t.Fatalf("seq gap: want 2 gso writes got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerRejectsFlagMismatch(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	pay := make([]byte, 1200)
	if err := c.Add(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// SYN|ACK is non-admissible. Must flush matching flow's slot (gso)
	// and then plain-write the SYN packet itself.
	syn := buildTCPv4(2200, tcpSyn|tcpAck, pay)
	if err := c.Add(syn); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || len(w.gsoWrites) != 1 {
		t.Fatalf("flag mismatch: want 1 plain + 1 gso, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerRejectsFIN(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	fin := buildTCPv4(1000, tcpAck|tcpFin, []byte("x"))
	if err := c.Add(fin); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// FIN isn't admissible — passthrough as plain, no slot, no gso.
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("FIN should be passthrough, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerShortLastSegmentClosesChain(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	full := make([]byte, 1200)
	half := make([]byte, 500)
	if err := c.Add(buildTCPv4(1000, tcpAck, full)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4(2200, tcpAck, half)); err != nil {
		t.Fatal(err)
	}
	// Chain now closed; next packet seeds a new slot on the same flow
	// after flushing the old one.
	if err := c.Add(buildTCPv4(2700, tcpAck, full)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Expect two gso writes: the first two packets coalesced, then the
	// third flushed alone (single-seg via GSO_NONE).
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes got %d", len(w.gsoWrites))
	}
	if len(w.writes) != 0 {
		t.Fatalf("want 0 plain writes got %d", len(w.writes))
	}
	if w.gsoWrites[0].gsoSize != 1200 {
		t.Errorf("gsoSize=%d want 1200", w.gsoWrites[0].gsoSize)
	}
	if got, want := w.gsoWrites[0].total(), 40+1200+500; got != want {
		t.Errorf("super len=%d want %d", got, want)
	}
}

func TestCoalescerPSHFinalizesChain(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	pay := make([]byte, 1200)
	if err := c.Add(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4(2200, tcpAckPsh, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4(3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// First two coalesce; the third seeds a fresh slot that flushes alone.
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes got %d", len(w.gsoWrites))
	}
	if len(w.writes) != 0 {
		t.Fatalf("want 0 plain writes got %d", len(w.writes))
	}
}

func TestCoalescerRejectsDifferentFlow(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	pay := make([]byte, 1200)
	p1 := buildTCPv4(1000, tcpAck, pay)
	p2 := buildTCPv4(2200, tcpAck, pay)
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
	// Two independent flows, each flushes its own single-segment WriteGSO.
	if len(w.gsoWrites) != 2 || len(w.writes) != 0 {
		t.Fatalf("diff flow: want 2 gso writes got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerRejectsIPOptions(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
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
	// Non-admissible parse → passthrough as plain.
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("IP options should passthrough, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerCapBySegments(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	pay := make([]byte, 512)
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
	for _, g := range w.gsoWrites {
		segs := len(g.pays)
		if segs > tcpCoalesceMaxSegs {
			t.Fatalf("super exceeded seg cap: %d > %d", segs, tcpCoalesceMaxSegs)
		}
	}
}

// TestCoalescerMultipleFlowsInSameBatch proves two interleaved bulk TCP
// flows coalesce independently in a single Flush.
func TestCoalescerMultipleFlowsInSameBatch(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	pay := make([]byte, 1200)

	// Flow A: sport 1000. Flow B: sport 3000.
	if err := c.Add(buildTCPv4Ports(1000, 2000, 100, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4Ports(3000, 2000, 500, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4Ports(1000, 2000, 1300, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4Ports(3000, 2000, 1700, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4Ports(1000, 2000, 2500, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4Ports(3000, 2000, 2900, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes (one per flow), got %d", len(w.gsoWrites))
	}
	if len(w.writes) != 0 {
		t.Fatalf("want no plain writes, got %d", len(w.writes))
	}
	// Each superpacket should carry 3 segments.
	for i, g := range w.gsoWrites {
		if len(g.pays) != 3 {
			t.Errorf("gso[%d]: segs=%d want 3", i, len(g.pays))
		}
		if g.gsoSize != 1200 {
			t.Errorf("gso[%d]: gsoSize=%d want 1200", i, g.gsoSize)
		}
	}
	// Verify each superpacket carries the source port it was seeded with.
	seenSports := map[uint16]bool{}
	for _, g := range w.gsoWrites {
		sp := binary.BigEndian.Uint16(g.hdr[20:22])
		seenSports[sp] = true
	}
	if !seenSports[1000] || !seenSports[3000] {
		t.Errorf("expected superpackets for sports 1000 and 3000, got %v", seenSports)
	}
}

// TestCoalescerPreservesArrivalOrder confirms that with passthrough and
// coalesced events both queued, Flush emits them in Add order rather than
// writing passthrough packets synchronously.
func TestCoalescerPreservesArrivalOrder(t *testing.T) {
	w := &orderedFakeWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	// Sequence: coalesceable TCP, ICMP (passthrough), coalesceable TCP on
	// a different flow. Expected emit order: gso(X), plain(ICMP), gso(Y).
	pay := make([]byte, 1200)
	if err := c.Add(buildTCPv4Ports(1000, 2000, 100, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	icmp := make([]byte, 28)
	icmp[0] = 0x45
	binary.BigEndian.PutUint16(icmp[2:4], 28)
	icmp[9] = 1
	copy(icmp[12:16], []byte{10, 0, 0, 1})
	copy(icmp[16:20], []byte{10, 0, 0, 3})
	if err := c.Add(icmp); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4Ports(3000, 2000, 500, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Nothing should have hit the writer synchronously.
	if len(w.events) != 0 {
		t.Fatalf("Add emitted events synchronously: %v", w.events)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := w.events, []string{"gso", "plain", "gso"}; !stringSliceEq(got, want) {
		t.Fatalf("flush order=%v want %v", got, want)
	}
}

// orderedFakeWriter records only the sequence of call types so tests can
// assert arrival order without inspecting bytes.
type orderedFakeWriter struct {
	gsoEnabled bool
	events     []string
}

func (w *orderedFakeWriter) Write(p []byte) (int, error) {
	w.events = append(w.events, "plain")
	return len(p), nil
}

func (w *orderedFakeWriter) WriteGSO(hdr []byte, pays [][]byte, gsoSize uint16, isV6 bool, csumStart uint16) error {
	w.events = append(w.events, "gso")
	return nil
}

func (w *orderedFakeWriter) GSOSupported() bool { return w.gsoEnabled }

func stringSliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestCoalescerInterleavedFlowsPreserveOrdering checks that a non-admissible
// packet (SYN) mid-flow only flushes its own flow, not others.
func TestCoalescerInterleavedFlowsPreserveOrdering(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w)
	pay := make([]byte, 1200)

	// Flow A two segments.
	if err := c.Add(buildTCPv4Ports(1000, 2000, 100, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4Ports(1000, 2000, 1300, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Flow B two segments.
	if err := c.Add(buildTCPv4Ports(3000, 2000, 500, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(buildTCPv4Ports(3000, 2000, 1700, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Flow A SYN (non-admissible) — must flush only flow A's slot.
	syn := buildTCPv4Ports(1000, 2000, 9999, tcpSyn|tcpAck, pay)
	if err := c.Add(syn); err != nil {
		t.Fatal(err)
	}
	// Flow B continues — should still be coalesced with its seed.
	if err := c.Add(buildTCPv4Ports(3000, 2000, 2900, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	// Expected:
	//   - 1 gso for flow A (first 2 segments)
	//   - 1 plain for flow A SYN
	//   - 1 gso for flow B (3 segments)
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes, got %d", len(w.gsoWrites))
	}
	if len(w.writes) != 1 {
		t.Fatalf("want 1 plain write (SYN), got %d", len(w.writes))
	}
	// Find the 3-segment gso (flow B) and the 2-segment gso (flow A).
	var segCounts []int
	for _, g := range w.gsoWrites {
		segCounts = append(segCounts, len(g.pays))
	}
	if !(segCounts[0] == 2 && segCounts[1] == 3) && !(segCounts[0] == 3 && segCounts[1] == 2) {
		t.Errorf("unexpected segment counts: %v (want 2 and 3)", segCounts)
	}
}
