package batch

import (
	"encoding/binary"
	"testing"

	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/test"
)

// fakeTunWriter records plain Writes and WriteGSO calls without touching a
// real TUN fd. WriteGSO records the IP header, transport header, and
// borrowed payload fragments separately so tests can inspect each.
type fakeTunWriter struct {
	gsoEnabled bool
	writes     [][]byte
	gsoWrites  []fakeGSOWrite
}

// fakeGSOWrite captures one WriteGSO call. hdr is the concatenation of the
// IP and transport headers (in that order), gsoSize / isV6 / csumStart are
// derived from the call so existing assertions keep working unchanged.
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

func (w *fakeTunWriter) WriteGSO(hdr []byte, transportHdr []byte, pays [][]byte, _ tio.GSOProto) error {
	hcopy := make([]byte, len(hdr)+len(transportHdr))
	copy(hcopy, hdr)
	copy(hcopy[len(hdr):], transportHdr)
	paysCopy := make([][]byte, len(pays))
	for i, p := range pays {
		pc := make([]byte, len(p))
		copy(pc, p)
		paysCopy[i] = pc
	}
	var gsoSize uint16
	if len(pays) > 1 {
		gsoSize = uint16(len(pays[0]))
	}
	isV6 := len(hdr) > 0 && hdr[0]>>4 == 6
	w.gsoWrites = append(w.gsoWrites, fakeGSOWrite{
		hdr:       hcopy,
		pays:      paysCopy,
		gsoSize:   gsoSize,
		isV6:      isV6,
		csumStart: uint16(len(hdr)),
	})
	return nil
}

func (w *fakeTunWriter) Capabilities() tio.Capabilities {
	return tio.Capabilities{TSO: w.gsoEnabled, USO: w.gsoEnabled}
}

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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pkt := buildTCPv4(1000, tcpAck, []byte("hello"))
	if err := c.Commit(pkt); err != nil {
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[9] = 1
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	if err := c.Commit(pkt); err != nil {
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pkt := buildTCPv4(1000, tcpAck, make([]byte, 1000))
	if err := c.Commit(pkt); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 0 || len(w.gsoWrites) != 0 {
		t.Fatalf("unexpected output before flush")
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Single-segment flush goes through WriteGSO with GSO_NONE
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(3400, tcpAck, pay)); err != nil {
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(3000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Each packet flushes as its own single-segment WriteGSO.
	if len(w.gsoWrites) != 2 || len(w.writes) != 0 {
		t.Fatalf("seq gap: want 2 gso writes got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerRejectsFlagMismatch(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// SYN|ACK is non-admissible. Must flush matching flow's slot (gso)
	// and then plain-write the SYN packet itself.
	syn := buildTCPv4(2200, tcpSyn|tcpAck, pay)
	if err := c.Commit(syn); err != nil {
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	fin := buildTCPv4(1000, tcpAck|tcpFin, []byte("x"))
	if err := c.Commit(fin); err != nil {
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	full := make([]byte, 1200)
	half := make([]byte, 500)
	if err := c.Commit(buildTCPv4(1000, tcpAck, full)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAck, half)); err != nil {
		t.Fatal(err)
	}
	// Chain now closed; next packet seeds a new slot on the same flow
	// after flushing the old one.
	if err := c.Commit(buildTCPv4(2700, tcpAck, full)); err != nil {
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAckPsh, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(3400, tcpAck, pay)); err != nil {
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

// TestCoalescerPropagatesPSHFromAppended ensures that when an appended
// segment carries PSH (or is short, sealing the chain), the PSH bit ends
// up in the emitted superpacket's TCP flags. The kernel TSO path keeps
// PSH only on the last segment iff the input header has it set; if the
// coalescer drops it the sender's push signal never reaches the receiver.
func TestCoalescerPropagatesPSHFromAppended(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	// Seed has no PSH; second segment carries PSH and seals the chain.
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAckPsh, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write got %d", len(w.gsoWrites))
	}
	g := w.gsoWrites[0]
	const ipHdrLen = 20
	flags := g.hdr[ipHdrLen+13]
	if flags&tcpPsh == 0 {
		t.Fatalf("PSH lost from coalesced superpacket: flags=0x%02x", flags)
	}
	if flags&tcpAck == 0 {
		t.Fatalf("ACK missing from coalesced superpacket: flags=0x%02x", flags)
	}
}

func TestCoalescerRejectsDifferentFlow(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	p1 := buildTCPv4(1000, tcpAck, pay)
	p2 := buildTCPv4(2200, tcpAck, pay)
	binary.BigEndian.PutUint16(p2[20:22], 9999)
	if err := c.Commit(p1); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(p2); err != nil {
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 500)
	pkt := buildTCPv4(1000, tcpAck, pay)
	// Bump IHL to 6 to simulate 4 bytes of IP options. Don't actually add
	// bytes — parser should bail before it matters.
	pkt[0] = 0x46
	if err := c.Commit(pkt); err != nil {
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 512)
	seq := uint32(1000)
	for i := 0; i < tcpCoalesceMaxSegs+5; i++ {
		if err := c.Commit(buildTCPv4(seq, tcpAck, pay)); err != nil {
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)

	// Flow A: sport 1000. Flow B: sport 3000.
	if err := c.Commit(buildTCPv4Ports(1000, 2000, 100, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(3000, 2000, 500, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(1000, 2000, 1300, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(3000, 2000, 1700, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(1000, 2000, 2500, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(3000, 2000, 2900, tcpAck, pay)); err != nil {
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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	// Sequence: coalesceable TCP, ICMP (passthrough), coalesceable TCP on
	// a different flow. Expected emit order: gso(X), plain(ICMP), gso(Y).
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4Ports(1000, 2000, 100, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	icmp := make([]byte, 28)
	icmp[0] = 0x45
	binary.BigEndian.PutUint16(icmp[2:4], 28)
	icmp[9] = 1
	copy(icmp[12:16], []byte{10, 0, 0, 1})
	copy(icmp[16:20], []byte{10, 0, 0, 3})
	if err := c.Commit(icmp); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(3000, 2000, 500, tcpAck, pay)); err != nil {
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

func (w *orderedFakeWriter) WriteGSO(hdr []byte, transportHdr []byte, pays [][]byte, _ tio.GSOProto) error {
	w.events = append(w.events, "gso")
	return nil
}

func (w *orderedFakeWriter) Capabilities() tio.Capabilities {
	return tio.Capabilities{TSO: w.gsoEnabled, USO: w.gsoEnabled}
}

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
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)

	// Flow A two segments.
	if err := c.Commit(buildTCPv4Ports(1000, 2000, 100, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(1000, 2000, 1300, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Flow B two segments.
	if err := c.Commit(buildTCPv4Ports(3000, 2000, 500, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(3000, 2000, 1700, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Flow A SYN (non-admissible) — must flush only flow A's slot.
	syn := buildTCPv4Ports(1000, 2000, 9999, tcpSyn|tcpAck, pay)
	if err := c.Commit(syn); err != nil {
		t.Fatal(err)
	}
	// Flow B continues — should still be coalesced with its seed.
	if err := c.Commit(buildTCPv4Ports(3000, 2000, 2900, tcpAck, pay)); err != nil {
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

// ECN test helpers and constants.

const (
	tcpEce = 0x40
	tcpCwr = 0x80

	// 2-bit IP-level ECN codepoints (lower 2 bits of IPv4 ToS / IPv6 TC).
	ecnNotECT = 0x00
	ecnECT1   = 0x01
	ecnECT0   = 0x02
	ecnCE     = 0x03
)

// buildTCPv4WithToS is buildTCPv4 with caller-specified IPv4 ToS so tests can
// drive DSCP and ECN bits.
func buildTCPv4WithToS(tos byte, seq uint32, flags byte, payload []byte) []byte {
	pkt := buildTCPv4(seq, flags, payload)
	pkt[1] = tos
	return pkt
}

// buildTCPv6 mirrors buildTCPv4 for IPv6. tcLow is the low 4 bits of Traffic
// Class, which carries the ECN codepoint (mask 0x03) and the bottom 2 DSCP
// bits — enough to drive the ECN paths under test.
func buildTCPv6(tcLow byte, seq uint32, flags byte, payload []byte) []byte {
	const ipHdrLen = 40
	const tcpHdrLen = 20
	pkt := make([]byte, ipHdrLen+tcpHdrLen+len(payload))

	pkt[0] = 0x60                // version=6, TC[7:4]=0
	pkt[1] = (tcLow & 0x0f) << 4 // TC[3:0] in high nibble; flow=0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(tcpHdrLen+len(payload)))
	pkt[6] = ipProtoTCP
	pkt[7] = 64
	copy(pkt[8:24], []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(pkt[24:40], []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})

	binary.BigEndian.PutUint16(pkt[40:42], 1000)
	binary.BigEndian.PutUint16(pkt[42:44], 2000)
	binary.BigEndian.PutUint32(pkt[44:48], seq)
	binary.BigEndian.PutUint32(pkt[48:52], 12345)
	pkt[52] = 0x50
	pkt[53] = flags
	binary.BigEndian.PutUint16(pkt[54:56], 0xffff)

	copy(pkt[60:], payload)
	return pkt
}

// TestCoalescerCoalescesEceFlow confirms that ECN-Echo-marked ACKs (an
// ECN-aware flow under congestion) keep getting coalesced into a TSO
// superpacket instead of falling out to passthrough, and that the seed
// retains ECE on the wire.
func TestCoalescerCoalescesEceFlow(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	flags := byte(tcpAck | tcpEce)
	if err := c.Commit(buildTCPv4(1000, flags, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, flags, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write, got %d (plain=%d)", len(w.gsoWrites), len(w.writes))
	}
	g := w.gsoWrites[0]
	if len(g.pays) != 2 {
		t.Errorf("pay count=%d want 2", len(g.pays))
	}
	if seedFlags := g.hdr[20+13]; seedFlags&tcpEce == 0 {
		t.Errorf("seed flags=0x%02x want ECE preserved", seedFlags)
	}
}

// TestCoalescerCwrSealsFlow confirms that a CWR-bearing segment in the
// middle of a flow goes to passthrough and seals the open slot, so a later
// in-flow segment seeds a new slot rather than extending the prior burst.
func TestCoalescerCwrSealsFlow(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAck|tcpCwr, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 {
		t.Fatalf("want 1 plain write (CWR), got %d", len(w.writes))
	}
	// Two GSO writes: the first seed before CWR, and a fresh seed after.
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes, got %d", len(w.gsoWrites))
	}
	for i, g := range w.gsoWrites {
		if len(g.pays) != 1 {
			t.Errorf("gso %d pay count=%d want 1", i, len(g.pays))
		}
	}
}

// TestCoalescerEceMismatchReseeds confirms that toggling ECE mid-flow does
// not silently merge — receivers expect ECE either set on every segment of
// a CE-echoing window or none.
func TestCoalescerEceMismatchReseeds(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4(1000, tcpAck|tcpEce, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 separate seeds, got %d gso writes", len(w.gsoWrites))
	}
	for i, g := range w.gsoWrites {
		if len(g.pays) != 1 {
			t.Errorf("gso %d pay count=%d want 1", i, len(g.pays))
		}
	}
}

// TestCoalescerDifferingECNReseeds confirms that segments with differing IP
// ECN codepoints do NOT coalesce: headersMatch compares the full ToS byte,
// matching kernel GRO. Two ECT(0) segments merge; a CE stamp mid-run seals
// the ECT(0) chain and starts a fresh superpacket that keeps CE; a trailing
// ECT(0) starts yet another. Each superpacket keeps its own codepoint —
// ORing the marks (the old buggy behavior) would have fabricated a false CE
// across the whole burst.
func TestCoalescerDifferingECNReseeds(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4WithToS(ecnECT0, 1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4WithToS(ecnECT0, 2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Router along the path stamped CE on this one.
	if err := c.Commit(buildTCPv4WithToS(ecnCE, 3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4WithToS(ecnECT0, 4600, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 3 {
		t.Fatalf("want 3 superpackets (ECN split), got %d (plain=%d)", len(w.gsoWrites), len(w.writes))
	}
	// gso[0]: the two ECT(0) segments merged; gso[1]: CE alone; gso[2]:
	// trailing ECT(0) alone. Emitted in seq order.
	type want struct {
		pays int
		ecn  byte
	}
	wants := []want{{2, ecnECT0}, {1, ecnCE}, {1, ecnECT0}}
	for i, wnt := range wants {
		g := w.gsoWrites[i]
		if len(g.pays) != wnt.pays {
			t.Errorf("gso %d pay count=%d want %d", i, len(g.pays), wnt.pays)
		}
		if got := g.hdr[1] & 0x03; got != wnt.ecn {
			t.Errorf("gso %d ECN=0x%02x want 0x%02x", i, got, wnt.ecn)
		}
	}
}

// TestCoalescerECT0ThenECT1NoCE is the core regression for the ECN merge
// bug: ORing ECT(0)=0b10 with ECT(1)=0b01 fabricates CE=0b11. The two
// segments must land in separate superpackets, each preserving its own
// codepoint, and neither may end up CE-marked.
func TestCoalescerECT0ThenECT1NoCE(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4WithToS(ecnECT0, 1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4WithToS(ecnECT1, 2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 separate superpackets (ECT0 vs ECT1), got %d", len(w.gsoWrites))
	}
	wantECN := []byte{ecnECT0, ecnECT1}
	for i, g := range w.gsoWrites {
		if got := g.hdr[1] & 0x03; got != wantECN[i] {
			t.Errorf("gso %d ECN=0x%02x want 0x%02x", i, got, wantECN[i])
		}
		if got := g.hdr[1] & 0x03; got == ecnCE {
			t.Errorf("gso %d fabricated CE from ECT merge", i)
		}
	}
}

// TestCoalescerDscpMismatchReseeds confirms that a DSCP difference (same
// ECN) still splits — headersMatch compares the full ToS byte, so the upper
// six DSCP bits must match too.
func TestCoalescerDscpMismatchReseeds(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	// Same ECN (Not-ECT), different DSCP (0x10 vs 0x20 in upper 6 bits).
	tosA := byte(0x10<<2) | ecnNotECT
	tosB := byte(0x20<<2) | ecnNotECT
	if err := c.Commit(buildTCPv4WithToS(tosA, 1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4WithToS(tosB, 2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 separate seeds (different DSCP), got %d", len(w.gsoWrites))
	}
}

// TestCoalescerIPv6CoalescesEceFlow is the IPv6 analogue of
// TestCoalescerCoalescesEceFlow.
func TestCoalescerIPv6CoalescesEceFlow(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	flags := byte(tcpAck | tcpEce)
	if err := c.Commit(buildTCPv6(0, 1000, flags, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv6(0, 2200, flags, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write, got %d", len(w.gsoWrites))
	}
	g := w.gsoWrites[0]
	if seedFlags := g.hdr[40+13]; seedFlags&tcpEce == 0 {
		t.Errorf("seed flags=0x%02x want ECE preserved", seedFlags)
	}
}

// TestCoalescerSortsReorderedSeedsAndMerges feeds three same-flow MSS
// segments out of TCP-seq order (mimicking a wire reorder that escaped
// the rxOrder per-batch sort). Without the reorderForFlush sort+merge,
// each out-of-seq arrival would seed its own slot and the slots would
// emit in arrival order, producing a kernel-visible TCP reorder. With
// the sort+merge, the three slots are sorted by seq and folded back into
// one in-order TSO superpacket — same shape the receiver TCP would have
// seen had the wire never reordered.
func TestCoalescerSortsReorderedSeedsAndMerges(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	// Arrival order: seq 1000, 3400, 2200. The 3400 seeds a separate slot
	// because 3400 != nextSeq=2200, then 2200 fails to extend the 3400 slot
	// and seeds its own. Three slots end up in c.slots; reorderForFlush
	// should sort them into [1000,2200,3400] and merge them back into one.
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 merged gso write got %d", len(w.gsoWrites))
	}
	g := w.gsoWrites[0]
	if len(g.pays) != 3 {
		t.Fatalf("merged segs=%d want 3", len(g.pays))
	}
	const ipHdrLen = 20
	if seedSeq := binary.BigEndian.Uint32(g.hdr[ipHdrLen+4 : ipHdrLen+8]); seedSeq != 1000 {
		t.Errorf("merged seed seq=%d want 1000 (lowest)", seedSeq)
	}
}

// TestCoalescerSortAcrossFlowsMergesEachIndependently checks that two
// flows interleaved with reorder are each sorted-and-merged in isolation
// without any cross-flow contamination.
func TestCoalescerSortAcrossFlowsMergesEachIndependently(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	// Flow A (sport 1000) seq 100, 1300; flow B (sport 3000) seq 500, 1700.
	// Arrival: A.1300, B.1700, A.100, B.500 — every flow reordered.
	if err := c.Commit(buildTCPv4Ports(1000, 2000, 1300, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(3000, 2000, 1700, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(1000, 2000, 100, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4Ports(3000, 2000, 500, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes (one per flow merged), got %d", len(w.gsoWrites))
	}
	for i, g := range w.gsoWrites {
		if len(g.pays) != 2 {
			t.Errorf("gso[%d] segs=%d want 2", i, len(g.pays))
		}
		const ipHdrLen = 20
		seedSeq := binary.BigEndian.Uint32(g.hdr[ipHdrLen+4 : ipHdrLen+8])
		sport := binary.BigEndian.Uint16(g.hdr[ipHdrLen : ipHdrLen+2])
		// Each flow's merged seed should be the LOWER of its two seqs.
		switch sport {
		case 1000:
			if seedSeq != 100 {
				t.Errorf("flow A seed seq=%d want 100", seedSeq)
			}
		case 3000:
			if seedSeq != 500 {
				t.Errorf("flow B seed seq=%d want 500", seedSeq)
			}
		default:
			t.Errorf("unexpected sport %d", sport)
		}
	}
}

// TestCoalescerSortKeepsPSHBoundary verifies that a PSH-sealed slot is
// not folded into a later seq-contiguous slot — PSH placement is part of
// the wire signal and merging across it would shift the receiver's push
// boundary by an arbitrary number of segments.
func TestCoalescerSortKeepsPSHBoundary(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	// Seq 1000 (no PSH) + 2200 (PSH) → seal one slot with PSH set.
	// Seq 3400 (no PSH) is contiguous to 3400 from seq 2200+1200; without
	// the PSH check it would merge in.
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAckPsh, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes (PSH-sealed and fresh seed), got %d", len(w.gsoWrites))
	}
}

// TestCoalescerSortKeepsPassthroughBarrier confirms a passthrough slot in
// the middle of the queue prevents the post-sort merge from folding
// across it. Reordered same-flow data on either side of the passthrough
// is sorted/merged independently.
func TestCoalescerSortKeepsPassthroughBarrier(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	// First two segments seed S1 (then a 3400 reorder seeds S2).
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Non-coalesceable packet (SYN+ACK) flushes S1's openSlots entry and
	// becomes a passthrough barrier in c.slots.
	if err := c.Commit(buildTCPv4(9999, tcpSyn|tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Post-barrier same-flow data: should never end up before the SYN.
	if err := c.Commit(buildTCPv4(2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// We expect: gso(merged 1000+3400 ranges sorted but not contiguous so 2
	// gso writes), plain(SYN), gso(2200 alone). The pre-barrier sort should
	// land 1000 before 3400, and the post-barrier 2200 stays after the SYN.
	if len(w.writes) != 1 {
		t.Fatalf("want 1 plain SYN passthrough, got %d", len(w.writes))
	}
}

// TestCoalescerIPv6DifferingECNReseeds is the IPv6 analogue of
// TestCoalescerDifferingECNReseeds. ECN bits live in TC[1:0] = byte 1 mask
// 0x30, so ipHeadersMatch (comparing byte 1 fully) still splits them.
func TestCoalescerIPv6DifferingECNReseeds(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewTCPCoalescer(w, test.NewLogger(), NewArena(0))
	pay := make([]byte, 1200)
	// tcLow is the low 4 bits of TC; ECN occupies the bottom 2 of those.
	if err := c.Commit(buildTCPv6(ecnECT0, 1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv6(ecnECT0, 2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv6(ecnCE, 3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv6(ecnECT0, 4600, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 3 {
		t.Fatalf("want 3 superpackets (ECN split), got %d", len(w.gsoWrites))
	}
	// Byte 1 high nibble holds TC[3:0]; ECN is the low 2 bits of that nibble,
	// which appears in byte 1 mask 0x30 (>>4 to read the codepoint value).
	type want struct {
		pays int
		ecn  byte
	}
	wants := []want{{2, ecnECT0}, {1, ecnCE}, {1, ecnECT0}}
	for i, wnt := range wants {
		g := w.gsoWrites[i]
		if len(g.pays) != wnt.pays {
			t.Errorf("gso %d pay count=%d want %d", i, len(g.pays), wnt.pays)
		}
		if got := (g.hdr[1] >> 4) & 0x03; got != wnt.ecn {
			t.Errorf("gso %d v6 ECN=0x%02x want 0x%02x", i, got, wnt.ecn)
		}
	}
}

func TestSortRunZeroAllocs(t *testing.T) {
	c := &TCPCoalescer{}
	mk := func(srcByte byte, seq uint32, pay int) *coalesceSlot {
		s := &coalesceSlot{nextSeq: seq + uint32(pay), totalPay: pay}
		s.fk.src[0] = srcByte
		return s
	}
	run := []*coalesceSlot{
		mk(3, 5000, 100),
		mk(1, 1000, 50),
		mk(2, 2000, 75),
		mk(1, 900, 50),
		mk(3, 4900, 100),
		mk(2, 1925, 75),
		mk(1, 1050, 50),
		mk(3, 5100, 100),
	}

	allocs := testing.AllocsPerRun(100, func() {
		// Re-shuffle so each run actually does sorting work.
		run[0], run[1], run[2], run[3] = run[3], run[2], run[1], run[0]
		c.sortRun(run)
	})
	if allocs != 0 {
		t.Fatalf("sortRun allocates %v times per run; want 0", allocs)
	}
}
