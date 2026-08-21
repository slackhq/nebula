package batch

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/test"
)

// fakeTunWriter records plain Writes and WriteGSO calls without touching a
// real TUN fd. WriteGSO records the IP header, transport header, and
// borrowed payload fragments separately so tests can inspect each.
// noTSO / noUSO withhold one offload from an otherwise GSO-capable writer, so
// tests can build the half-capable queues real kernels hand us (USO needs a
// newer kernel than TSO).
type fakeTunWriter struct {
	gsoEnabled bool
	noTSO      bool
	noUSO      bool
	writes     [][]byte
	gsoWrites  []fakeGSOWrite
	// order records the interleaving of Write ("write") and WriteGSO ("gso")
	// calls for tests that assert cross-call emission order.
	order []string
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
	w.order = append(w.order, "write")
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
	w.order = append(w.order, "gso")
	return nil
}

func (w *fakeTunWriter) Capabilities() tio.Capabilities {
	return tio.Capabilities{TSO: w.gsoEnabled && !w.noTSO, USO: w.gsoEnabled && !w.noUSO}
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

// setIPv4ID stamps an IPv4 ID and DF state onto a builder packet. The
// builders default to DF=1/ID=0 (an atomic datagram); the ID-admission
// tests use this to fabricate non-atomic (DF=0) senders.
func setIPv4ID(pkt []byte, id uint16, df bool) {
	binary.BigEndian.PutUint16(pkt[4:6], id)
	var flags uint16
	if df {
		flags = 0x4000
	}
	binary.BigEndian.PutUint16(pkt[6:8], flags)
}

// newTestTCPCoalescer builds a coalescer over w and fails the test if w can't
// do TSO. Every test but TestNewTCPCoalescerRefusesWhenGSOUnavailable wants the
// GSO path, and the constructor now hands back a nil coalescer otherwise.
func newTestTCPCoalescer(tb testing.TB, w io.Writer) *TCPCoalescer {
	tb.Helper()
	c := NewTCPCoalescer(w, test.NewLogger())
	if c == nil {
		tb.Fatal("NewTCPCoalescer: writer does not support TSO")
	}
	return c
}

// TestNewTCPCoalescerRefusesWhenGSOUnavailable pins the constructor
// precondition: no TSO, no coalescer. There's no degraded mode — the caller
// (MultiCoalescer) sends TCP down the verbatim lane instead.
func TestNewTCPCoalescerRefusesWhenGSOUnavailable(t *testing.T) {
	if c := NewTCPCoalescer(&fakeTunWriter{gsoEnabled: false}, test.NewLogger()); c != nil {
		t.Fatalf("want nil for a non-TSO writer, got %v", c)
	}
	// A writer that isn't a GSOWriter at all is refused the same way.
	if c := NewTCPCoalescer(&plainOnlyWriter{}, test.NewLogger()); c != nil {
		t.Fatalf("want nil for a plain writer, got %v", c)
	}
}

// plainOnlyWriter is an io.Writer with no GSO support at all — the
// single-packet Queue shape.
type plainOnlyWriter struct{ writes int }

func (w *plainOnlyWriter) Write(p []byte) (int, error) {
	w.writes++
	return len(p), nil
}

func TestCoalescerNonTCPPassthrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	c := newTestTCPCoalescer(t, w)
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
	// A slot that never grew past one segment flushes as a plain Write of
	// the original packet bytes: the original (already valid) checksum
	// ships via the DATA_VALID path, so the kernel does no csum work.
	// WriteGSO is reserved for slots that actually coalesced (>=2 segs).
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("single-seg flush: writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
	if !bytes.Equal(w.writes[0], pkt) {
		t.Errorf("plain write not byte-identical to committed packet: got %d bytes want %d", len(w.writes[0]), len(pkt))
	}
}

// TestCoalescerPureAckDoesNotSealRun pins the pure-ACK fast path: a bare
// acknowledgment (zero payload, nothing beyond ACK|PSH|ECE) rides its lane
// as a verbatim WITHOUT sealing the flow's open slot, so an inbound data
// run on a bidirectional connection keeps coalescing across the peer ACKs
// interleaved into it. The ACK is emitted after the superpacket (stale ACKs
// are ignored by receivers, so the reorder is harmless by design).
func TestCoalescerPureAckDoesNotSealRun(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	ack := buildTCPv4(2200, tcpAck, nil)
	if err := c.Commit(ack); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 || len(w.writes) != 1 {
		t.Fatalf("ACK sealed the run: writes=%d gso=%d, want 1 gso (2 pays) + 1 plain", len(w.writes), len(w.gsoWrites))
	}
	if got := len(w.gsoWrites[0].pays); got != 2 {
		t.Errorf("pay count=%d want 2 (data kept coalescing across the ACK)", got)
	}
	if !bytes.Equal(w.writes[0], ack) {
		t.Errorf("plain write is not the ACK packet: got %d bytes want %d", len(w.writes[0]), len(ack))
	}
	if got, want := w.order, []string{"gso", "write"}; !stringSliceEq(got, want) {
		t.Errorf("flush order=%v want %v (slot order: data run seeded first)", got, want)
	}
}

// TestCoalescerFinStillSealsRun is the guard rail for the pure-ACK fast
// path: control flags (here FIN|ACK, zero payload) must keep sealing the
// open slot so data never reorders across a flow-state transition.
func TestCoalescerFinStillSealsRun(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpFin|tcpAck, nil)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// FIN evicts the open slot; the third packet seeds a fresh one. All
	// three stay single-segment, so all three emit as plain writes in
	// arrival order — any gso write would mean data coalesced across FIN.
	if len(w.writes) != 3 || len(w.gsoWrites) != 0 {
		t.Fatalf("FIN must seal the run: writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerCoalescesAdjacentACKs(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	c := newTestTCPCoalescer(t, w)
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
	// Each packet stays a single-segment slot and flushes as its own plain
	// write of the original bytes.
	if len(w.writes) != 2 || len(w.gsoWrites) != 0 {
		t.Fatalf("seq gap: want 2 plain writes got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerRejectsFlagMismatch(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// SYN|ACK is non-admissible. Must flush the matching flow's slot —
	// single-segment, so a plain write of the original bytes — and then
	// plain-write the SYN packet itself.
	syn := buildTCPv4(2200, tcpSyn|tcpAck, pay)
	if err := c.Commit(syn); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 2 || len(w.gsoWrites) != 0 {
		t.Fatalf("flag mismatch: want 2 plain writes (flushed seed + SYN), got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
	if !bytes.Equal(w.writes[1], syn) {
		t.Errorf("second plain write should be the SYN packet, got %d bytes", len(w.writes[1]))
	}
}

func TestCoalescerRejectsFIN(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	fin := buildTCPv4(1000, tcpAck|tcpFin, []byte("x"))
	if err := c.Commit(fin); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// FIN isn't admissible — verbatim as plain, no slot, no gso.
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("FIN should be verbatim, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerShortLastSegmentClosesChain(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	// Expect one gso write for the first two packets coalesced, then the
	// third — still single-segment — flushed as a plain write of the
	// original packet.
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write got %d", len(w.gsoWrites))
	}
	if len(w.writes) != 1 {
		t.Fatalf("want 1 plain write got %d", len(w.writes))
	}
	if w.gsoWrites[0].gsoSize != 1200 {
		t.Errorf("gsoSize=%d want 1200", w.gsoWrites[0].gsoSize)
	}
	if got, want := w.gsoWrites[0].total(), 40+1200+500; got != want {
		t.Errorf("super len=%d want %d", got, want)
	}
	if got, want := len(w.writes[0]), 40+1200; got != want {
		t.Errorf("plain write len=%d want %d", got, want)
	}
}

func TestCoalescerPSHFinalizesChain(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	// First two coalesce into one gso write; the third seeds a fresh slot
	// that stays single-segment and flushes as a plain write.
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write got %d", len(w.gsoWrites))
	}
	if len(w.writes) != 1 {
		t.Fatalf("want 1 plain write got %d", len(w.writes))
	}
}

// TestCoalescerPropagatesPSHFromAppended ensures that when an appended
// segment carries PSH (or is short, sealing the chain), the PSH bit ends
// up in the emitted superpacket's TCP flags. The kernel TSO path keeps
// PSH only on the last segment iff the input header has it set; if the
// coalescer drops it the sender's push signal never reaches the receiver.
func TestCoalescerPropagatesPSHFromAppended(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	c := newTestTCPCoalescer(t, w)
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
	// Two independent flows, each stays single-segment and flushes as its
	// own plain write of the original bytes.
	if len(w.writes) != 2 || len(w.gsoWrites) != 0 {
		t.Fatalf("diff flow: want 2 plain writes got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerRejectsIPOptions(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	// Non-admissible parse → verbatim as plain.
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("IP options should verbatim, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestCoalescerCapBySegments(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	c := newTestTCPCoalescer(t, w)
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

// TestCoalescerPreservesArrivalOrder confirms that with verbatim and
// coalesced events both queued, Flush emits them in Add order rather than
// writing verbatim packets synchronously.
func TestCoalescerPreservesArrivalOrder(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	// Sequence: coalesceable TCP, ICMP (verbatim), coalesceable TCP on
	// a different flow. Both TCP slots stay single-segment, so all three
	// emit as plain writes; the packet order (X, ICMP, Y) is asserted by
	// byte content since the kinds no longer distinguish them.
	pay := make([]byte, 1200)
	tcpX := buildTCPv4Ports(1000, 2000, 100, tcpAck, pay)
	if err := c.Commit(tcpX); err != nil {
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
	tcpY := buildTCPv4Ports(3000, 2000, 500, tcpAck, pay)
	if err := c.Commit(tcpY); err != nil {
		t.Fatal(err)
	}
	// Nothing should have hit the writer synchronously.
	if len(w.order) != 0 {
		t.Fatalf("Add emitted events synchronously: %v", w.order)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := w.order, []string{"write", "write", "write"}; !stringSliceEq(got, want) {
		t.Fatalf("flush order=%v want %v", got, want)
	}
	for i, want := range [][]byte{tcpX, icmp, tcpY} {
		if !bytes.Equal(w.writes[i], want) {
			t.Fatalf("write %d out of arrival order: got %d bytes, want %d bytes", i, len(w.writes[i]), len(want))
		}
	}
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
	c := newTestTCPCoalescer(t, w)
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
// superpacket instead of falling out to verbatim, and that the seed
// retains ECE on the wire.
func TestCoalescerCoalescesEceFlow(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
// middle of a flow goes to verbatim and seals the open slot, so a later
// in-flow segment seeds a new slot rather than extending the prior burst.
func TestCoalescerCwrSealsFlow(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	// All three emissions are plain writes: the seed before CWR and the
	// fresh seed after both stay single-segment, and the CWR packet itself
	// is verbatim. Order: seed, CWR, reseed.
	if len(w.writes) != 3 || len(w.gsoWrites) != 0 {
		t.Fatalf("want 3 plain writes (seed, CWR, reseed), got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
	if flags := w.writes[1][20+13]; flags&tcpCwr == 0 {
		t.Errorf("middle write flags=0x%02x want CWR (verbatim in arrival order)", flags)
	}
}

// TestCoalescerEceMismatchReseeds confirms that toggling ECE mid-flow does
// not silently merge — receivers expect ECE either set on every segment of
// a CE-echoing window or none.
func TestCoalescerEceMismatchReseeds(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	// Each seed stays single-segment and flushes as its own plain write.
	if len(w.writes) != 2 || len(w.gsoWrites) != 0 {
		t.Fatalf("want 2 separate plain writes, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
	if flags := w.writes[0][20+13]; flags&tcpEce == 0 {
		t.Errorf("first write lost ECE: flags=0x%02x", flags)
	}
	if flags := w.writes[1][20+13]; flags&tcpEce != 0 {
		t.Errorf("second write gained ECE: flags=0x%02x", flags)
	}
}

// TestCoalescerDifferingECNReseeds confirms that segments with differing IP
// ECN codepoints do NOT coalesce: headersMatch compares the full ToS byte,
// matching kernel GRO. Two ECT(0) segments merge into a superpacket; a CE
// stamp mid-run seals the ECT(0) chain and reseeds, and the trailing ECT(0)
// reseeds again — those reseeds stay single-segment and ship as plain
// writes of the original packets, each keeping its own codepoint. ORing
// the marks (the old buggy behavior) would have fabricated a false CE
// across the whole burst.
func TestCoalescerDifferingECNReseeds(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	// gso: the two ECT(0) segments merged; then plain CE alone; then plain
	// trailing ECT(0) alone. Emitted in seq order.
	if len(w.gsoWrites) != 1 || len(w.writes) != 2 {
		t.Fatalf("want 1 gso (ECT0 pair) + 2 plain (ECN split), got gso=%d plain=%d", len(w.gsoWrites), len(w.writes))
	}
	if got, want := w.order, []string{"gso", "write", "write"}; !stringSliceEq(got, want) {
		t.Fatalf("emission order=%v want %v", got, want)
	}
	g := w.gsoWrites[0]
	if len(g.pays) != 2 {
		t.Errorf("gso pay count=%d want 2", len(g.pays))
	}
	if got := g.hdr[1] & 0x03; got != ecnECT0 {
		t.Errorf("gso ECN=0x%02x want 0x%02x", got, ecnECT0)
	}
	wantECN := []byte{ecnCE, ecnECT0}
	for i, wnt := range wantECN {
		if got := w.writes[i][1] & 0x03; got != wnt {
			t.Errorf("plain %d ECN=0x%02x want 0x%02x", i, got, wnt)
		}
	}
}

// TestCoalescerECT0ThenECT1NoCE is the core regression for the ECN merge
// bug: ORing ECT(0)=0b10 with ECT(1)=0b01 fabricates CE=0b11. The two
// segments must land in separate emissions — both stay single-segment, so
// each ships as a plain write of its original bytes, preserving its own
// codepoint — and neither may end up CE-marked.
func TestCoalescerECT0ThenECT1NoCE(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	if len(w.writes) != 2 || len(w.gsoWrites) != 0 {
		t.Fatalf("want 2 separate plain writes (ECT0 vs ECT1), got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
	wantECN := []byte{ecnECT0, ecnECT1}
	for i, p := range w.writes {
		if got := p[1] & 0x03; got != wantECN[i] {
			t.Errorf("write %d ECN=0x%02x want 0x%02x", i, got, wantECN[i])
		}
		if got := p[1] & 0x03; got == ecnCE {
			t.Errorf("write %d fabricated CE from ECT merge", i)
		}
	}
}

// TestCoalescerDscpMismatchReseeds confirms that a DSCP difference (same
// ECN) still splits — headersMatch compares the full ToS byte, so the upper
// six DSCP bits must match too.
func TestCoalescerDscpMismatchReseeds(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	// Both seeds stay single-segment → two plain writes, no gso.
	if len(w.writes) != 2 || len(w.gsoWrites) != 0 {
		t.Fatalf("want 2 separate plain writes (different DSCP), got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

// TestCoalescerIPv6CoalescesEceFlow is the IPv6 analogue of
// TestCoalescerCoalescesEceFlow.
func TestCoalescerIPv6CoalescesEceFlow(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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

// TestCoalescerPSHKeepsChainBoundary verifies that a PSH-sealed chain is
// not extended by a later seq-contiguous segment — PSH placement is part of
// the wire signal and growing the superpacket past it would shift the
// receiver's push boundary by an arbitrary number of segments.
func TestCoalescerPSHKeepsChainBoundary(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	pay := make([]byte, 1200)
	// Seq 1000 (no PSH) + 2200 (PSH) → seal one slot with PSH set.
	// Seq 3400 is contiguous to the sealed chain's nextSeq; without the
	// seal check it would append in.
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
	// The PSH-sealed pair is a real superpacket; the fresh seed stays
	// single-segment and flushes as a plain write.
	if len(w.gsoWrites) != 1 || len(w.writes) != 1 {
		t.Fatalf("want 1 gso (PSH-sealed pair) + 1 plain (fresh seed), got gso=%d plain=%d", len(w.gsoWrites), len(w.writes))
	}
}

// TestCoalescerSynSealsFlowChain confirms a non-admissible in-flow packet
// (SYN+ACK here) seals its flow's open chain and holds its emission
// position: data committed after it seeds a fresh slot and emits after it,
// never extending a chain created before it.
func TestCoalescerSynSealsFlowChain(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	pay := make([]byte, 1200)
	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Discontiguous seq: evicts the 1000 slot and seeds its own.
	if err := c.Commit(buildTCPv4(3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Non-coalesceable packet (SYN+ACK) seals the flow's open slot and
	// becomes a verbatim slot in c.slots.
	if err := c.Commit(buildTCPv4(9999, tcpSyn|tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// Post-SYN data: must emit after the SYN, in its own slot.
	if err := c.Commit(buildTCPv4(2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// All four packets emit as plain writes in creation order: 1000 and
	// 3400 are separate single-segment slots, the SYN is verbatim, and the
	// post-SYN 2200 is a fresh single-segment slot after it.
	if len(w.writes) != 4 || len(w.gsoWrites) != 0 {
		t.Fatalf("want 4 plain writes, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
	wantSeqs := []uint32{1000, 3400, 9999, 2200}
	for i, want := range wantSeqs {
		if seq := binary.BigEndian.Uint32(w.writes[i][24:28]); seq != want {
			t.Errorf("write %d seq=%d want %d", i, seq, want)
		}
	}
}

// TestCoalescerIPv6DifferingECNReseeds is the IPv6 analogue of
// TestCoalescerDifferingECNReseeds. ECN bits live in TC[1:0] = byte 1 mask
// 0x30, so ipHeadersMatch (comparing byte 1 fully) still splits them.
func TestCoalescerIPv6DifferingECNReseeds(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
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
	// Like the v4 test: the ECT(0) pair merges into one superpacket; the CE
	// and trailing ECT(0) reseeds stay single-segment and ship as plain
	// writes, in seq order.
	if len(w.gsoWrites) != 1 || len(w.writes) != 2 {
		t.Fatalf("want 1 gso (ECT0 pair) + 2 plain (ECN split), got gso=%d plain=%d", len(w.gsoWrites), len(w.writes))
	}
	// Byte 1 high nibble holds TC[3:0]; ECN is the low 2 bits of that nibble,
	// which appears in byte 1 mask 0x30 (>>4 to read the codepoint value).
	g := w.gsoWrites[0]
	if len(g.pays) != 2 {
		t.Errorf("gso pay count=%d want 2", len(g.pays))
	}
	if got := (g.hdr[1] >> 4) & 0x03; got != ecnECT0 {
		t.Errorf("gso v6 ECN=0x%02x want 0x%02x", got, ecnECT0)
	}
	wantECN := []byte{ecnCE, ecnECT0}
	for i, wnt := range wantECN {
		if got := (w.writes[i][1] >> 4) & 0x03; got != wnt {
			t.Errorf("plain %d v6 ECN=0x%02x want 0x%02x", i, got, wnt)
		}
	}
}

// TestCoalescerNonAtomicSequentialIDsCoalesce: with DF clear, coalescing
// is allowed when the IPv4 IDs already run seed+1 per segment — kernel
// TSO's re-stamp then reproduces the originals exactly (the kernel GRO
// admission rule).
func TestCoalescerNonAtomicSequentialIDsCoalesce(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	pay := make([]byte, 1200)

	seq := uint32(1000)
	for i := range 3 {
		pkt := buildTCPv4(seq, tcpAck, pay)
		setIPv4ID(pkt, uint16(700+i), false)
		if err := c.Commit(pkt); err != nil {
			t.Fatal(err)
		}
		seq += uint32(len(pay))
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 || len(w.gsoWrites[0].pays) != 3 {
		t.Fatalf("sequential-ID DF=0 chain must coalesce: gso=%d", len(w.gsoWrites))
	}
	if id := binary.BigEndian.Uint16(w.gsoWrites[0].hdr[4:6]); id != 700 {
		t.Errorf("superpacket seed ID=%d want 700", id)
	}
}

// TestCoalescerNonAtomicIDGapDoesNotCoalesce: with DF clear and an ID jump
// mid-flow, neither the append path nor the flush-time merge may combine
// the segments — TSO would re-stamp seed+n and rewrite the second
// packet's ID, which is meaningful on non-atomic datagrams. Each stays a
// single-segment slot and flushes as a plain write with its original ID.
func TestCoalescerNonAtomicIDGapDoesNotCoalesce(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	pay := make([]byte, 1200)

	p1 := buildTCPv4(1000, tcpAck, pay)
	setIPv4ID(p1, 700, false)
	p2 := buildTCPv4(1000+uint32(len(pay)), tcpAck, pay)
	setIPv4ID(p2, 900, false)

	if err := c.Commit(p1); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(p2); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 2 || len(w.gsoWrites) != 0 {
		t.Fatalf("ID gap on DF=0 must not coalesce (append or merge): writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
	for i, want := range []uint16{700, 900} {
		if id := binary.BigEndian.Uint16(w.writes[i][4:6]); id != want {
			t.Errorf("write %d: ID=%d want %d (must be preserved)", i, id, want)
		}
	}
}

// TestCoalescerAtomicRandomIDsCoalesce guards the other direction: DF set
// makes the datagram atomic (RFC 6864), so arbitrary IDs must not block
// coalescing.
func TestCoalescerAtomicRandomIDsCoalesce(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	pay := make([]byte, 1200)

	p1 := buildTCPv4(1000, tcpAck, pay)
	setIPv4ID(p1, 0x1234, true)
	p2 := buildTCPv4(1000+uint32(len(pay)), tcpAck, pay)
	setIPv4ID(p2, 0x0007, true)

	if err := c.Commit(p1); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(p2); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 || len(w.gsoWrites[0].pays) != 2 {
		t.Fatalf("DF=1 chain with arbitrary IDs must coalesce: gso=%d", len(w.gsoWrites))
	}
}

// TestCoalescerSeqWrapAroundAppends pins the serial-number arithmetic on the
// append path: a chain crossing the 2^32 seq wrap must keep extending when
// contiguous.
func TestCoalescerSeqWrapAroundAppends(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)

	payA := bytes.Repeat([]byte{'A'}, 32)
	payB := bytes.Repeat([]byte{'B'}, 32)
	seqA := uint32(0xffffffe0) // 32 before the wrap: nextSeq lands exactly on 0

	if err := c.Commit(buildTCPv4(seqA, tcpAck, payA)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(0, tcpAck, payB)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write across the wrap, got %d (plain=%d)", len(w.gsoWrites), len(w.writes))
	}
	g := w.gsoWrites[0]
	const ipHdrLen = 20
	if seedSeq := binary.BigEndian.Uint32(g.hdr[ipHdrLen+4 : ipHdrLen+8]); seedSeq != seqA {
		t.Errorf("seed seq=%#x want %#x", seedSeq, seqA)
	}
	if len(g.pays) != 2 {
		t.Fatalf("segs=%d want 2", len(g.pays))
	}
	if !bytes.Equal(g.pays[0], payA) || !bytes.Equal(g.pays[1], payB) {
		t.Errorf("payload order wrong across the wrap: got %q then %q", g.pays[0][:1], g.pays[1][:1])
	}
}

// TestCoalescerUnparseableSealsAllChains: an unparseable packet's flow is
// unknowable, so it must close every open chain. Later data — even data
// seq-contiguous with a pre-existing chain — seeds a fresh slot and emits
// after the unparseable packet, exactly as transmitted.
func TestCoalescerUnparseableSealsAllChains(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := newTestTCPCoalescer(t, w)
	pay := make([]byte, 1200)

	if err := c.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildTCPv4(2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	// IHL=6 fakes IP options: the parse bails, flow key unknown.
	opts := buildTCPv4(5000, tcpAck, make([]byte, 500))
	opts[0] = 0x46
	if err := c.Commit(opts); err != nil {
		t.Fatal(err)
	}
	// Contiguous with the first chain (nextSeq 3400), but that chain is
	// sealed now: must not append, must not emit before the unparseable.
	if err := c.Commit(buildTCPv4(3400, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write (pre-fragment pair), got %d", len(w.gsoWrites))
	}
	if len(w.gsoWrites[0].pays) != 2 {
		t.Fatalf("pre-fragment chain segs=%d want 2", len(w.gsoWrites[0].pays))
	}
	if len(w.writes) != 2 {
		t.Fatalf("want 2 plain writes (unparseable + post-fragment seed), got %d", len(w.writes))
	}
	if w.writes[0][0] != 0x46 {
		t.Errorf("first plain write must be the unparseable packet")
	}
	if seq := binary.BigEndian.Uint32(w.writes[1][24:28]); seq != 3400 {
		t.Errorf("post-fragment data seq=%d want 3400", seq)
	}
	if len(w.order) != 3 || w.order[0] != "gso" || w.order[1] != "write" || w.order[2] != "write" {
		t.Fatalf("emission order = %v, want [gso write write]", w.order)
	}
}
