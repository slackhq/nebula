package batch

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/slackhq/nebula/test"
)

// newTestMultiCoalescer builds a batcher over w and asserts it really is
// multi-lane. NewMultiCoalescer collapses to a bare Passthrough when w can
// offload neither protocol, and a test that meant to exercise a lane would
// otherwise pass vacuously.
func newTestMultiCoalescer(tb testing.TB, w io.Writer) *MultiCoalescer {
	tb.Helper()
	b := NewMultiCoalescer(w, test.NewLogger())
	m, ok := b.(*MultiCoalescer)
	if !ok {
		tb.Fatalf("want a *MultiCoalescer, got %T", b)
	}
	return m
}

// TestMultiCoalescerRoutesByProto confirms TCP/UDP/other land in the right
// lane: TCP and UDP get coalesced when their lanes are enabled, anything
// else (ICMP here) falls through to plain Write.
func TestMultiCoalescerRoutesByProto(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	m := newTestMultiCoalescer(t, w)

	tcpPay := make([]byte, 1200)
	udpPay := make([]byte, 1200)
	icmp := make([]byte, 28)
	icmp[0] = 0x45
	icmp[2] = 0
	icmp[3] = 28
	icmp[9] = 1

	if err := m.Commit(buildTCPv4(1000, tcpAck, tcpPay)); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4(2200, tcpAck, tcpPay)); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv4(2000, 53, udpPay)); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv4(2000, 53, udpPay)); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(icmp); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	// 1 TCP super (2 segments) + 1 UDP super (2 segments) = 2 gso writes.
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes (one TCP + one UDP), got %d", len(w.gsoWrites))
	}
	if len(w.writes) != 1 {
		t.Fatalf("want 1 plain write (ICMP), got %d", len(w.writes))
	}
}

// TestMultiCoalescerNoUSOFallsThrough verifies that on a queue without USO
// (older kernel: TSO but no GSO_UDP_L4) the UDP lane never comes up and UDP
// packets still reach the kernel via passthrough rather than being lost.
func TestMultiCoalescerNoUSOFallsThrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true, noUSO: true}
	m := newTestMultiCoalescer(t, w)
	if m.udp != nil {
		t.Fatal("UDP lane must not come up without USO")
	}

	if err := m.Commit(buildUDPv4(1000, 53, make([]byte, 800))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv4(1000, 53, make([]byte, 800))); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 0 {
		t.Errorf("UDP must NOT be coalesced when USO disabled, got %d gso writes", len(w.gsoWrites))
	}
	if len(w.writes) != 2 {
		t.Errorf("UDP must pass through as 2 plain writes, got %d", len(w.writes))
	}
}

// TestMultiCoalescerNoOffloadsIsPassthrough covers a queue that can't offload
// anything. Both lane constructors refuse, so there's nothing left to
// dispatch between and NewMultiCoalescer hands back the passthrough lane
// itself — no wrapper, no per-packet protocol demux, and every packet reaches
// the kernel in arrival order. This is the case Interface.activate used to
// special-case with a bare Passthrough.
func TestMultiCoalescerNoOffloadsIsPassthrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: false}
	m := NewMultiCoalescer(w, test.NewLogger())

	if _, ok := m.(*Passthrough); !ok {
		t.Fatalf("want a bare *Passthrough when neither offload is available, got %T", m)
	}
	pkts := [][]byte{
		buildTCPv4(1000, tcpAck, make([]byte, 1200)),
		buildUDPv4(1000, 53, make([]byte, 800)),
		buildTCPv4(2200, tcpAck, make([]byte, 1200)),
	}
	for _, p := range pkts {
		if err := m.Commit(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 0 {
		t.Errorf("no GSO writes possible, got %d", len(w.gsoWrites))
	}
	if len(w.writes) != len(pkts) {
		t.Fatalf("want %d plain writes, got %d", len(pkts), len(w.writes))
	}
	// One lane for everything means arrival order survives end to end.
	for i, want := range pkts {
		if !bytes.Equal(w.writes[i], want) {
			t.Errorf("write %d out of order or corrupt", i)
		}
	}
}

// buildUDPv6Fragment builds an IPv6 packet whose extension chain is a
// single fragment header (NH=44) naming UDP as the terminal protocol —
// a first fragment (offset 0, MF set) carrying the UDP header and a
// partial payload.
func buildUDPv6Fragment(sport, dport uint16, payload []byte) []byte {
	const ipHdrLen = 40
	const fragHdrLen = 8
	const udpHdrLen = 8
	total := ipHdrLen + fragHdrLen + udpHdrLen + len(payload)
	pkt := make([]byte, total)

	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(total-ipHdrLen))
	pkt[6] = 44 // fragment extension header
	pkt[7] = 64
	pkt[8] = 0xfe
	pkt[9] = 0x80
	pkt[23] = 1
	pkt[24] = 0xfe
	pkt[25] = 0x80
	pkt[39] = 2

	pkt[40] = ipProtoUDP                              // fragment's next header
	binary.BigEndian.PutUint16(pkt[42:44], 0x0001)    // offset 0, MF set
	binary.BigEndian.PutUint32(pkt[44:48], 0x1badf00) // identification

	binary.BigEndian.PutUint16(pkt[48:50], sport)
	binary.BigEndian.PutUint16(pkt[50:52], dport)
	binary.BigEndian.PutUint16(pkt[52:54], uint16(udpHdrLen+len(payload)))
	copy(pkt[56:], payload)
	return pkt
}

// TestMultiCoalescerIPv6FragmentStaysInLane locks in extension-header
// routing: a fragment whose chain terminates in UDP must ride the UDP lane
// as an in-lane passthrough — emitted ahead of later same-flow datagrams —
// not the passthrough lane, which flushes after every coalescer lane and
// would reorder it behind data that arrived after it.
func TestMultiCoalescerIPv6FragmentStaysInLane(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	m := newTestMultiCoalescer(t, w)

	if err := m.Commit(buildUDPv6Fragment(2000, 53, make([]byte, 512))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv6(2000, 53, make([]byte, 800))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv6(2000, 53, make([]byte, 800))); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 {
		t.Fatalf("want the fragment as 1 plain write, got %d", len(w.writes))
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want the two whole datagrams coalesced into 1 gso write, got %d", len(w.gsoWrites))
	}
	// Arrival order was fragment-then-data; same-lane routing must keep it.
	if w.order[0] != "write" {
		t.Fatalf("fragment must be emitted before later data (in-lane passthrough), order=%v", w.order)
	}
}

// TestMultiCoalescerNoTSOFallsThrough mirrors the no-TSO case.
func TestMultiCoalescerNoTSOFallsThrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true, noTSO: true}
	m := newTestMultiCoalescer(t, w)
	if m.tcp != nil {
		t.Fatal("TCP lane must not come up without TSO")
	}

	pay := make([]byte, 1200)
	if err := m.Commit(buildTCPv4(1000, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4(2200, tcpAck, pay)); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 0 {
		t.Errorf("TCP must NOT be coalesced when TSO disabled, got %d gso writes", len(w.gsoWrites))
	}
	if len(w.writes) != 2 {
		t.Errorf("TCP must pass through as 2 plain writes, got %d", len(w.writes))
	}
}
