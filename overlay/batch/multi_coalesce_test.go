package batch

import (
	"bytes"
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
