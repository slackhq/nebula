package batch

import (
	"testing"

	"github.com/slackhq/nebula/test"
)

// TestMultiCoalescerRoutesByProto confirms TCP/UDP/other land in the right
// lane: TCP and UDP get coalesced when their lanes are enabled, anything
// else (ICMP here) falls through to plain Write.
func TestMultiCoalescerRoutesByProto(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	m := NewMultiCoalescer(w, test.NewLogger(), true, true)

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

// TestMultiCoalescerDisabledUDPFallsThrough verifies that when the UDP lane
// is disabled (e.g. kernel doesn't support USO), UDP packets still reach
// the kernel via the passthrough lane rather than being lost.
func TestMultiCoalescerDisabledUDPFallsThrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	m := NewMultiCoalescer(w, test.NewLogger(), true, false) // TSO on, USO off

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

// TestMultiCoalescerDisabledTCPFallsThrough mirrors the TSO=off case.
func TestMultiCoalescerDisabledTCPFallsThrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	m := NewMultiCoalescer(w, test.NewLogger(), false, true) // TSO off, USO on

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
