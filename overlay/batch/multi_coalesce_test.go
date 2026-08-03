package batch

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/test"
)

// keySeq hands out SortKeys with ascending counters in a fixed epoch, for
// tests where commit order IS transmission order.
type keySeq struct {
	epoch, counter uint64
}

func (k *keySeq) next() SortKey {
	k.counter++
	return SortKey{Epoch: k.epoch, Counter: k.counter}
}

// newTestMultiCoalescer builds a batcher over w and asserts the concrete
// type so tests can reach into the lanes.
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
	k := &keySeq{epoch: 1}

	tcpPay := make([]byte, 1200)
	udpPay := make([]byte, 1200)
	icmp := make([]byte, 28)
	icmp[0] = 0x45
	icmp[2] = 0
	icmp[3] = 28
	icmp[9] = 1

	if err := m.Commit(buildTCPv4(1000, tcpAck, tcpPay), k.next(), testPP(buildTCPv4(1000, tcpAck, tcpPay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4(2200, tcpAck, tcpPay), k.next(), testPP(buildTCPv4(2200, tcpAck, tcpPay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv4(2000, 53, udpPay), k.next(), testPP(buildUDPv4(2000, 53, udpPay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv4(2000, 53, udpPay), k.next(), testPP(buildUDPv4(2000, 53, udpPay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(icmp, k.next(), testPP(icmp)); err != nil {
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

// TestMultiCoalescerRestoresTransmissionOrder is the core staging-sort
// property: packets committed out of counter order (wire reorder inside one
// flush batch) are replayed into the lanes in transmission order, so the
// reorder never fragments the coalesce chain — one superpacket, in seq
// order, exactly as if the wire had never reordered. The retransmit shape
// falls out of the same key: a retransmit carries a lower seq but a HIGHER
// counter (it was encrypted later), so it emits after the data it trails.
func TestMultiCoalescerRestoresTransmissionOrder(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	m := newTestMultiCoalescer(t, w)
	pay := make([]byte, 1200)

	// Transmission order: seq 1000 (c1), 2200 (c2), 3400 (c3).
	// Arrival order: 3400, 1000, 2200.
	if err := m.Commit(buildTCPv4(3400, tcpAck, pay), SortKey{Epoch: 1, Counter: 3}, testPP(buildTCPv4(3400, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4(1000, tcpAck, pay), SortKey{Epoch: 1, Counter: 1}, testPP(buildTCPv4(1000, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4(2200, tcpAck, pay), SortKey{Epoch: 1, Counter: 2}, testPP(buildTCPv4(2200, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 || len(w.writes) != 0 {
		t.Fatalf("want 1 gso write (unfragmented chain), got gso=%d plain=%d", len(w.gsoWrites), len(w.writes))
	}
	g := w.gsoWrites[0]
	if len(g.pays) != 3 {
		t.Fatalf("segs=%d want 3", len(g.pays))
	}
	const ipHdrLen = 20
	if seedSeq := binary.BigEndian.Uint32(g.hdr[ipHdrLen+4 : ipHdrLen+8]); seedSeq != 1000 {
		t.Errorf("seed seq=%d want 1000", seedSeq)
	}

	// Retransmit: seq 1000 again but counter 4 — sorts after seq 4600 (c3).
	w.writes, w.gsoWrites, w.order = nil, nil, nil
	if err := m.Commit(buildTCPv4(1000, tcpAck, pay), SortKey{Epoch: 1, Counter: 4}, testPP(buildTCPv4(1000, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4(4600, tcpAck, pay), SortKey{Epoch: 1, Counter: 3}, testPP(buildTCPv4(4600, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 2 {
		t.Fatalf("want 2 plain writes, got %d (gso=%d)", len(w.writes), len(w.gsoWrites))
	}
	first := binary.BigEndian.Uint32(w.writes[0][24:28])
	second := binary.BigEndian.Uint32(w.writes[1][24:28])
	if first != 4600 || second != 1000 {
		t.Fatalf("emission (%d, %d), want (4600, 1000): retransmit must not overtake in-flight data", first, second)
	}
}

// TestMultiCoalescerRestoresOrderAcrossFlows scrambles two interleaved flows;
// the staging sort must repair each flow into one superpacket without any
// cross-flow contamination.
func TestMultiCoalescerRestoresOrderAcrossFlows(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	m := newTestMultiCoalescer(t, w)
	pay := make([]byte, 1200)

	// Transmission: A.100 (c1), B.500 (c2), A.1300 (c3), B.1700 (c4).
	// Arrival: A.1300, B.1700, A.100, B.500.
	if err := m.Commit(buildTCPv4Ports(1000, 2000, 1300, tcpAck, pay), SortKey{Epoch: 1, Counter: 3}, testPP(buildTCPv4Ports(1000, 2000, 1300, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4Ports(3000, 2000, 1700, tcpAck, pay), SortKey{Epoch: 1, Counter: 4}, testPP(buildTCPv4Ports(3000, 2000, 1700, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4Ports(1000, 2000, 100, tcpAck, pay), SortKey{Epoch: 1, Counter: 1}, testPP(buildTCPv4Ports(1000, 2000, 100, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4Ports(3000, 2000, 500, tcpAck, pay), SortKey{Epoch: 1, Counter: 2}, testPP(buildTCPv4Ports(3000, 2000, 500, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes (one per flow), got %d (plain=%d)", len(w.gsoWrites), len(w.writes))
	}
	for i, g := range w.gsoWrites {
		if len(g.pays) != 2 {
			t.Errorf("gso[%d] segs=%d want 2", i, len(g.pays))
		}
		const ipHdrLen = 20
		seedSeq := binary.BigEndian.Uint32(g.hdr[ipHdrLen+4 : ipHdrLen+8])
		sport := binary.BigEndian.Uint16(g.hdr[ipHdrLen : ipHdrLen+2])
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

// TestMultiCoalescerEpochOrdersAcrossRehandshake: a re-handshake replaces
// the tunnel, and the replacement's counter space starts near zero — raw
// counter order would emit the new tunnel's packets first while the old
// tunnel's backlog is still arriving. The epoch key must dominate:
// everything from the old tunnel emits before anything from the new one.
func TestMultiCoalescerEpochOrdersAcrossRehandshake(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	m := newTestMultiCoalescer(t, w)
	pay := make([]byte, 1200)

	// New session's first data arrives before the old session's last data.
	if err := m.Commit(buildTCPv4(2200, tcpAck, pay), SortKey{Epoch: 8, Counter: 1}, testPP(buildTCPv4(2200, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4(1000, tcpAck, pay), SortKey{Epoch: 7, Counter: 9_000_000}, testPP(buildTCPv4(1000, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	// Same flow, contiguous seq, identical headers: after the epoch sort the
	// two segments append into one superpacket seeded by the OLD session's
	// packet.
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write, got %d (plain=%d)", len(w.gsoWrites), len(w.writes))
	}
	const ipHdrLen = 20
	if seedSeq := binary.BigEndian.Uint32(w.gsoWrites[0].hdr[ipHdrLen+4 : ipHdrLen+8]); seedSeq != 1000 {
		t.Errorf("seed seq=%d want 1000 (old session first)", seedSeq)
	}
}

// TestMultiCoalescerNoUSOFallsThrough verifies that on a queue without USO
// (older kernel: TSO but no GSO_UDP_L4) the UDP lane never comes up and UDP
// packets still reach the kernel via verbatim rather than being lost.
func TestMultiCoalescerNoUSOFallsThrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true, noUSO: true}
	m := newTestMultiCoalescer(t, w)
	k := &keySeq{epoch: 1}
	if m.udp != nil {
		t.Fatal("UDP lane must not come up without USO")
	}

	if err := m.Commit(buildUDPv4(1000, 53, make([]byte, 800)), k.next(), testPP(buildUDPv4(1000, 53, make([]byte, 800)))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv4(1000, 53, make([]byte, 800)), k.next(), testPP(buildUDPv4(1000, 53, make([]byte, 800)))); err != nil {
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

// TestMultiCoalescerNoOffloadsStillSorts covers a queue that can't offload
// anything. Both lane constructors refuse, so every packet rides the
// verbatim lane — but the staging sort still applies, so emission follows
// transmission order even without GSO.
func TestMultiCoalescerNoOffloadsStillSorts(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: false}
	m := newTestMultiCoalescer(t, w)
	if m.tcp != nil || m.udp != nil {
		t.Fatal("no lane may come up without offloads")
	}
	pkts := [][]byte{
		buildTCPv4(1000, tcpAck, make([]byte, 1200)),
		buildUDPv4(1000, 53, make([]byte, 800)),
		buildTCPv4(2200, tcpAck, make([]byte, 1200)),
	}
	// Committed in reverse transmission order; keys carry the truth.
	for i := len(pkts) - 1; i >= 0; i-- {
		if err := m.Commit(pkts[i], SortKey{Epoch: 1, Counter: uint64(i + 1)}, testPP(pkts[i])); err != nil {
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
	// One lane for everything means the sorted order survives end to end.
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
// as an in-lane verbatim — emitted ahead of later same-flow datagrams —
// not the verbatim lane, which flushes after every coalescer lane and
// would reorder it behind data that arrived after it.
func TestMultiCoalescerIPv6FragmentStaysInLane(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	m := newTestMultiCoalescer(t, w)
	k := &keySeq{epoch: 1}

	if err := m.Commit(buildUDPv6Fragment(2000, 53, make([]byte, 512)), k.next(), testPP(buildUDPv6Fragment(2000, 53, make([]byte, 512)))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv6(2000, 53, make([]byte, 800)), k.next(), testPP(buildUDPv6(2000, 53, make([]byte, 800)))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv6(2000, 53, make([]byte, 800)), k.next(), testPP(buildUDPv6(2000, 53, make([]byte, 800)))); err != nil {
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
	// Transmission order was fragment-then-data; same-lane routing must keep it.
	if w.order[0] != "write" {
		t.Fatalf("fragment must be emitted before later data (in-lane verbatim), order=%v", w.order)
	}
}

// TestMultiCoalescerFragmentSealsUDPChains: an unparseable datagram
// (fragment) seals every open UDP chain, so datagrams from before and after
// it land in separate superpackets and the fragment holds its transmission-
// order position between them.
func TestMultiCoalescerFragmentSealsUDPChains(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	m := newTestMultiCoalescer(t, w)
	k := &keySeq{epoch: 1}

	if err := m.Commit(buildUDPv6(2000, 53, make([]byte, 800)), k.next(), testPP(buildUDPv6(2000, 53, make([]byte, 800)))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv6(2000, 53, make([]byte, 800)), k.next(), testPP(buildUDPv6(2000, 53, make([]byte, 800)))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv6Fragment(2000, 53, make([]byte, 512)), k.next(), testPP(buildUDPv6Fragment(2000, 53, make([]byte, 512)))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv6(2000, 53, make([]byte, 800)), k.next(), testPP(buildUDPv6(2000, 53, make([]byte, 800)))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildUDPv6(2000, 53, make([]byte, 800)), k.next(), testPP(buildUDPv6(2000, 53, make([]byte, 800)))); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes (chains sealed around the fragment), got %d", len(w.gsoWrites))
	}
	if len(w.writes) != 1 {
		t.Fatalf("want the fragment as 1 plain write, got %d", len(w.writes))
	}
	want := []string{"gso", "write", "gso"}
	if len(w.order) != 3 || w.order[0] != want[0] || w.order[1] != want[1] || w.order[2] != want[2] {
		t.Fatalf("emission order = %v, want %v", w.order, want)
	}
}

// TestMultiCoalescerNoTSOFallsThrough mirrors the no-TSO case.
func TestMultiCoalescerNoTSOFallsThrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true, noTSO: true}
	m := newTestMultiCoalescer(t, w)
	k := &keySeq{epoch: 1}
	if m.tcp != nil {
		t.Fatal("TCP lane must not come up without TSO")
	}

	pay := make([]byte, 1200)
	if err := m.Commit(buildTCPv4(1000, tcpAck, pay), k.next(), testPP(buildTCPv4(1000, tcpAck, pay))); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(buildTCPv4(2200, tcpAck, pay), k.next(), testPP(buildTCPv4(2200, tcpAck, pay))); err != nil {
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

// testPP derives the ParsedPacket newPacket would produce for the packet
// shapes the tests build: plain v4/v6, v4 with options or fragment bits set,
// and the single-fragment-header v6 shape from buildUDPv6Fragment. Anything
// unrecognizable stays zero (proto 0 routes to the passthrough lane).
func testPP(pkt []byte) *firewall.ParsedPacket {
	pp := &firewall.ParsedPacket{}
	if len(pkt) < 20 {
		return pp
	}
	switch pkt[0] >> 4 {
	case 4:
		pp.Protocol = pkt[9]
		pp.IPHdrLen = int(pkt[0]&0x0f) * 4
		pp.FragAny = binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0
	case 6:
		pp.Protocol = pkt[6]
		pp.IPHdrLen = 40
		if pp.Protocol == 44 { // fragment extension header
			pp.Protocol = pkt[40]
			pp.IPHdrLen = 48
			pp.FragAny = true
		}
	}
	return pp
}
