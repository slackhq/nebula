package batch

import (
	"encoding/binary"
	"testing"
)

// buildUDPv4 builds a minimal IPv4+UDP packet with the given payload and ports.
func buildUDPv4(sport, dport uint16, payload []byte) []byte {
	const ipHdrLen = 20
	const udpHdrLen = 8
	total := ipHdrLen + udpHdrLen + len(payload)
	pkt := make([]byte, total)

	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = ipProtoUDP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})

	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpHdrLen+len(payload)))
	binary.BigEndian.PutUint16(pkt[26:28], 0)

	copy(pkt[28:], payload)
	return pkt
}

// buildUDPv6 builds a minimal IPv6+UDP packet.
func buildUDPv6(sport, dport uint16, payload []byte) []byte {
	const ipHdrLen = 40
	const udpHdrLen = 8
	total := ipHdrLen + udpHdrLen + len(payload)
	pkt := make([]byte, total)

	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpHdrLen+len(payload)))
	pkt[6] = ipProtoUDP
	pkt[7] = 64
	pkt[8] = 0xfe
	pkt[9] = 0x80
	pkt[23] = 1
	pkt[24] = 0xfe
	pkt[25] = 0x80
	pkt[39] = 2

	binary.BigEndian.PutUint16(pkt[40:42], sport)
	binary.BigEndian.PutUint16(pkt[42:44], dport)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpHdrLen+len(payload)))
	binary.BigEndian.PutUint16(pkt[46:48], 0)

	copy(pkt[48:], payload)
	return pkt
}

func TestUDPCoalescerPassthroughWhenGSOUnavailable(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: false}
	c := NewUDPCoalescer(w)
	pkt := buildUDPv4(1000, 53, make([]byte, 100))
	if err := c.Commit(pkt); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 0 || len(w.gsoWrites) != 0 {
		t.Fatalf("no Add-time writes: writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("want single plain write, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestUDPCoalescerNonUDPPassthrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	// ICMP packet
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
		t.Fatalf("ICMP must pass through unchanged: writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestUDPCoalescerSeedThenFlushAlone(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	pkt := buildUDPv4(1000, 53, make([]byte, 800))
	if err := c.Commit(pkt); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Single-segment flush goes through WriteGSO; the writer infers GSO_NONE
	// from len(pays)==1 and the kernel fills in the UDP csum (NEEDS_CSUM).
	if len(w.gsoWrites) != 1 || len(w.writes) != 0 {
		t.Fatalf("single-seg flush: writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

func TestUDPCoalescerCoalescesEqualSized(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	pay := make([]byte, 1200)
	for i := 0; i < 3; i++ {
		if err := c.Commit(buildUDPv4(1000, 53, pay)); err != nil {
			t.Fatal(err)
		}
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
	if len(g.pays) != 3 {
		t.Errorf("pay count=%d want 3", len(g.pays))
	}
	if g.csumStart != 20 {
		t.Errorf("csumStart=%d want 20", g.csumStart)
	}
	// IP totalLen and UDP length must be the TOTAL across all segments —
	// the kernel's ip_rcv_core trims skbs to iph->tot_len, so a per-segment
	// value would silently drop everything but the first segment. Total =
	// IP(20) + UDP(8) + 3*1200 = 3628.
	gotTotalLen := binary.BigEndian.Uint16(g.hdr[2:4])
	if gotTotalLen != 3628 {
		t.Errorf("ipv4 total_len=%d want 3628 (must be total across segments)", gotTotalLen)
	}
	gotUDPLen := binary.BigEndian.Uint16(g.hdr[20+4 : 20+6])
	if gotUDPLen != 8+3*1200 {
		t.Errorf("udp len=%d want %d", gotUDPLen, 8+3*1200)
	}
}

// Last segment may be shorter, sealing the chain.
func TestUDPCoalescerShortLastSegmentSeals(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	full := make([]byte, 1200)
	tail := make([]byte, 600)
	if err := c.Commit(buildUDPv4(1000, 53, full)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildUDPv4(1000, 53, full)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildUDPv4(1000, 53, tail)); err != nil {
		t.Fatal(err)
	}
	// A 4th packet, even same-sized, must NOT join — chain is sealed.
	if err := c.Commit(buildUDPv4(1000, 53, full)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes (sealed + new seed), got %d", len(w.gsoWrites))
	}
	if len(w.gsoWrites[0].pays) != 3 {
		t.Errorf("first super: want 3 pays, got %d", len(w.gsoWrites[0].pays))
	}
	if len(w.gsoWrites[1].pays) != 1 {
		t.Errorf("second super: want 1 pay (re-seed), got %d", len(w.gsoWrites[1].pays))
	}
}

// A larger-than-gsoSize packet cannot extend the slot — it reseeds.
func TestUDPCoalescerLargerThanSeedReseeds(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	if err := c.Commit(buildUDPv4(1000, 53, make([]byte, 800))); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildUDPv4(1000, 53, make([]byte, 1200))); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 separate seeds, got %d", len(w.gsoWrites))
	}
}

// Different 5-tuples must not coalesce.
func TestUDPCoalescerDifferentFlowsKeepSeparate(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	pay := make([]byte, 800)
	if err := c.Commit(buildUDPv4(1000, 53, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildUDPv4(2000, 53, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildUDPv4(1000, 53, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(buildUDPv4(2000, 53, pay)); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Two flows × 2 datagrams each = 2 superpackets of 2 segments.
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes (one per flow), got %d", len(w.gsoWrites))
	}
	for i, g := range w.gsoWrites {
		if len(g.pays) != 2 {
			t.Errorf("super %d: want 2 pays, got %d", i, len(g.pays))
		}
	}
}

// Caps at udpCoalesceMaxSegs.
func TestUDPCoalescerCapsAtMaxSegs(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	pay := make([]byte, 100)
	for i := 0; i < udpCoalesceMaxSegs+5; i++ {
		if err := c.Commit(buildUDPv4(1000, 53, pay)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// First superpacket holds udpCoalesceMaxSegs segments; the spillover
	// reseeds a new one.
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 gso writes (cap then reseed), got %d", len(w.gsoWrites))
	}
	if len(w.gsoWrites[0].pays) != udpCoalesceMaxSegs {
		t.Errorf("first super: pays=%d want %d", len(w.gsoWrites[0].pays), udpCoalesceMaxSegs)
	}
	if len(w.gsoWrites[1].pays) != 5 {
		t.Errorf("second super: pays=%d want 5", len(w.gsoWrites[1].pays))
	}
}

// CE marks on appended segments must be merged into the seed's IP TOS.
func TestUDPCoalescerMergesCEMark(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	pay := make([]byte, 800)
	pkt0 := buildUDPv4(1000, 53, pay) // ECN=00
	pkt1 := buildUDPv4(1000, 53, pay)
	pkt1[1] = 0x03 // CE
	pkt2 := buildUDPv4(1000, 53, pay)
	if err := c.Commit(pkt0); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(pkt1); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(pkt2); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 merged gso write, got %d (plain=%d)", len(w.gsoWrites), len(w.writes))
	}
	if w.gsoWrites[0].hdr[1]&0x03 != 0x03 {
		t.Errorf("CE not merged into seed (tos=%#x)", w.gsoWrites[0].hdr[1])
	}
}

// IPv6 path: same flow, equal-sized → coalesced.
func TestUDPCoalescerIPv6Coalesces(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	pay := make([]byte, 1200)
	for i := 0; i < 3; i++ {
		if err := c.Commit(buildUDPv6(1000, 53, pay)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 1 {
		t.Fatalf("want 1 gso write, got %d", len(w.gsoWrites))
	}
	g := w.gsoWrites[0]
	if !g.isV6 {
		t.Errorf("expected v6 write")
	}
	if g.csumStart != 40 {
		t.Errorf("csumStart=%d want 40", g.csumStart)
	}
	// IPv6 payload_len and UDP length must be TOTAL — kernel's
	// ip6_rcv_core trims to payload_len + ipv6 hdr size. Total UDP = 8 +
	// 3*1200 = 3608.
	gotPlen := binary.BigEndian.Uint16(g.hdr[4:6])
	if gotPlen != 8+3*1200 {
		t.Errorf("ipv6 payload_len=%d want %d (must be total)", gotPlen, 8+3*1200)
	}
	gotUDPLen := binary.BigEndian.Uint16(g.hdr[40+4 : 40+6])
	if gotUDPLen != 8+3*1200 {
		t.Errorf("udp len=%d want %d", gotUDPLen, 8+3*1200)
	}
}

// DSCP differences must reseed (headers don't match outside ECN).
func TestUDPCoalescerDSCPMismatchReseeds(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	pay := make([]byte, 800)
	pkt0 := buildUDPv4(1000, 53, pay)
	pkt1 := buildUDPv4(1000, 53, pay)
	pkt1[1] = 0xb8 // EF DSCP, ECN=0
	if err := c.Commit(pkt0); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(pkt1); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.gsoWrites) != 2 {
		t.Fatalf("want 2 separate seeds (different DSCP), got %d", len(w.gsoWrites))
	}
}

// Fragmented IPv4 must not be coalesced.
func TestUDPCoalescerFragmentedIPv4PassesThrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	pkt := buildUDPv4(1000, 53, make([]byte, 200))
	binary.BigEndian.PutUint16(pkt[6:8], 0x2000) // MF=1
	if err := c.Commit(pkt); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("frag must pass through plain, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}

// IPv4 with options is not admissible (we require IHL=5).
func TestUDPCoalescerIPv4WithOptionsPassesThrough(t *testing.T) {
	w := &fakeTunWriter{gsoEnabled: true}
	c := NewUDPCoalescer(w)
	pkt := buildUDPv4(1000, 53, make([]byte, 200))
	pkt[0] = 0x46 // IHL = 6 (24-byte IPv4 header — has options)
	if err := c.Commit(pkt); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || len(w.gsoWrites) != 0 {
		t.Fatalf("ipv4-with-options must pass through plain, got writes=%d gso=%d", len(w.writes), len(w.gsoWrites))
	}
}
