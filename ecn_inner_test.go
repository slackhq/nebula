package nebula

import (
	"encoding/binary"
	"log/slog"
	"testing"

	"golang.org/x/net/ipv4"
)

func TestInnerECN(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want byte
	}{
		{"empty", nil, 0},
		{"v4_NotECT", v4WithToS(0x00), 0x00},
		{"v4_ECT0", v4WithToS(0x02), 0x02},
		{"v4_ECT1", v4WithToS(0x01), 0x01},
		{"v4_CE", v4WithToS(0x03), 0x03},
		{"v4_DSCP_then_NotECT", v4WithToS(0x88 | 0x00), 0x00},
		{"v4_DSCP_then_CE", v4WithToS(0x88 | 0x03), 0x03},
		{"v6_NotECT", v6WithTC(0x00), 0x00},
		{"v6_ECT0", v6WithTC(0x02), 0x02},
		{"v6_CE", v6WithTC(0x03), 0x03},
		{"v6_DSCP_then_CE", v6WithTC(0x88 | 0x03), 0x03},
		{"unknown_version", []byte{0xa5, 0xff}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := innerECN(c.pkt)
			if got != c.want {
				t.Errorf("innerECN=0x%02x want 0x%02x", got, c.want)
			}
		})
	}
}

// v4WithToS returns a 2-byte slice tall enough for innerECN: byte 0 carries
// version=4 in the high nibble, byte 1 is the full ToS so we exercise both
// the DSCP and ECN portions through the byte 1 mask.
func v4WithToS(tos byte) []byte {
	return []byte{0x45, tos}
}

// v6WithTC builds a 2-byte slice that places a known traffic class value
// across bytes 0 (high nibble of TC) and 1 (low nibble of TC). innerECN
// extracts ECN as (b[1]>>4)&0x03, which corresponds to TC[1:0].
func v6WithTC(tc byte) []byte {
	return []byte{0x60 | (tc>>4)&0x0f, (tc & 0x0f) << 4}
}

func TestApplyOuterECN(t *testing.T) {
	silent := slog.New(slog.DiscardHandler)
	hi := &HostInfo{}

	// Build a v4 packet helper with a given inner ECN field.
	v4 := func(innerECN byte) []byte {
		// 20-byte minimal IPv4 header with ToS = innerECN (DSCP zeroed).
		return []byte{
			0x45, innerECN, 0, 28,
			0, 0, 0x40, 0,
			64, 6, 0, 0,
			10, 0, 0, 1,
			10, 0, 0, 2,
		}
	}
	// Build a v6 packet helper with a given inner ECN field. ECN occupies
	// TC[1:0] which sit at byte 1 mask 0x30.
	v6 := func(innerECN byte) []byte {
		// 40-byte minimal IPv6 header with TC[1:0] = innerECN.
		pkt := make([]byte, 40)
		pkt[0] = 0x60                   // version=6, TC[7:4]=0
		pkt[1] = (innerECN & 0x03) << 4 // TC[3:0]: low 2 bits = ECN, top 2 = DSCP-low (0)
		return pkt
	}

	type cell struct {
		outer    byte
		inner    byte
		wantECN  byte
		wantSame bool // expect inner unchanged (true => verify the byte didn't move)
	}

	// RFC 6040 normal-mode combine table. Only outer==CE causes mutation.
	table := []cell{
		{ecnNotECT, ecnNotECT, ecnNotECT, true},
		{ecnNotECT, ecnECT0, ecnECT0, true},
		{ecnNotECT, ecnECT1, ecnECT1, true},
		{ecnNotECT, ecnCE, ecnCE, true},

		{ecnECT0, ecnNotECT, ecnNotECT, true},
		{ecnECT0, ecnECT0, ecnECT0, true},
		{ecnECT0, ecnECT1, ecnECT1, true},
		{ecnECT0, ecnCE, ecnCE, true},

		{ecnECT1, ecnNotECT, ecnNotECT, true},
		{ecnECT1, ecnECT0, ecnECT0, true},
		{ecnECT1, ecnECT1, ecnECT1, true},
		{ecnECT1, ecnCE, ecnCE, true},

		{ecnCE, ecnNotECT, ecnNotECT, true}, // legacy: log, leave alone
		{ecnCE, ecnECT0, ecnCE, false},      // CE folded in
		{ecnCE, ecnECT1, ecnCE, false},
		{ecnCE, ecnCE, ecnCE, true},
	}

	for _, c := range table {
		t.Run("v4", func(t *testing.T) {
			pkt := v4(c.inner)
			applyOuterECN(pkt, c.outer, hi, silent)
			got := pkt[1] & 0x03
			if got != c.wantECN {
				t.Errorf("v4 outer=0x%02x inner=0x%02x: got 0x%02x want 0x%02x", c.outer, c.inner, got, c.wantECN)
			}
		})
		t.Run("v6", func(t *testing.T) {
			pkt := v6(c.inner)
			applyOuterECN(pkt, c.outer, hi, silent)
			got := (pkt[1] >> 4) & 0x03
			if got != c.wantECN {
				t.Errorf("v6 outer=0x%02x inner=0x%02x: got 0x%02x want 0x%02x", c.outer, c.inner, got, c.wantECN)
			}
		})
	}
}

// TestApplyOuterECN_IPv4ChecksumStaysValid guards against H1: folding an outer
// CE mark into the inner IPv4 ToS byte must keep the IPv4 header checksum valid.
// The passthrough emit paths write the packet verbatim, so a stale checksum
// turns an underlay congestion mark into packet loss at the receiver.
func TestApplyOuterECN_IPv4ChecksumStaysValid(t *testing.T) {
	silent := slog.New(slog.DiscardHandler)
	hi := &HostInfo{}

	// 20-byte IPv4 header with DSCP=0x88 and inner ECN = ECT(0). Folding CE
	// flips only the low two bits of the ToS byte while leaving DSCP intact.
	pkt := []byte{
		0x45, 0x88 | ecnECT0, 0, 40,
		0x1c, 0x46, 0x40, 0x00,
		64, 6, 0, 0,
		10, 0, 0, 1,
		10, 0, 0, 2,
	}
	// Stamp a correct header checksum before the fold.
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[:ipv4.HeaderLen]))
	if !ipv4HeaderChecksumValid(pkt[:ipv4.HeaderLen]) {
		t.Fatal("test setup: initial header checksum invalid")
	}

	applyOuterECN(pkt, ecnCE, hi, silent)

	// CE folded in, DSCP preserved.
	if got, want := pkt[1], byte(0x88|ecnCE); got != want {
		t.Fatalf("ToS after fold = 0x%02x, want 0x%02x", got, want)
	}
	// The incremental RFC 1624 update must leave the checksum valid and equal
	// to a full recompute over the mutated header.
	if !ipv4HeaderChecksumValid(pkt[:ipv4.HeaderLen]) {
		t.Fatalf("IPv4 header checksum invalid after CE fold: 0x%04x", binary.BigEndian.Uint16(pkt[10:12]))
	}
	if got, want := binary.BigEndian.Uint16(pkt[10:12]), ipv4HeaderChecksum(pkt[:ipv4.HeaderLen]); got != want {
		t.Fatalf("checksum = 0x%04x, full recompute = 0x%04x", got, want)
	}
}

// ipv4HeaderChecksum computes the RFC 1071 IPv4 header checksum over hdr,
// treating the checksum field (bytes 10:12) as zero.
func ipv4HeaderChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		if i == 10 {
			continue // checksum field
		}
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// ipv4HeaderChecksumValid reports whether the stored checksum matches a fresh
// computation over the header.
func ipv4HeaderChecksumValid(hdr []byte) bool {
	return binary.BigEndian.Uint16(hdr[10:12]) == ipv4HeaderChecksum(hdr)
}
