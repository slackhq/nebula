//go:build linux && !android

package virtio

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/slackhq/nebula/overlay/checksum"
)

// verifyChecksum confirms that the one's-complement sum across b, seeded with
// a folded pseudo-header sum, equals all-ones (a valid on-wire checksum).
// A corrupted header stamped into a segment makes this fail even when the
// checksum field itself was computed from the (pristine) base sums, because
// the bytes the receiver would sum no longer match what was checksummed.
func verifyChecksum(b []byte, pseudo uint16) bool {
	return checksum.Checksum(b, pseudo) == 0xffff
}

// pseudoHeaderIPv4 folds the TCP/UDP pseudo-header sum from a segment's own
// address and length fields, used to independently verify its L4 checksum.
func pseudoHeaderIPv4(src, dst []byte, proto byte, l4Len int) uint16 {
	s := uint32(checksum.Checksum(src, 0)) + uint32(checksum.Checksum(dst, 0))
	s += uint32(proto) + uint32(l4Len)
	s = (s & 0xffff) + (s >> 16)
	s = (s & 0xffff) + (s >> 16)
	return uint16(s)
}

// buildTCPv4Super constructs a synthetic IPv4/TCP TSO superpacket with a
// payload of payLen bytes and returns it alongside the header fields the
// segmenter needs. The header is a fixed 40 bytes (20 IPv4 + 20 TCP).
func buildTCPv4Super(payLen int) (pkt []byte, hdrLen, csumStart uint16) {
	const ipLen = 20
	const tcpLen = 20
	pkt = make([]byte, ipLen+tcpLen+payLen)

	// IPv4 header.
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen+tcpLen+payLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x4242) // ID
	pkt[8] = 64                                  // TTL
	pkt[9] = unix.IPPROTO_TCP
	copy(pkt[12:16], []byte{10, 0, 0, 1}) // src
	copy(pkt[16:20], []byte{10, 0, 0, 2}) // dst

	// TCP header.
	binary.BigEndian.PutUint16(pkt[20:22], 12345) // sport
	binary.BigEndian.PutUint16(pkt[22:24], 80)    // dport
	binary.BigEndian.PutUint32(pkt[24:28], 10000) // seq
	binary.BigEndian.PutUint32(pkt[28:32], 20000) // ack
	pkt[32] = 0x50                                // data offset 5 words
	pkt[33] = 0x18                                // ACK | PSH
	binary.BigEndian.PutUint16(pkt[34:36], 65535) // window

	for i := range payLen {
		pkt[ipLen+tcpLen+i] = byte(i & 0xff)
	}
	return pkt, ipLen + tcpLen, ipLen
}

// buildUDPv4Super constructs a synthetic IPv4/UDP USO superpacket with a
// payload of payLen bytes. Header is a fixed 28 bytes (20 IPv4 + 8 UDP).
func buildUDPv4Super(payLen int) (pkt []byte, hdrLen, csumStart uint16) {
	const ipLen = 20
	const udpLen = 8
	pkt = make([]byte, ipLen+udpLen+payLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen+udpLen+payLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x4242)
	pkt[8] = 64
	pkt[9] = unix.IPPROTO_UDP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})

	binary.BigEndian.PutUint16(pkt[20:22], 12345) // sport
	binary.BigEndian.PutUint16(pkt[22:24], 53)    // dport

	for i := range payLen {
		pkt[ipLen+udpLen+i] = byte(i & 0xff)
	}
	return pkt, ipLen + udpLen, ipLen
}

// collectTCP segments a fresh copy of pkt and returns each segment as an
// independent slice so assertions can run after segmentation completes.
func collectTCP(t *testing.T, pkt []byte, hdrLen, csumStart, gsoSize uint16) [][]byte {
	t.Helper()
	work := append([]byte(nil), pkt...)
	var out [][]byte
	err := SegmentTCP(work, hdrLen, csumStart, gsoSize, func(seg []byte) error {
		out = append(out, append([]byte(nil), seg...))
		return nil
	})
	if err != nil {
		t.Fatalf("SegmentTCP: %v", err)
	}
	return out
}

func collectUDP(t *testing.T, pkt []byte, hdrLen, csumStart, gsoSize uint16) [][]byte {
	t.Helper()
	work := append([]byte(nil), pkt...)
	var out [][]byte
	err := SegmentUDP(work, hdrLen, csumStart, gsoSize, func(seg []byte) error {
		out = append(out, append([]byte(nil), seg...))
		return nil
	})
	if err != nil {
		t.Fatalf("SegmentUDP: %v", err)
	}
	return out
}

// TestSegmentTCPHeaderNotCorrupted is the regression test for the in-place
// header-slide bug: when gsoSize < headerLen the old code stamped each
// segment's header from pkt[:headerLen], which had already been overwritten
// by the previous segment's overlapping stamp, so segments 2..n carried a
// corrupted header (garbage src/dst/ports/seq). Every segment must instead
// carry the ORIGINAL constant header fields with correct per-segment seq.
func TestSegmentTCPHeaderNotCorrupted(t *testing.T) {
	const origSeq = 10000
	cases := []struct {
		name    string
		payLen  int
		gsoSize uint16
	}{
		// gsoSize (8) < headerLen (40): the bug's trigger. Even split.
		{"small-gso-even", 40, 8},
		// gsoSize (8) < headerLen (40) with a short final segment.
		{"small-gso-odd-tail", 44, 8},
		// gsoSize (100) >= headerLen (40): the normal path, must still work.
		{"normal-gso", 250, 100},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt, hdrLen, csumStart := buildTCPv4Super(tc.payLen)
			gso := int(tc.gsoSize)
			wantSeg := (tc.payLen + gso - 1) / gso
			segs := collectTCP(t, pkt, hdrLen, csumStart, tc.gsoSize)
			if len(segs) != wantSeg {
				t.Fatalf("got %d segments, want %d", len(segs), wantSeg)
			}

			off := 0
			for i, seg := range segs {
				// Constant header fields must be identical to the original in
				// EVERY segment. These are exactly the bytes the old code
				// corrupted in segments 2..n.
				if got := seg[0]; got != 0x45 {
					t.Errorf("seg %d: version/IHL byte=%#x want 0x45", i, got)
				}
				if seg[9] != unix.IPPROTO_TCP {
					t.Errorf("seg %d: proto=%d want %d", i, seg[9], unix.IPPROTO_TCP)
				}
				if !bytes.Equal(seg[12:16], []byte{10, 0, 0, 1}) {
					t.Errorf("seg %d: src=%v want [10 0 0 1]", i, seg[12:16])
				}
				if !bytes.Equal(seg[16:20], []byte{10, 0, 0, 2}) {
					t.Errorf("seg %d: dst=%v want [10 0 0 2]", i, seg[16:20])
				}
				if sport := binary.BigEndian.Uint16(seg[20:22]); sport != 12345 {
					t.Errorf("seg %d: sport=%d want 12345", i, sport)
				}
				if dport := binary.BigEndian.Uint16(seg[22:24]); dport != 80 {
					t.Errorf("seg %d: dport=%d want 80", i, dport)
				}
				if ack := binary.BigEndian.Uint32(seg[28:32]); ack != 20000 {
					t.Errorf("seg %d: ack=%d want 20000", i, ack)
				}
				if seg[32] != 0x50 {
					t.Errorf("seg %d: data-offset byte=%#x want 0x50", i, seg[32])
				}

				// Per-segment seq must advance by the payload offset.
				segStart := i * gso
				if seq := binary.BigEndian.Uint32(seg[24:28]); seq != uint32(origSeq+segStart) {
					t.Errorf("seg %d: seq=%d want %d", i, seq, origSeq+segStart)
				}

				// Payload bytes must be the original contiguous slice.
				segPayLen := len(seg) - int(hdrLen)
				wantPay := make([]byte, segPayLen)
				for k := range segPayLen {
					wantPay[k] = byte((off + k) & 0xff)
				}
				if !bytes.Equal(seg[hdrLen:], wantPay) {
					t.Errorf("seg %d: payload mismatch", i)
				}
				off += segPayLen

				// End-to-end: the stamped header must checksum-verify. A
				// corrupted header fails here because the written checksum was
				// derived from the pristine header.
				if !verifyChecksum(seg[:20], 0) {
					t.Errorf("seg %d: bad IPv4 header checksum", i)
				}
				psum := pseudoHeaderIPv4(seg[12:16], seg[16:20], unix.IPPROTO_TCP, len(seg)-20)
				if !verifyChecksum(seg[20:], psum) {
					t.Errorf("seg %d: bad TCP checksum", i)
				}
			}
		})
	}
}

// TestCorrectHdrLenChecksumBound guards the checksum-field bounds check in
// CorrectHdrLen. The checksum field sits at CsumStart+CsumOffset, so the check
// must be computed from CsumStart+CsumOffset — NOT CsumStart+CsumStart, a
// regression that doubled CsumStart and thus over-tightened the bound (since
// CsumOffset, 6 for UDP / 16 for TCP, is always < CsumStart >= 20). That bogus
// bound spuriously rejected valid small USO superpackets in decodeRead.
func TestCorrectHdrLenChecksumBound(t *testing.T) {
	// A valid IPv4 USO superpacket: 20B IPv4 + 8B UDP + two 6-byte segments
	// (payload 12) = 40 bytes total. CsumStart=20, CsumOffset=6, so the UDP
	// checksum field lives at bytes 26..27, comfortably inside the 40-byte
	// packet. The OLD formula computed cSumAt = CsumStart+CsumStart = 40 and
	// rejected on cSumAt+1 (41) >= len(pkt) (40); the fix (CsumStart+CsumOffset
	// = 26) accepts. This case FAILS against the CsumStart+CsumStart regression.
	t.Run("valid-small-uso-accepted", func(t *testing.T) {
		pkt, _, csumStart := buildUDPv4Super(12) // total len 40
		hdr := NewHeader(
			unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, /*flags*/
			unix.VIRTIO_NET_HDR_GSO_UDP_L4,   /*gsoType*/
			0,                                /*hdrLen*/
			6,                                /*gsoSize: two 6-byte segments*/
			csumStart,                        /*csumStart*/
			6,                                /*csumOffset*/
		)
		if err := CorrectHdrLen(pkt, &hdr); err != nil {
			t.Fatalf("CorrectHdrLen rejected a valid 40-byte USO superpacket: %v", err)
		}
		if hdr.HdrLen != csumStart+udpHeaderLen {
			t.Errorf("HdrLen = %d, want %d", hdr.HdrLen, csumStart+udpHeaderLen)
		}
	})

	// A genuinely-too-short packet: CsumStart=20, CsumOffset=6 means the
	// checksum field would end at byte 27, but the packet is only 25 bytes
	// (CsumStart+CsumOffset+2 = 28 > 25). CorrectHdrLen must still reject it.
	t.Run("too-short-rejected", func(t *testing.T) {
		pkt := make([]byte, 25)
		pkt[0] = 0x45 // IPv4, IHL 5
		hdr := NewHeader(
			unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, /*flags*/
			unix.VIRTIO_NET_HDR_GSO_UDP_L4,   /*gsoType*/
			0,                                /*hdrLen*/
			6,                                /*gsoSize*/
			20,                               /*csumStart*/
			6,                                /*csumOffset*/
		)
		if err := CorrectHdrLen(pkt, &hdr); err == nil {
			t.Fatalf("CorrectHdrLen accepted a too-short (25-byte) packet")
		}
	})
}

// TestSegmentUDPHeaderNotCorrupted is the USO counterpart: SegmentUDP performs
// the same header stamp and must be correct when gsoSize < headerLen.
func TestSegmentUDPHeaderNotCorrupted(t *testing.T) {
	cases := []struct {
		name    string
		payLen  int
		gsoSize uint16
	}{
		{"small-gso-even", 40, 8},
		{"small-gso-odd-tail", 44, 8},
		{"normal-gso", 250, 100},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt, hdrLen, csumStart := buildUDPv4Super(tc.payLen)
			gso := int(tc.gsoSize)
			wantSeg := (tc.payLen + gso - 1) / gso
			segs := collectUDP(t, pkt, hdrLen, csumStart, tc.gsoSize)
			if len(segs) != wantSeg {
				t.Fatalf("got %d segments, want %d", len(segs), wantSeg)
			}

			off := 0
			for i, seg := range segs {
				if got := seg[0]; got != 0x45 {
					t.Errorf("seg %d: version/IHL byte=%#x want 0x45", i, got)
				}
				if seg[9] != unix.IPPROTO_UDP {
					t.Errorf("seg %d: proto=%d want %d", i, seg[9], unix.IPPROTO_UDP)
				}
				if !bytes.Equal(seg[12:16], []byte{10, 0, 0, 1}) {
					t.Errorf("seg %d: src=%v want [10 0 0 1]", i, seg[12:16])
				}
				if !bytes.Equal(seg[16:20], []byte{10, 0, 0, 2}) {
					t.Errorf("seg %d: dst=%v want [10 0 0 2]", i, seg[16:20])
				}
				if sport := binary.BigEndian.Uint16(seg[20:22]); sport != 12345 {
					t.Errorf("seg %d: sport=%d want 12345", i, sport)
				}
				if dport := binary.BigEndian.Uint16(seg[22:24]); dport != 53 {
					t.Errorf("seg %d: dport=%d want 53", i, dport)
				}
				// Software UDP GSO bumps the IPv4 ID per segment just like TSO
				// (inet_gso_segment's fixed-ID case is TCP-only).
				if id := binary.BigEndian.Uint16(seg[4:6]); id != 0x4242+uint16(i) {
					t.Errorf("seg %d: ip id=%#x want %#x", i, id, 0x4242+uint16(i))
				}

				segPayLen := len(seg) - int(hdrLen)
				if udpLen := binary.BigEndian.Uint16(seg[24:26]); udpLen != uint16(8+segPayLen) {
					t.Errorf("seg %d: udp len=%d want %d", i, udpLen, 8+segPayLen)
				}

				wantPay := make([]byte, segPayLen)
				for k := range segPayLen {
					wantPay[k] = byte((off + k) & 0xff)
				}
				if !bytes.Equal(seg[hdrLen:], wantPay) {
					t.Errorf("seg %d: payload mismatch", i)
				}
				off += segPayLen

				if !verifyChecksum(seg[:20], 0) {
					t.Errorf("seg %d: bad IPv4 header checksum", i)
				}
				psum := pseudoHeaderIPv4(seg[12:16], seg[16:20], unix.IPPROTO_UDP, len(seg)-20)
				if !verifyChecksum(seg[20:], psum) {
					t.Errorf("seg %d: bad UDP checksum", i)
				}
			}
		})
	}
}

// buildUDPv4Single constructs a single IPv4/UDP datagram with the checksum field pre-loaded with the folded
// pseudo-header sum, which is how a NEEDS_CSUM (CHECKSUM_PARTIAL) packet arrives from the tun.
func buildUDPv4Single(payload []byte) (pkt []byte, hdr Hdr) {
	const ipLen, udpLen = 20, 8
	pkt = make([]byte, ipLen+udpLen+len(payload))

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = unix.IPPROTO_UDP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})

	binary.BigEndian.PutUint16(pkt[ipLen:ipLen+2], 12345)
	binary.BigEndian.PutUint16(pkt[ipLen+2:ipLen+4], 53)
	binary.BigEndian.PutUint16(pkt[ipLen+4:ipLen+6], uint16(udpLen+len(payload)))
	copy(pkt[ipLen+udpLen:], payload)

	pseudo := pseudoHeaderIPv4(pkt[12:16], pkt[16:20], unix.IPPROTO_UDP, udpLen+len(payload))
	binary.BigEndian.PutUint16(pkt[ipLen+udpChecksumOff:ipLen+udpChecksumOff+2], pseudo)

	return pkt, NewHeader(unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, unix.VIRTIO_NET_HDR_GSO_NONE, 0, 0, ipLen, udpChecksumOff)
}

// TestFinishChecksumUDPZeroStoresAllOnes pins RFC 768: a UDP checksum that computes to zero goes on the wire as
// 0xffff, because all-zero is the reserved "no checksum" encoding that IPv6 rejects outright.
func TestFinishChecksumUDPZeroStoresAllOnes(t *testing.T) {
	var payload []byte
	for i := range 0x10000 {
		p := []byte{byte(i >> 8), byte(i)}
		pkt, hdr := buildUDPv4Single(p)
		cs, co := int(hdr.CsumStart), int(hdr.CsumOffset)
		partial := binary.BigEndian.Uint16(pkt[cs+co : cs+co+2])
		pkt[cs+co], pkt[cs+co+1] = 0, 0
		if ^checksum.Checksum(pkt[cs:], partial) == 0 {
			payload = p
			break
		}
	}
	if payload == nil {
		t.Fatal("no 2-byte payload produced a zero checksum")
	}

	pkt, hdr := buildUDPv4Single(payload)
	if err := FinishChecksum(pkt, hdr); err != nil {
		t.Fatalf("FinishChecksum: %v", err)
	}
	off := int(hdr.CsumStart) + int(hdr.CsumOffset)
	if got := binary.BigEndian.Uint16(pkt[off : off+2]); got != 0xffff {
		t.Fatalf("stored %#04x, want 0xffff for a UDP checksum that folds to zero", got)
	}
}

// TestFinishChecksumTCPZeroPreserved is the other half of the protocol split: zero is a legal TCP checksum and must
// be stored as-is, so the UDP rewrite must not fire on a TCP csum_offset.
func TestFinishChecksumTCPZeroPreserved(t *testing.T) {
	const cs, co = 20, tcpChecksumOff

	// Seed the partial so the completed checksum lands on zero, the case the UDP path rewrites.
	seg := make([]byte, cs+co+2)
	for i := range seg[cs:] {
		seg[cs+i] = byte(i * 7)
	}
	var partial uint16
	for i := 0; i <= 0xffff; i++ {
		binary.BigEndian.PutUint16(seg[cs+co:cs+co+2], uint16(i))
		probe := append([]byte(nil), seg...)
		probe[cs+co], probe[cs+co+1] = 0, 0
		if ^checksum.Checksum(probe[cs:], uint16(i)) == 0 {
			partial = uint16(i)
			break
		}
	}
	binary.BigEndian.PutUint16(seg[cs+co:cs+co+2], partial)

	hdr := NewHeader(unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, unix.VIRTIO_NET_HDR_GSO_NONE, 0, 0, cs, co)
	if err := FinishChecksum(seg, hdr); err != nil {
		t.Fatalf("FinishChecksum: %v", err)
	}
	if got := binary.BigEndian.Uint16(seg[cs+co : cs+co+2]); got != 0 {
		t.Fatalf("stored %#04x, want 0x0000 (zero is a legal TCP checksum)", got)
	}
}

// TestFinishChecksumUDPValidates confirms the ordinary path still produces a checksum a receiver accepts.
func TestFinishChecksumUDPValidates(t *testing.T) {
	payload := []byte("the definitive tun offloads branch")
	pkt, hdr := buildUDPv4Single(payload)
	if err := FinishChecksum(pkt, hdr); err != nil {
		t.Fatalf("FinishChecksum: %v", err)
	}
	pseudo := pseudoHeaderIPv4(pkt[12:16], pkt[16:20], unix.IPPROTO_UDP, 8+len(payload))
	if !verifyChecksum(pkt[hdr.CsumStart:], pseudo) {
		t.Fatal("completed UDP checksum does not validate")
	}
}

// TestCheckValidMasksGSOECN: GSO_ECN is a qualifier bit the kernel ORs
// into gso_type for TSO superpackets with CWR set. CheckValid must
// validate an ECN-qualified type as its base type — previously TCPV4|ECN
// fell into the default case and skipped the IP-version agreement check.
// The qualifier is TCP-only, so it must be rejected on UDP_L4.
func TestCheckValidMasksGSOECN(t *testing.T) {
	v4pkt, _, _ := buildTCPv4Super(100)
	v6pkt := make([]byte, len(v4pkt))
	copy(v6pkt, v4pkt)
	v6pkt[0] = 0x60 // claim IPv6

	cases := []struct {
		name    string
		pkt     []byte
		gsoType uint8
		wantErr bool
	}{
		{"tcpv4-ecn-v4", v4pkt, unix.VIRTIO_NET_HDR_GSO_TCPV4 | unix.VIRTIO_NET_HDR_GSO_ECN, false},
		{"tcpv4-ecn-v6-mismatch", v6pkt, unix.VIRTIO_NET_HDR_GSO_TCPV4 | unix.VIRTIO_NET_HDR_GSO_ECN, true},
		{"tcpv6-ecn-v4-mismatch", v4pkt, unix.VIRTIO_NET_HDR_GSO_TCPV6 | unix.VIRTIO_NET_HDR_GSO_ECN, true},
		{"udp-l4-ecn-rejected", v4pkt, unix.VIRTIO_NET_HDR_GSO_UDP_L4 | unix.VIRTIO_NET_HDR_GSO_ECN, true},
		{"tcpv4-plain-v4", v4pkt, unix.VIRTIO_NET_HDR_GSO_TCPV4, false},
		{"tcpv4-plain-v6-mismatch", v6pkt, unix.VIRTIO_NET_HDR_GSO_TCPV4, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckValid(tc.pkt, NewHeader(0, tc.gsoType, 0, 100, 0, 0))
			if tc.wantErr && err == nil {
				t.Errorf("CheckValid(gsoType=%#x) = nil, want error", tc.gsoType)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("CheckValid(gsoType=%#x) = %v, want nil", tc.gsoType, err)
			}
		})
	}
}

// TestCheckValidRejectsZeroGSOSize: a GSO-typed header with gso_size=0 must be
// rejected. It would produce a Packet whose GSOInfo.IsSuperpacket() is false,
// dodging both segmentation and FinishChecksum on its way downstream.
func TestCheckValidRejectsZeroGSOSize(t *testing.T) {
	v4pkt, _, _ := buildTCPv4Super(100)
	if err := CheckValid(v4pkt, NewHeader(0, unix.VIRTIO_NET_HDR_GSO_TCPV4, 0, 0, 0, 0)); err == nil {
		t.Fatal("CheckValid accepted a GSO-typed header with gso_size=0")
	}
}

// TestFoldComplementMatchesReference checks the segmenter's fold-and-invert
// against an independent RFC 1071 reference fold, hitting the carry edge
// cases (values whose first fold produces another carry).
func TestFoldComplementMatchesReference(t *testing.T) {
	refFold := func(s uint64) uint16 {
		for s>>16 != 0 {
			s = s&0xffff + s>>16
		}
		return uint16(s)
	}
	cases := []uint32{
		0, 1, 0xffff,
		0x10000,    // single carry
		0x1fffe,    // 0xffff + 0xffff: carry produces another 0xffff
		0xffff0000, // high half only
		0xfffeffff, // first fold yields another carry
		0xffffffff, // worst case
	}
	for _, c := range cases {
		if got, want := foldComplement(c), ^refFold(uint64(c)); got != want {
			t.Errorf("foldComplement(%#x) = %#x, want %#x", c, got, want)
		}
	}
}

// referenceBaseIPv4HdrSum and referenceBaseTCPHdrSum are the straightforward
// implementations that baseIPv4HdrSum/baseTCPHdrSum replaced: copy the header
// into scratch, zero the fields the segment loop rewrites, sum. The production
// versions instead sum in place and subtract those fields via one's-complement
// arithmetic, which is faster but far less obvious — particularly for the TCP
// flags byte, which is only half of a 16-bit word. These references exist so
// that trade is checked rather than asserted.
func referenceBaseIPv4HdrSum(pkt []byte, ihl int) uint32 {
	var ipTmp [ipv4HeaderMaxLen]byte
	copy(ipTmp[:ihl], pkt[:ihl])
	ipTmp[ipv4TotalLenOff], ipTmp[ipv4TotalLenOff+1] = 0, 0
	ipTmp[ipv4ChecksumOff], ipTmp[ipv4ChecksumOff+1] = 0, 0
	ipTmp[ipv4IDOff], ipTmp[ipv4IDOff+1] = 0, 0
	return uint32(checksum.Checksum(ipTmp[:ihl], 0))
}

func referenceBaseTCPHdrSum(pkt []byte, csumStart, headerLen int) uint32 {
	tcpLen := headerLen - csumStart
	var tmp [tcpHeaderMaxLen]byte
	copy(tmp[:tcpLen], pkt[csumStart:headerLen])
	tmp[tcpSeqOff], tmp[tcpSeqOff+1], tmp[tcpSeqOff+2], tmp[tcpSeqOff+3] = 0, 0, 0, 0
	tmp[tcpFlagsOff] = 0
	tmp[tcpChecksumOff], tmp[tcpChecksumOff+1] = 0, 0
	return uint32(checksum.Checksum(tmp[:tcpLen], 0))
}

// randSeed is a tiny deterministic PRNG so this test needs no imports beyond
// what the file already has and reproduces identically on every run.
func randByte(state *uint32) byte {
	*state = *state*1664525 + 1013904223
	return byte(*state >> 24)
}

func TestBaseSumsMatchZeroingReference(t *testing.T) {
	state := uint32(12345)

	t.Run("ipv4", func(t *testing.T) {
		for ihl := ipv4HeaderMinLen; ihl <= ipv4HeaderMaxLen; ihl += 4 {
			for range 5000 {
				pkt := make([]byte, ihl)
				for i := range pkt {
					pkt[i] = randByte(&state)
				}
				pkt[0] = byte(0x40 | (ihl / 4))

				want := referenceBaseIPv4HdrSum(pkt, ihl)
				got, err := baseIPv4HdrSum(pkt, ihl)
				if err != nil {
					t.Fatalf("ihl=%d: %v", ihl, err)
				}
				// Compare the value that reaches the wire: the raw partial
				// sums may legally differ by one's-complement -0 vs +0.
				for _, tl := range []uint32{20, 1500, 65535} {
					for _, id := range []uint32{0, 0x4242, 0xffff} {
						if a, b := foldComplement(want+tl+id), foldComplement(got+tl+id); a != b {
							t.Fatalf("ihl=%d tl=%d id=%d: %#04x != %#04x", ihl, tl, id, a, b)
						}
					}
				}
			}
		}
	})

	t.Run("tcp", func(t *testing.T) {
		const csumStart = 20
		for dataOff := 5; dataOff <= 15; dataOff++ {
			tcpLen := dataOff * 4
			headerLen := csumStart + tcpLen
			for range 5000 {
				pkt := make([]byte, headerLen+64)
				for i := range pkt {
					pkt[i] = randByte(&state)
				}
				pkt[0] = 0x45
				pkt[csumStart+tcpDataOffOff] = byte(dataOff << 4)

				want := referenceBaseTCPHdrSum(pkt, csumStart, headerLen)
				got := baseTCPHdrSum(pkt, csumStart, headerLen)
				for _, seq := range []uint32{0, 1, 0x4242_4242, 0xffff_ffff} {
					for _, fl := range []uint32{0x00, 0x10, 0x18, 0x19, 0xff} {
						for _, l4 := range []uint32{20, 1460, 65535} {
							a := foldComplement(want + seq + fl + l4)
							b := foldComplement(got + seq + fl + l4)
							if a != b {
								t.Fatalf("dataOff=%d seq=%#x fl=%#x l4=%d: %#04x != %#04x",
									dataOff, seq, fl, l4, a, b)
							}
						}
					}
				}
			}
		}
	})
}
