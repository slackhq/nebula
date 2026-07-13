//go:build linux && !android
// +build linux,!android

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

	for i := 0; i < payLen; i++ {
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

	for i := 0; i < payLen; i++ {
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
				for k := 0; k < segPayLen; k++ {
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
				// UDP-GSO keeps the same IPv4 ID across every segment.
				if id := binary.BigEndian.Uint16(seg[4:6]); id != 0x4242 {
					t.Errorf("seg %d: ip id=%#x want 0x4242", i, id)
				}

				segPayLen := len(seg) - int(hdrLen)
				if udpLen := binary.BigEndian.Uint16(seg[24:26]); udpLen != uint16(8+segPayLen) {
					t.Errorf("seg %d: udp len=%d want %d", i, udpLen, 8+segPayLen)
				}

				wantPay := make([]byte, segPayLen)
				for k := 0; k < segPayLen; k++ {
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
