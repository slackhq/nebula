//go:build linux && !android && !e2e_testing
// +build linux,!android,!e2e_testing

package tio

import (
	"encoding/binary"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"

	"github.com/slackhq/nebula/overlay/tio/virtio"
)

// testSegScratchSize is a generous segmentation scratch sized to fit any
// of the synthetic TSO/USO superpackets these tests generate (one
// worst-case 64 KiB superpacket plus replicated per-segment headers).
const testSegScratchSize = 192 * 1024

// TestProtoFromGSOTypeMasksECN guards the CWR-superpacket drop bug: the
// kernel qualifies a TSO superpacket whose TCP header carries CWR with
// VIRTIO_NET_HDR_GSO_ECN (we negotiate TUN_F_TSO_ECN, so it WILL send
// them once ECN feedback flows), and the decoder must mask that bit
// rather than reject the packet as an unknown type.
func TestProtoFromGSOTypeMasksECN(t *testing.T) {
	cases := []struct {
		typ  uint8
		want GSOProto
	}{
		{unix.VIRTIO_NET_HDR_GSO_TCPV4, GSOProtoTCP},
		{unix.VIRTIO_NET_HDR_GSO_TCPV4 | unix.VIRTIO_NET_HDR_GSO_ECN, GSOProtoTCP},
		{unix.VIRTIO_NET_HDR_GSO_TCPV6, GSOProtoTCP},
		{unix.VIRTIO_NET_HDR_GSO_TCPV6 | unix.VIRTIO_NET_HDR_GSO_ECN, GSOProtoTCP},
		{unix.VIRTIO_NET_HDR_GSO_UDP_L4, GSOProtoUDP},
	}
	for _, c := range cases {
		got, err := protoFromGSOType(c.typ)
		if err != nil || got != c.want {
			t.Errorf("protoFromGSOType(%#x) = (%v, %v), want (%v, nil)", c.typ, got, err, c.want)
		}
	}
	if _, err := protoFromGSOType(unix.VIRTIO_NET_HDR_GSO_NONE); err == nil {
		t.Error("GSO_NONE must still be rejected")
	}
	if _, err := protoFromGSOType(unix.VIRTIO_NET_HDR_GSO_ECN); err == nil {
		t.Error("a bare ECN bit with no base type must still be rejected")
	}
}

// verifyChecksum confirms that the one's-complement sum across `b`, seeded
// with a folded pseudo-header sum, equals all-ones (valid).
func verifyChecksum(b []byte, pseudo uint16) bool {
	return checksum.Checksum(b, pseudo) == 0xffff
}

// segmentForTest is the test-only counterpart to the production
// SegmentSuperpacket path. It handles GSO_NONE (with optional
// finishChecksum) inline and dispatches GSO superpackets through
// SegmentSuperpacket, draining each yielded segment into a
// freshly-copied [][]byte slot so callers can iterate after the call
// returns. Tests pre-set hdr.HdrLen correctly, so correctHdrLen is not
// invoked here.
func segmentForTest(pkt []byte, hdr virtio.Hdr, out *[][]byte, scratch []byte) error {
	if hdr.GSOType == unix.VIRTIO_NET_HDR_GSO_NONE {
		cp := append([]byte(nil), pkt...)
		if hdr.Flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			if err := virtio.FinishChecksum(cp, hdr); err != nil {
				return err
			}
		}
		*out = append(*out, cp)
		return nil
	}
	proto, err := protoFromGSOType(hdr.GSOType)
	if err != nil {
		return err
	}
	gso := GSOInfo{
		Size:      hdr.GSOSize,
		HdrLen:    hdr.HdrLen,
		CsumStart: hdr.CsumStart,
		Proto:     proto,
	}
	return SegmentSuperpacket(Packet{Bytes: pkt, GSO: gso}, func(seg []byte) error {
		*out = append(*out, append([]byte(nil), seg...))
		return nil
	})
}

// pseudoHeaderIPv4 returns the folded pseudo-header sum used to verify a
// TCP/UDP segment's checksum in tests. src/dst are 4 bytes each.
func pseudoHeaderIPv4(src, dst []byte, proto byte, l4Len int) uint16 {
	s := uint32(checksum.Checksum(src, 0)) + uint32(checksum.Checksum(dst, 0))
	s += uint32(proto) + uint32(l4Len)
	s = (s & 0xffff) + (s >> 16)
	s = (s & 0xffff) + (s >> 16)
	return uint16(s)
}

// pseudoHeaderIPv6 returns the folded pseudo-header sum used to verify a
// TCP/UDP segment's checksum in tests. src/dst are 16 bytes each.
func pseudoHeaderIPv6(src, dst []byte, proto byte, l4Len int) uint16 {
	s := uint32(checksum.Checksum(src, 0)) + uint32(checksum.Checksum(dst, 0))
	s += uint32(l4Len>>16) + uint32(l4Len&0xffff) + uint32(proto)
	s = (s & 0xffff) + (s >> 16)
	s = (s & 0xffff) + (s >> 16)
	return uint16(s)
}

// buildTSOv4 builds a synthetic IPv4/TCP TSO superpacket with a payload of
// `payLen` bytes split at `mss`.
func buildTSOv4(t *testing.T, payLen, mss int) ([]byte, virtio.Hdr) {
	t.Helper()
	const ipLen = 20
	const tcpLen = 20
	pkt := make([]byte, ipLen+tcpLen+payLen)

	// IPv4 header
	pkt[0] = 0x45 // version 4, IHL 5
	// total length is meaningless for TSO but set it anyway
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen+tcpLen+payLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x4242) // original ID
	pkt[8] = 64                                  // TTL
	pkt[9] = unix.IPPROTO_TCP
	copy(pkt[12:16], []byte{10, 0, 0, 1}) // src
	copy(pkt[16:20], []byte{10, 0, 0, 2}) // dst

	// TCP header
	binary.BigEndian.PutUint16(pkt[20:22], 12345) // sport
	binary.BigEndian.PutUint16(pkt[22:24], 80)    // dport
	binary.BigEndian.PutUint32(pkt[24:28], 10000) // seq
	binary.BigEndian.PutUint32(pkt[28:32], 20000) // ack
	pkt[32] = 0x50                                // data offset 5 words
	pkt[33] = 0x18                                // ACK | PSH
	binary.BigEndian.PutUint16(pkt[34:36], 65535) // window

	// payload
	for i := 0; i < payLen; i++ {
		pkt[ipLen+tcpLen+i] = byte(i & 0xff)
	}

	return pkt, virtio.Hdr{
		Flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		GSOType:    unix.VIRTIO_NET_HDR_GSO_TCPV4,
		HdrLen:     uint16(ipLen + tcpLen),
		GSOSize:    uint16(mss),
		CsumStart:  uint16(ipLen),
		CsumOffset: 16,
	}
}

func TestSegmentTCPv4(t *testing.T) {
	const mss = 100
	const numSeg = 3
	pkt, hdr := buildTSOv4(t, mss*numSeg, mss)

	scratch := make([]byte, testSegScratchSize)
	var out [][]byte
	if err := segmentForTest(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentForTest: %v", err)
	}
	if len(out) != numSeg {
		t.Fatalf("expected %d segments, got %d", numSeg, len(out))
	}

	for i, seg := range out {
		if len(seg) != 40+mss {
			t.Errorf("seg %d: unexpected len %d", i, len(seg))
		}
		totalLen := binary.BigEndian.Uint16(seg[2:4])
		if totalLen != uint16(40+mss) {
			t.Errorf("seg %d: total_len=%d want %d", i, totalLen, 40+mss)
		}
		id := binary.BigEndian.Uint16(seg[4:6])
		if id != 0x4242+uint16(i) {
			t.Errorf("seg %d: ip id=%#x want %#x", i, id, 0x4242+uint16(i))
		}
		seq := binary.BigEndian.Uint32(seg[24:28])
		wantSeq := uint32(10000 + i*mss)
		if seq != wantSeq {
			t.Errorf("seg %d: seq=%d want %d", i, seq, wantSeq)
		}
		flags := seg[33]
		wantFlags := byte(0x10) // ACK only, PSH cleared
		if i == numSeg-1 {
			wantFlags = 0x18 // ACK | PSH preserved on last
		}
		if flags != wantFlags {
			t.Errorf("seg %d: flags=%#x want %#x", i, flags, wantFlags)
		}
		// IPv4 header checksum must verify against itself.
		if !verifyChecksum(seg[:20], 0) {
			t.Errorf("seg %d: bad IPv4 header checksum", i)
		}
		// TCP checksum must verify against the pseudo-header.
		psum := pseudoHeaderIPv4(seg[12:16], seg[16:20], unix.IPPROTO_TCP, 20+mss)
		if !verifyChecksum(seg[20:], psum) {
			t.Errorf("seg %d: bad TCP checksum", i)
		}
	}
}

func TestSegmentTCPv4OddTail(t *testing.T) {
	// Payload of 250 bytes with MSS 100 → segments of 100, 100, 50.
	pkt, hdr := buildTSOv4(t, 250, 100)
	scratch := make([]byte, testSegScratchSize)
	var out [][]byte
	if err := segmentForTest(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentForTest: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 segments, got %d", len(out))
	}
	wantPayLens := []int{100, 100, 50}
	for i, seg := range out {
		if len(seg)-40 != wantPayLens[i] {
			t.Errorf("seg %d: pay len %d want %d", i, len(seg)-40, wantPayLens[i])
		}
		if !verifyChecksum(seg[:20], 0) {
			t.Errorf("seg %d: bad IPv4 header checksum", i)
		}
		psum := pseudoHeaderIPv4(seg[12:16], seg[16:20], unix.IPPROTO_TCP, 20+wantPayLens[i])
		if !verifyChecksum(seg[20:], psum) {
			t.Errorf("seg %d: bad TCP checksum", i)
		}
	}
}

func TestSegmentTCPv6(t *testing.T) {
	const ipLen = 40
	const tcpLen = 20
	const mss = 120
	const numSeg = 2
	payLen := mss * numSeg
	pkt := make([]byte, ipLen+tcpLen+payLen)

	// IPv6 header
	pkt[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(pkt[4:6], uint16(tcpLen+payLen))
	pkt[6] = unix.IPPROTO_TCP
	pkt[7] = 64
	// src/dst fe80::1 / fe80::2
	pkt[8] = 0xfe
	pkt[9] = 0x80
	pkt[23] = 1
	pkt[24] = 0xfe
	pkt[25] = 0x80
	pkt[39] = 2

	// TCP header
	binary.BigEndian.PutUint16(pkt[40:42], 12345)
	binary.BigEndian.PutUint16(pkt[42:44], 80)
	binary.BigEndian.PutUint32(pkt[44:48], 7)
	binary.BigEndian.PutUint32(pkt[48:52], 99)
	pkt[52] = 0x50
	pkt[53] = 0x19 // FIN | ACK | PSH — exercise FIN clearing too
	binary.BigEndian.PutUint16(pkt[54:56], 65535)

	for i := 0; i < payLen; i++ {
		pkt[ipLen+tcpLen+i] = byte(i)
	}

	hdr := virtio.Hdr{
		Flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		GSOType:    unix.VIRTIO_NET_HDR_GSO_TCPV6,
		HdrLen:     uint16(ipLen + tcpLen),
		GSOSize:    uint16(mss),
		CsumStart:  uint16(ipLen),
		CsumOffset: 16,
	}

	scratch := make([]byte, testSegScratchSize)
	var out [][]byte
	if err := segmentForTest(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentForTest: %v", err)
	}
	if len(out) != numSeg {
		t.Fatalf("want %d segments, got %d", numSeg, len(out))
	}

	for i, seg := range out {
		if len(seg) != ipLen+tcpLen+mss {
			t.Errorf("seg %d: len %d want %d", i, len(seg), ipLen+tcpLen+mss)
		}
		pl := binary.BigEndian.Uint16(seg[4:6])
		if pl != uint16(tcpLen+mss) {
			t.Errorf("seg %d: payload_length=%d want %d", i, pl, tcpLen+mss)
		}
		seq := binary.BigEndian.Uint32(seg[44:48])
		if seq != uint32(7+i*mss) {
			t.Errorf("seg %d: seq=%d want %d", i, seq, 7+i*mss)
		}
		flags := seg[53]
		// Original flags = 0x19 (FIN|ACK|PSH). FIN(0x01)+PSH(0x08) should be
		// cleared on all but the last; ACK(0x10) always preserved.
		wantFlags := byte(0x10)
		if i == numSeg-1 {
			wantFlags = 0x19
		}
		if flags != wantFlags {
			t.Errorf("seg %d: flags=%#x want %#x", i, flags, wantFlags)
		}
		psum := pseudoHeaderIPv6(seg[8:24], seg[24:40], unix.IPPROTO_TCP, tcpLen+mss)
		if !verifyChecksum(seg[ipLen:], psum) {
			t.Errorf("seg %d: bad TCP checksum", i)
		}
	}
}

func TestSegmentGSONonePassesThrough(t *testing.T) {
	pkt, hdr := buildTSOv4(t, 100, 100)
	hdr.GSOType = unix.VIRTIO_NET_HDR_GSO_NONE
	hdr.Flags = 0 // no NEEDS_CSUM, leave packet untouched

	scratch := make([]byte, testSegScratchSize)
	var out [][]byte
	if err := segmentForTest(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentForTest: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 segment, got %d", len(out))
	}
	if len(out[0]) != len(pkt) {
		t.Fatalf("unexpected length: %d vs %d", len(out[0]), len(pkt))
	}
}

// TestSegmentRejectsLegacyUDPGSO ensures the legacy GSO_UDP (UFO) marker is
// still rejected; only modern GSO_UDP_L4 (USO) is supported.
func TestSegmentRejectsLegacyUDPGSO(t *testing.T) {
	hdr := virtio.Hdr{GSOType: unix.VIRTIO_NET_HDR_GSO_UDP}
	var out [][]byte
	if err := segmentForTest(nil, hdr, &out, nil); err == nil {
		t.Fatalf("expected rejection for legacy UDP GSO")
	}
}

// buildUSOv4 builds a synthetic IPv4/UDP USO superpacket with payload of
// payLen bytes, segmented at gsoSize.
func buildUSOv4(t *testing.T, payLen, gsoSize int) ([]byte, virtio.Hdr) {
	t.Helper()
	const ipLen = 20
	const udpLen = 8
	pkt := make([]byte, ipLen+udpLen+payLen)

	// IPv4 header
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen+udpLen+payLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x4242)
	pkt[8] = 64
	pkt[9] = unix.IPPROTO_UDP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})

	// UDP header (length + checksum filled in per segment by segmentUDPYield)
	binary.BigEndian.PutUint16(pkt[20:22], 12345) // sport
	binary.BigEndian.PutUint16(pkt[22:24], 53)    // dport

	for i := 0; i < payLen; i++ {
		pkt[ipLen+udpLen+i] = byte(i & 0xff)
	}

	return pkt, virtio.Hdr{
		Flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		GSOType:    unix.VIRTIO_NET_HDR_GSO_UDP_L4,
		HdrLen:     uint16(ipLen + udpLen),
		GSOSize:    uint16(gsoSize),
		CsumStart:  uint16(ipLen),
		CsumOffset: 6,
	}
}

func TestSegmentUDPv4(t *testing.T) {
	const gso = 100
	const numSeg = 3
	pkt, hdr := buildUSOv4(t, gso*numSeg, gso)

	scratch := make([]byte, testSegScratchSize)
	var out [][]byte
	if err := segmentForTest(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentForTest: %v", err)
	}
	if len(out) != numSeg {
		t.Fatalf("expected %d segments, got %d", numSeg, len(out))
	}

	for i, seg := range out {
		if len(seg) != 28+gso {
			t.Errorf("seg %d: len %d want %d", i, len(seg), 28+gso)
		}
		totalLen := binary.BigEndian.Uint16(seg[2:4])
		if totalLen != uint16(28+gso) {
			t.Errorf("seg %d: total_len=%d want %d", i, totalLen, 28+gso)
		}
		// kernel UDP-GSO does NOT bump the IPv4 ID across segments; every
		// segment carries the same ID as the seed.
		id := binary.BigEndian.Uint16(seg[4:6])
		if id != 0x4242 {
			t.Errorf("seg %d: ip id=%#x want %#x", i, id, 0x4242)
		}
		udpLen := binary.BigEndian.Uint16(seg[24:26])
		if udpLen != uint16(8+gso) {
			t.Errorf("seg %d: udp len=%d want %d", i, udpLen, 8+gso)
		}
		if !verifyChecksum(seg[:20], 0) {
			t.Errorf("seg %d: bad IPv4 header checksum", i)
		}
		psum := pseudoHeaderIPv4(seg[12:16], seg[16:20], unix.IPPROTO_UDP, 8+gso)
		if !verifyChecksum(seg[20:], psum) {
			t.Errorf("seg %d: bad UDP checksum", i)
		}
	}
}

func TestSegmentUDPv4OddTail(t *testing.T) {
	// 250 bytes payload, gsoSize=100 → segments of 100, 100, 50.
	pkt, hdr := buildUSOv4(t, 250, 100)
	scratch := make([]byte, testSegScratchSize)
	var out [][]byte
	if err := segmentForTest(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentForTest: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 segments, got %d", len(out))
	}
	wantPay := []int{100, 100, 50}
	for i, seg := range out {
		if len(seg)-28 != wantPay[i] {
			t.Errorf("seg %d: pay len %d want %d", i, len(seg)-28, wantPay[i])
		}
		udpLen := binary.BigEndian.Uint16(seg[24:26])
		if udpLen != uint16(8+wantPay[i]) {
			t.Errorf("seg %d: udp len=%d want %d", i, udpLen, 8+wantPay[i])
		}
		if !verifyChecksum(seg[:20], 0) {
			t.Errorf("seg %d: bad IPv4 header checksum", i)
		}
		psum := pseudoHeaderIPv4(seg[12:16], seg[16:20], unix.IPPROTO_UDP, 8+wantPay[i])
		if !verifyChecksum(seg[20:], psum) {
			t.Errorf("seg %d: bad UDP checksum", i)
		}
	}
}

func TestSegmentUDPv6(t *testing.T) {
	const ipLen = 40
	const udpLen = 8
	const gso = 120
	const numSeg = 2
	payLen := gso * numSeg
	pkt := make([]byte, ipLen+udpLen+payLen)

	// IPv6 header
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen+payLen))
	pkt[6] = unix.IPPROTO_UDP
	pkt[7] = 64
	pkt[8] = 0xfe
	pkt[9] = 0x80
	pkt[23] = 1
	pkt[24] = 0xfe
	pkt[25] = 0x80
	pkt[39] = 2

	binary.BigEndian.PutUint16(pkt[40:42], 12345)
	binary.BigEndian.PutUint16(pkt[42:44], 53)

	for i := 0; i < payLen; i++ {
		pkt[ipLen+udpLen+i] = byte(i)
	}

	hdr := virtio.Hdr{
		Flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		GSOType:    unix.VIRTIO_NET_HDR_GSO_UDP_L4,
		HdrLen:     uint16(ipLen + udpLen),
		GSOSize:    uint16(gso),
		CsumStart:  uint16(ipLen),
		CsumOffset: 6,
	}

	scratch := make([]byte, testSegScratchSize)
	var out [][]byte
	if err := segmentForTest(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentForTest: %v", err)
	}
	if len(out) != numSeg {
		t.Fatalf("want %d segments, got %d", numSeg, len(out))
	}

	for i, seg := range out {
		if len(seg) != ipLen+udpLen+gso {
			t.Errorf("seg %d: len %d want %d", i, len(seg), ipLen+udpLen+gso)
		}
		pl := binary.BigEndian.Uint16(seg[4:6])
		if pl != uint16(udpLen+gso) {
			t.Errorf("seg %d: payload_length=%d want %d", i, pl, udpLen+gso)
		}
		ul := binary.BigEndian.Uint16(seg[ipLen+4 : ipLen+6])
		if ul != uint16(udpLen+gso) {
			t.Errorf("seg %d: udp len=%d want %d", i, ul, udpLen+gso)
		}
		psum := pseudoHeaderIPv6(seg[8:24], seg[24:40], unix.IPPROTO_UDP, udpLen+gso)
		if !verifyChecksum(seg[ipLen:], psum) {
			t.Errorf("seg %d: bad UDP checksum", i)
		}
	}
}

// TestSegmentUDPCEPropagates confirms IP-level CE marks on the seed appear on
// every segment. UDP has no transport-level CWR/ECE: the IP TOS/TC byte is
// copied verbatim into every segment by the segment-prefix copy.
func TestSegmentUDPCEPropagates(t *testing.T) {
	pkt, hdr := buildUSOv4(t, 200, 100)
	pkt[1] = 0x03 // CE codepoint in IP-ECN

	scratch := make([]byte, testSegScratchSize)
	var out [][]byte
	if err := segmentForTest(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentForTest: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 segments, got %d", len(out))
	}
	for i, seg := range out {
		if seg[1]&0x03 != 0x03 {
			t.Errorf("seg %d: CE missing (tos=%#x)", i, seg[1])
		}
		if !verifyChecksum(seg[:20], 0) {
			t.Errorf("seg %d: bad IPv4 header checksum", i)
		}
	}
}

// TestSegmentTCPCwrFirstSegmentOnly confirms RFC 3168 §6.1.2: when a TSO
// burst's seed has CWR set, only the first emitted segment carries CWR.
// ECE is preserved on every segment (different signal, persistent state).
func TestSegmentTCPCwrFirstSegmentOnly(t *testing.T) {
	const mss = 100
	const numSeg = 3
	pkt, hdr := buildTSOv4(t, mss*numSeg, mss)
	// Seed flags: CWR | ECE | ACK | PSH.
	pkt[33] = 0x80 | 0x40 | 0x10 | 0x08

	scratch := make([]byte, testSegScratchSize)
	var out [][]byte
	if err := segmentForTest(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentForTest: %v", err)
	}
	if len(out) != numSeg {
		t.Fatalf("expected %d segments, got %d", numSeg, len(out))
	}
	for i, seg := range out {
		flags := seg[33]
		hasCwr := flags&0x80 != 0
		hasEce := flags&0x40 != 0
		hasPsh := flags&0x08 != 0
		wantCwr := i == 0
		wantPsh := i == numSeg-1
		if hasCwr != wantCwr {
			t.Errorf("seg %d: CWR=%v want %v (flags=%#x)", i, hasCwr, wantCwr, flags)
		}
		if !hasEce {
			t.Errorf("seg %d: ECE missing (flags=%#x)", i, flags)
		}
		if hasPsh != wantPsh {
			t.Errorf("seg %d: PSH=%v want %v (flags=%#x)", i, hasPsh, wantPsh, flags)
		}
		// IP and TCP checksums must still verify after the flag rewrite.
		if !verifyChecksum(seg[:20], 0) {
			t.Errorf("seg %d: bad IPv4 header checksum", i)
		}
		psum := pseudoHeaderIPv4(seg[12:16], seg[16:20], unix.IPPROTO_TCP, 20+mss)
		if !verifyChecksum(seg[20:], psum) {
			t.Errorf("seg %d: bad TCP checksum", i)
		}
	}
}

func BenchmarkSegmentTCPv4(b *testing.B) {
	sizes := []struct {
		name   string
		payLen int
		mss    int
	}{
		{"64KiB_MSS1460", 65000, 1460},
		{"16KiB_MSS1460", 16384, 1460},
		{"4KiB_MSS1460", 4096, 1460},
	}
	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			const ipLen = 20
			const tcpLen = 20
			pkt := make([]byte, ipLen+tcpLen+sz.payLen)
			pkt[0] = 0x45
			binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen+tcpLen+sz.payLen))
			binary.BigEndian.PutUint16(pkt[4:6], 0x4242)
			pkt[8] = 64
			pkt[9] = unix.IPPROTO_TCP
			copy(pkt[12:16], []byte{10, 0, 0, 1})
			copy(pkt[16:20], []byte{10, 0, 0, 2})
			binary.BigEndian.PutUint16(pkt[20:22], 12345)
			binary.BigEndian.PutUint16(pkt[22:24], 80)
			binary.BigEndian.PutUint32(pkt[24:28], 10000)
			binary.BigEndian.PutUint32(pkt[28:32], 20000)
			pkt[32] = 0x50
			pkt[33] = 0x18
			binary.BigEndian.PutUint16(pkt[34:36], 65535)
			for i := 0; i < sz.payLen; i++ {
				pkt[ipLen+tcpLen+i] = byte(i)
			}
			hdr := virtio.Hdr{
				Flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				GSOType:    unix.VIRTIO_NET_HDR_GSO_TCPV4,
				HdrLen:     uint16(ipLen + tcpLen),
				GSOSize:    uint16(sz.mss),
				CsumStart:  uint16(ipLen),
				CsumOffset: 16,
			}

			scratch := make([]byte, testSegScratchSize)
			out := make([][]byte, 0, 64)

			// SegmentSuperpacket consumes its input destructively; restore
			// pkt from a master copy each iteration. The restore mirrors the
			// kernel→userspace copy that hands a fresh GSO blob to the
			// segmenter in production, so it's representative cost rather
			// than bench overhead.
			master := append([]byte(nil), pkt...)
			work := make([]byte, len(pkt))

			b.SetBytes(int64(len(pkt)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(work, master)
				out = out[:0]
				if err := segmentForTest(work, hdr, &out, scratch); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestTunFileWriteVnetHdrNoAlloc verifies the IFF_VNET_HDR fast-path write is
// allocation-free. We write to /dev/null so every call succeeds synchronously.
func TestTunFileWriteVnetHdrNoAlloc(t *testing.T) {
	fd, err := unix.Open("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	tf := &Offload{fd: fd}

	payload := make([]byte, 1400)
	// Warm up (first call may trigger one-time internal allocations elsewhere).
	if _, err := tf.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := tf.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
	})
	if allocs != 0 {
		t.Fatalf("Write allocated %.1f times per call, want 0", allocs)
	}
}

// TestWriteGSOSkipsEmptyPayloads is the defense-in-depth guard for the
// zero-length UDP DoS: a payload fragment of length zero would make &p[0]
// panic (index-out-of-range) when building the iovec array. WriteGSO must
// skip empties instead. We write to /dev/null so the writev always succeeds
// synchronously; the point is simply that neither call panics.
func TestWriteGSOSkipsEmptyPayloads(t *testing.T) {
	fd, err := unix.Open("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	o := &Offload{fd: fd, gsoIovs: make([]unix.Iovec, 2, gsoMaxIovs)}
	o.gsoIovs[0].Base = &o.gsoHdrBuf[0]
	o.gsoIovs[0].SetLen(virtio.Size)

	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // IPv4, IHL 5
	udpHdr := make([]byte, 8)

	// Sole payload empty: exercises the all-empty skip (n stays at 3).
	if err := o.WriteGSO(ipHdr, udpHdr, [][]byte{{}}, GSOProtoUDP); err != nil {
		t.Fatalf("WriteGSO with a single empty payload: %v", err)
	}
	// Empty mixed with a real fragment: exercises the index-drift skip so a
	// later non-empty payload still lands in the right iovec slot.
	real := make([]byte, 1200)
	if err := o.WriteGSO(ipHdr, udpHdr, [][]byte{real, {}}, GSOProtoUDP); err != nil {
		t.Fatalf("WriteGSO with a trailing empty payload: %v", err)
	}
}

// buildTSOv6 builds a synthetic IPv6/TCP TSO superpacket with payLen bytes
// of payload, segmented at gso. Returns the packet bytes only; the
// virtio_net_hdr is the caller's responsibility.
func buildTSOv6(payLen, gso int) []byte {
	const ipLen = 40
	const tcpLen = 20
	pkt := make([]byte, ipLen+tcpLen+payLen)

	pkt[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(pkt[4:6], uint16(tcpLen+payLen))
	pkt[6] = unix.IPPROTO_TCP
	pkt[7] = 64
	pkt[8] = 0xfe
	pkt[9] = 0x80
	pkt[23] = 1
	pkt[24] = 0xfe
	pkt[25] = 0x80
	pkt[39] = 2

	binary.BigEndian.PutUint16(pkt[40:42], 12345)
	binary.BigEndian.PutUint16(pkt[42:44], 80)
	binary.BigEndian.PutUint32(pkt[44:48], 7)
	binary.BigEndian.PutUint32(pkt[48:52], 99)
	pkt[52] = 0x50
	pkt[53] = 0x10 // ACK only
	binary.BigEndian.PutUint16(pkt[54:56], 65535)

	for i := 0; i < payLen; i++ {
		pkt[ipLen+tcpLen+i] = byte(i)
	}
	return pkt
}

// TestDecodeReadFitsMaxTSOAtDrainThreshold proves the rxBuf sizing is
// correct: when rxOff is at the maximum value the drain headroom check
// allows, decodeRead must still be able to absorb a worst-case 64KiB
// TSO superpacket without dropping the burst. With segmentation deferred
// to encrypt time, decodeRead writes only the kernel-supplied bytes into
// rxBuf, so the size requirement is just "fit one worst-case input."
//
// Regression history: in a prior layout the rx buffer doubled as the
// segmentation output, a near-threshold drain read returned "scratch too
// small", the whole 45-segment TSO burst was dropped, and the remote's TCP
// fast-retransmit collapsed cwnd. Keeping this test in the new layout
// guards against re-introducing a drain headroom shortfall.
func TestDecodeReadFitsMaxTSOAtDrainThreshold(t *testing.T) {
	const ipv6HdrLen = 40
	const tcpHdrLen = 20
	const headerLen = ipv6HdrLen + tcpHdrLen
	// Maximum TUN read body. The tunReadBufSize cap on readv's body iovec
	// is what bounds the kernel's superpacket length.
	pktLen := tunReadBufSize
	payLen := pktLen - headerLen
	const targetSegs = 64
	gsoSize := (payLen + targetSegs - 1) / targetSegs

	pkt := buildTSOv6(payLen, gsoSize)
	if len(pkt) != pktLen {
		t.Fatalf("buildTSOv6 produced %d bytes, want %d", len(pkt), pktLen)
	}

	o := &Offload{
		rxBuf: make([]byte, tunRxBufCap),
	}
	// rxOff at the maximum value the drain headroom check permits before
	// it would refuse another read. Any drain-time read up to this
	// threshold MUST still process correctly.
	o.rxOff = tunRxBufCap - tunRxBufSize

	// Stage the body in rxBuf as if readv(2) just placed it there.
	copy(o.rxBuf[o.rxOff:], pkt)

	// Encode the matching virtio_net_hdr.
	hdr := virtio.Hdr{
		Flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		GSOType:    unix.VIRTIO_NET_HDR_GSO_TCPV6,
		HdrLen:     uint16(headerLen),
		GSOSize:    uint16(gsoSize),
		CsumStart:  uint16(ipv6HdrLen),
		CsumOffset: 16,
	}
	hdr.Encode(o.readVnetScratch[:])

	startRxOff := o.rxOff
	if err := o.decodeRead(pktLen); err != nil {
		t.Fatalf("decodeRead at drain threshold returned %v — rxBuf sizing regression: "+
			"tunRxBufSize=%d must hold one worst-case input (%d)",
			err, tunRxBufSize, pktLen)
	}

	if len(o.pending) != 1 {
		t.Fatalf("got %d packets, want 1 superpacket entry", len(o.pending))
	}
	got := o.pending[0]
	if !got.GSO.IsSuperpacket() {
		t.Fatalf("expected superpacket GSO metadata, got %+v", got.GSO)
	}
	if got.GSO.Proto != GSOProtoTCP {
		t.Errorf("GSO.Proto=%d want TCP", got.GSO.Proto)
	}
	if got.GSO.Size != uint16(gsoSize) {
		t.Errorf("GSO.Size=%d want %d", got.GSO.Size, gsoSize)
	}
	if got.GSO.HdrLen != uint16(headerLen) {
		t.Errorf("GSO.HdrLen=%d want %d", got.GSO.HdrLen, headerLen)
	}
	if got.GSO.CsumStart != uint16(ipv6HdrLen) {
		t.Errorf("GSO.CsumStart=%d want %d", got.GSO.CsumStart, ipv6HdrLen)
	}
	if len(got.Bytes) != pktLen {
		t.Errorf("len(Bytes)=%d want %d", len(got.Bytes), pktLen)
	}

	// rxOff advances exactly by the kernel-supplied body length — no
	// segmentation output to account for any more.
	if o.rxOff != startRxOff+pktLen {
		t.Errorf("rxOff=%d want %d", o.rxOff, startRxOff+pktLen)
	}
	if o.rxOff > tunRxBufCap {
		t.Fatalf("rxOff=%d overran rxBuf (cap=%d)", o.rxOff, tunRxBufCap)
	}

	// Validate that segmenting the returned superpacket reproduces the
	// expected per-segment IPv6 payload length and TCP checksum.
	wantSegs := (payLen + gsoSize - 1) / gsoSize
	gotSegs := 0
	if err := SegmentSuperpacket(got, func(seg []byte) error {
		defer func() { gotSegs++ }()
		if len(seg) < headerLen+1 {
			t.Errorf("seg %d too short: %d", gotSegs, len(seg))
			return nil
		}
		if seg[0]>>4 != 6 {
			t.Errorf("seg %d: bad IP version %#x", gotSegs, seg[0])
		}
		segPay := len(seg) - headerLen
		gotPL := binary.BigEndian.Uint16(seg[4:6])
		if gotPL != uint16(tcpHdrLen+segPay) {
			t.Errorf("seg %d: payload_len=%d want %d", gotSegs, gotPL, tcpHdrLen+segPay)
		}
		psum := pseudoHeaderIPv6(seg[8:24], seg[24:40], unix.IPPROTO_TCP, tcpHdrLen+segPay)
		if !verifyChecksum(seg[ipv6HdrLen:], psum) {
			t.Errorf("seg %d: bad TCP checksum", gotSegs)
		}
		return nil
	}); err != nil {
		t.Fatalf("SegmentSuperpacket: %v", err)
	}
	if gotSegs != wantSegs {
		t.Fatalf("got %d segments, want %d", gotSegs, wantSegs)
	}
}
