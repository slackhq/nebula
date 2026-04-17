//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package overlay

import (
	"encoding/binary"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// verifyChecksum confirms that the one's-complement sum across `b`, optionally
// seeded with a pseudo-header sum, folds to all-ones (valid).
func verifyChecksum(b []byte, pseudo uint32) bool {
	sum := checksumBytes(b, pseudo)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}

// buildTSOv4 builds a synthetic IPv4/TCP TSO superpacket with a payload of
// `payLen` bytes split at `mss`.
func buildTSOv4(t *testing.T, payLen, mss int) ([]byte, virtioNetHdr) {
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

	return pkt, virtioNetHdr{
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

	scratch := make([]byte, tunSegBufSize)
	var out [][]byte
	if err := segmentTCP(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentTCP: %v", err)
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
	scratch := make([]byte, tunSegBufSize)
	var out [][]byte
	if err := segmentTCP(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentTCP: %v", err)
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

	hdr := virtioNetHdr{
		Flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		GSOType:    unix.VIRTIO_NET_HDR_GSO_TCPV6,
		HdrLen:     uint16(ipLen + tcpLen),
		GSOSize:    uint16(mss),
		CsumStart:  uint16(ipLen),
		CsumOffset: 16,
	}

	scratch := make([]byte, tunSegBufSize)
	var out [][]byte
	if err := segmentTCP(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentTCP: %v", err)
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

	scratch := make([]byte, tunSegBufSize)
	var out [][]byte
	if err := segmentInto(pkt, hdr, &out, scratch); err != nil {
		t.Fatalf("segmentInto: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 segment, got %d", len(out))
	}
	if len(out[0]) != len(pkt) {
		t.Fatalf("unexpected length: %d vs %d", len(out[0]), len(pkt))
	}
}

func TestSegmentRejectsUDP(t *testing.T) {
	hdr := virtioNetHdr{GSOType: unix.VIRTIO_NET_HDR_GSO_UDP}
	var out [][]byte
	if err := segmentInto(nil, hdr, &out, nil); err == nil {
		t.Fatalf("expected rejection for UDP GSO")
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

	tf := &tunFile{fd: fd, vnetHdr: true}
	tf.writeIovs[0].Base = &zeroVnetHdr[0]
	tf.writeIovs[0].SetLen(virtioNetHdrLen)

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
