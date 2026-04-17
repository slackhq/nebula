//go:build linux && !android && !e2e_testing
// +build linux,!android,!e2e_testing

package tio

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// segmentInto splits a TUN-side packet described by hdr into one or more
// IP packets, each appended to *out as a slice of scratch. scratch must be
// sized to hold every segment (including replicated headers).
func segmentInto(pkt []byte, hdr VirtioNetHdr, out *[][]byte, scratch []byte) error {
	// When RSC_INFO is set the csum_start/csum_offset fields are repurposed to
	// carry coalescing info rather than checksum offsets. A TUN writing via
	// IFF_VNET_HDR should never emit this, but if it did we would silently
	// miscompute the segment checksums — refuse the packet instead.
	if hdr.Flags&unix.VIRTIO_NET_HDR_F_RSC_INFO != 0 {
		return fmt.Errorf("virtio RSC_INFO flag not supported on TUN reads")
	}

	switch hdr.GSOType {
	case unix.VIRTIO_NET_HDR_GSO_NONE:
		if len(pkt) > len(scratch) {
			return fmt.Errorf("packet larger than segment buffer: %d > %d", len(pkt), len(scratch))
		}
		copy(scratch, pkt)
		seg := scratch[:len(pkt)]
		if hdr.Flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			if err := finishChecksum(seg, hdr); err != nil {
				return err
			}
		}
		*out = append(*out, seg)
		return nil

	case unix.VIRTIO_NET_HDR_GSO_TCPV4, unix.VIRTIO_NET_HDR_GSO_TCPV6:
		return segmentTCP(pkt, hdr, out, scratch)

	default:
		return fmt.Errorf("unsupported virtio gso type: %d", hdr.GSOType)
	}
}

// finishChecksum computes the L4 checksum for a non-GSO packet that the kernel
// handed us with NEEDS_CSUM set. csum_start / csum_offset point at the 16-bit
// checksum field; we zero it, fold a full sum (the field was pre-loaded with
// the pseudo-header partial sum by the kernel), and store the result.
func finishChecksum(seg []byte, hdr VirtioNetHdr) error {
	cs := int(hdr.CsumStart)
	co := int(hdr.CsumOffset)
	if cs+co+2 > len(seg) {
		return fmt.Errorf("csum offsets out of range: start=%d offset=%d len=%d", cs, co, len(seg))
	}
	// The kernel stores a partial pseudo-header sum at [cs+co:]; sum over the
	// L4 region starting at cs, folding the prior partial in as the seed.
	partial := binary.BigEndian.Uint16(seg[cs+co : cs+co+2])
	seg[cs+co] = 0
	seg[cs+co+1] = 0
	binary.BigEndian.PutUint16(seg[cs+co:cs+co+2], ^checksum.Checksum(seg[cs:], partial))
	return nil
}

// segmentTCP software-segments a TSO superpacket into one IP packet per MSS
// chunk. The caller guarantees hdr.GSOType is TCPV4 or TCPV6.
//
// Hot-path shape: the per-segment loop only sums the payload chunk. The TCP
// header, the IPv4 header, and the pseudo-header src/dst/proto contributions
// are each summed once up front — every segment reuses those three pre-folded
// uint32 values and combines them with small per-segment deltas (seq, flags,
// tcpLen, ip_id, total_len) that are cheap to fold in.
func segmentTCP(pkt []byte, hdr VirtioNetHdr, out *[][]byte, scratch []byte) error {
	if hdr.GSOSize == 0 {
		return fmt.Errorf("gso_size is zero")
	}
	if int(hdr.HdrLen) > len(pkt) || hdr.HdrLen == 0 {
		return fmt.Errorf("hdr_len %d out of range (pkt %d)", hdr.HdrLen, len(pkt))
	}
	if hdr.CsumStart == 0 || hdr.CsumStart >= hdr.HdrLen {
		return fmt.Errorf("csum_start %d out of range (hdr_len %d)", hdr.CsumStart, hdr.HdrLen)
	}

	isV4 := hdr.GSOType == unix.VIRTIO_NET_HDR_GSO_TCPV4
	headerLen := int(hdr.HdrLen)
	csumStart := int(hdr.CsumStart)

	if isV4 && csumStart < 20 {
		return fmt.Errorf("csum_start %d too small for IPv4", csumStart)
	}
	if !isV4 && csumStart < 40 {
		return fmt.Errorf("csum_start %d too small for IPv6", csumStart)
	}
	tcpHdrLen := headerLen - csumStart
	if tcpHdrLen < 20 {
		return fmt.Errorf("tcp header region too small: %d", tcpHdrLen)
	}

	payload := pkt[headerLen:]
	payLen := len(payload)
	gso := int(hdr.GSOSize)
	numSeg := (payLen + gso - 1) / gso
	if numSeg == 0 {
		numSeg = 1
	}

	need := numSeg*headerLen + payLen
	if need > len(scratch) {
		return fmt.Errorf("scratch too small for %d segments: need %d have %d", numSeg, need, len(scratch))
	}

	origSeq := binary.BigEndian.Uint32(pkt[csumStart+4 : csumStart+8])
	origFlags := pkt[csumStart+13]
	const tcpFinPsh = 0x09 // FIN(0x01) | PSH(0x08)

	// Precompute the TCP header sum with seq/flags/csum zeroed. The max TCP
	// header is 60 bytes; copy onto the stack, zero the per-segment-varying
	// fields, sum once.
	var tmp [60]byte
	copy(tmp[:tcpHdrLen], pkt[csumStart:headerLen])
	tmp[4], tmp[5], tmp[6], tmp[7] = 0, 0, 0, 0 // seq
	tmp[13] = 0                                 // flags
	tmp[16], tmp[17] = 0, 0                     // csum
	baseTcpHdrSum := uint32(checksum.Checksum(tmp[:tcpHdrLen], 0))

	// Pseudo-header src+dst+proto contribution (tcpLen varies per segment).
	var baseProtoSum uint32
	if isV4 {
		baseProtoSum = uint32(checksum.Checksum(pkt[12:20], 0))
	} else {
		baseProtoSum = uint32(checksum.Checksum(pkt[8:40], 0))
	}
	baseProtoSum += uint32(unix.IPPROTO_TCP)

	// Precompute IPv4 header sum with total_len/id/csum zeroed.
	var origIPID uint16
	var ihl int
	var baseIPHdrSum uint32
	if isV4 {
		origIPID = binary.BigEndian.Uint16(pkt[4:6])
		ihl = int(pkt[0]&0x0f) * 4
		if ihl < 20 || ihl > csumStart {
			return fmt.Errorf("bad IPv4 IHL: %d", ihl)
		}
		var ipTmp [60]byte
		copy(ipTmp[:ihl], pkt[:ihl])
		ipTmp[2], ipTmp[3] = 0, 0   // total_len
		ipTmp[4], ipTmp[5] = 0, 0   // id
		ipTmp[10], ipTmp[11] = 0, 0 // checksum
		baseIPHdrSum = uint32(checksum.Checksum(ipTmp[:ihl], 0))
	}

	off := 0
	for i := 0; i < numSeg; i++ {
		segStart := i * gso
		segEnd := segStart + gso
		if segEnd > payLen {
			segEnd = payLen
		}
		segPayLen := segEnd - segStart

		copy(scratch[off:], pkt[:headerLen])
		copy(scratch[off+headerLen:], payload[segStart:segEnd])
		seg := scratch[off : off+headerLen+segPayLen]
		off += headerLen + segPayLen

		segSeq := origSeq + uint32(segStart)
		segFlags := origFlags
		if i != numSeg-1 {
			segFlags = origFlags &^ tcpFinPsh
		}
		totalLen := headerLen + segPayLen

		// Patch IP header and write the v4 header checksum from the precomputed base.
		if isV4 {
			segID := origIPID + uint16(i)
			binary.BigEndian.PutUint16(seg[2:4], uint16(totalLen))
			binary.BigEndian.PutUint16(seg[4:6], segID)
			ipSum := baseIPHdrSum + uint32(totalLen) + uint32(segID)
			binary.BigEndian.PutUint16(seg[10:12], foldComplement(ipSum))
		} else {
			// IPv6 payload length excludes the 40-byte fixed header but
			// includes any extension headers between [40:csumStart].
			binary.BigEndian.PutUint16(seg[4:6], uint16(headerLen-40+segPayLen))
		}

		// Patch TCP header.
		binary.BigEndian.PutUint32(seg[csumStart+4:csumStart+8], segSeq)
		seg[csumStart+13] = segFlags
		// (csum is written below; its prior contents in `seg` don't affect the
		// computation since we never sum over the segment's own header.)

		tcpLen := tcpHdrLen + segPayLen
		paySum := uint32(checksum.Checksum(payload[segStart:segEnd], 0))

		// Combine pre-folded uint32s into a wider accumulator, then fold. Using
		// uint64 guards against overflow when segSeq's high bits set.
		wide := uint64(baseTcpHdrSum) + uint64(paySum) + uint64(baseProtoSum)
		wide += uint64(segSeq) + uint64(segFlags) + uint64(tcpLen)
		wide = (wide & 0xffffffff) + (wide >> 32)
		wide = (wide & 0xffffffff) + (wide >> 32)
		binary.BigEndian.PutUint16(seg[csumStart+16:csumStart+18], foldComplement(uint32(wide)))

		*out = append(*out, seg)
	}

	return nil
}

// foldComplement folds a 32-bit one's-complement partial sum to 16 bits and
// complements it, yielding the on-wire Internet checksum value.
func foldComplement(sum uint32) uint16 {
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	return ^uint16(sum)
}

// pseudoHeaderIPv4 returns the folded pseudo-header sum used to verify a TCP
// segment's checksum in tests. src/dst are 4 bytes each.
func pseudoHeaderIPv4(src, dst []byte, proto byte, tcpLen int) uint16 {
	s := uint32(checksum.Checksum(src, 0)) + uint32(checksum.Checksum(dst, 0))
	s += uint32(proto) + uint32(tcpLen)
	s = (s & 0xffff) + (s >> 16)
	s = (s & 0xffff) + (s >> 16)
	return uint16(s)
}

// pseudoHeaderIPv6 returns the folded pseudo-header sum used to verify a TCP
// segment's checksum in tests. src/dst are 16 bytes each.
func pseudoHeaderIPv6(src, dst []byte, proto byte, tcpLen int) uint16 {
	s := uint32(checksum.Checksum(src, 0)) + uint32(checksum.Checksum(dst, 0))
	s += uint32(tcpLen>>16) + uint32(tcpLen&0xffff) + uint32(proto)
	s = (s & 0xffff) + (s >> 16)
	s = (s & 0xffff) + (s >> 16)
	return uint16(s)
}
