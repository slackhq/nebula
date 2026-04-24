//go:build linux && !android && !e2e_testing
// +build linux,!android,!e2e_testing

package tio

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// Protocol header size bounds used to validate / cap kernel-supplied offsets.
const (
	ipv4HeaderMinLen = 20 // IHL=5, no options
	ipv4HeaderMaxLen = 60 // IHL=15, max options
	ipv6FixedLen     = 40 // IPv6 base header; extensions would extend this
	tcpHeaderMinLen  = 20 // data-offset=5, no options
	tcpHeaderMaxLen  = 60 // data-offset=15, max options
)

// Byte offsets inside an IPv4 header.
const (
	ipv4TotalLenOff = 2
	ipv4IDOff       = 4
	ipv4ChecksumOff = 10
	ipv4SrcOff      = 12
	ipv4AddrsEnd    = 20 // end of dst address (ipv4SrcOff + 2*4)
)

// Byte offsets inside an IPv6 header.
const (
	ipv6PayloadLenOff = 4
	ipv6SrcOff        = 8
	ipv6AddrsEnd      = 40 // end of dst address (ipv6SrcOff + 2*16)
)

// Byte offsets inside a TCP header (relative to its start, i.e. csumStart).
const (
	tcpSeqOff      = 4
	tcpDataOffOff  = 12 // upper nibble is header len in 32-bit words
	tcpFlagsOff    = 13
	tcpChecksumOff = 16
)

// tcpFinPshMask is cleared on every segment except the last of a TSO burst.
const tcpFinPshMask = 0x09 // FIN(0x01) | PSH(0x08)

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
	if hdr.CsumStart == 0 {
		return fmt.Errorf("csum_start is zero")
	}

	isV4 := hdr.GSOType == unix.VIRTIO_NET_HDR_GSO_TCPV4
	csumStart := int(hdr.CsumStart)

	if isV4 && csumStart < ipv4HeaderMinLen {
		return fmt.Errorf("csum_start %d too small for IPv4", csumStart)
	}
	if !isV4 && csumStart < ipv6FixedLen {
		return fmt.Errorf("csum_start %d too small for IPv6", csumStart)
	}

	// Don't trust hdr.HdrLen from the kernel: on some paths it can be set
	// to the full length of the first packet rather than the true L3+L4 header length.
	// Instead, read the TCP data-offset field from the packet itself and derive
	// headerLen = csum_start + tcpHdrLen. Matches wireguard-go's approach.
	if csumStart+tcpFlagsOff+1 > len(pkt) {
		return fmt.Errorf("packet too short for tcp header at csum_start=%d (pkt %d)", csumStart, len(pkt))
	}
	tcpHdrLen := int(pkt[csumStart+tcpDataOffOff]>>4) * 4
	if tcpHdrLen < tcpHeaderMinLen || tcpHdrLen > tcpHeaderMaxLen {
		return fmt.Errorf("tcp data-offset out of range: %d", tcpHdrLen)
	}
	headerLen := csumStart + tcpHdrLen
	if headerLen > len(pkt) {
		return fmt.Errorf("derived hdr_len %d > pkt %d", headerLen, len(pkt))
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

	origSeq := binary.BigEndian.Uint32(pkt[csumStart+tcpSeqOff : csumStart+tcpSeqOff+4])
	origFlags := pkt[csumStart+tcpFlagsOff]

	// Precompute the TCP header sum with seq/flags/csum zeroed. Copy onto
	// the stack, zero the per-segment-varying fields, sum once.
	var tmp [tcpHeaderMaxLen]byte
	copy(tmp[:tcpHdrLen], pkt[csumStart:headerLen])
	tmp[tcpSeqOff], tmp[tcpSeqOff+1], tmp[tcpSeqOff+2], tmp[tcpSeqOff+3] = 0, 0, 0, 0
	tmp[tcpFlagsOff] = 0
	tmp[tcpChecksumOff], tmp[tcpChecksumOff+1] = 0, 0
	baseTcpHdrSum := uint32(checksum.Checksum(tmp[:tcpHdrLen], 0))

	// Pseudo-header src+dst+proto contribution (tcpLen varies per segment).
	var baseProtoSum uint32
	if isV4 {
		baseProtoSum = uint32(checksum.Checksum(pkt[ipv4SrcOff:ipv4AddrsEnd], 0))
	} else {
		baseProtoSum = uint32(checksum.Checksum(pkt[ipv6SrcOff:ipv6AddrsEnd], 0))
	}
	baseProtoSum += uint32(unix.IPPROTO_TCP)

	// Precompute IPv4 header sum with total_len/id/csum zeroed.
	var origIPID uint16
	var ihl int
	var baseIPHdrSum uint32
	if isV4 {
		origIPID = binary.BigEndian.Uint16(pkt[ipv4IDOff : ipv4IDOff+2])
		ihl = int(pkt[0]&0x0f) * 4
		if ihl < ipv4HeaderMinLen || ihl > csumStart {
			return fmt.Errorf("bad IPv4 IHL: %d", ihl)
		}
		var ipTmp [ipv4HeaderMaxLen]byte
		copy(ipTmp[:ihl], pkt[:ihl])
		ipTmp[ipv4TotalLenOff], ipTmp[ipv4TotalLenOff+1] = 0, 0
		ipTmp[ipv4IDOff], ipTmp[ipv4IDOff+1] = 0, 0
		ipTmp[ipv4ChecksumOff], ipTmp[ipv4ChecksumOff+1] = 0, 0
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
			segFlags = origFlags &^ tcpFinPshMask
		}
		totalLen := headerLen + segPayLen

		// Patch IP header and write the v4 header checksum from the precomputed base.
		if isV4 {
			segID := origIPID + uint16(i)
			binary.BigEndian.PutUint16(seg[ipv4TotalLenOff:ipv4TotalLenOff+2], uint16(totalLen))
			binary.BigEndian.PutUint16(seg[ipv4IDOff:ipv4IDOff+2], segID)
			ipSum := baseIPHdrSum + uint32(totalLen) + uint32(segID)
			binary.BigEndian.PutUint16(seg[ipv4ChecksumOff:ipv4ChecksumOff+2], foldComplement(ipSum))
		} else {
			// IPv6 payload length excludes the fixed header but includes any
			// extension headers between [ipv6FixedLen:csumStart].
			binary.BigEndian.PutUint16(seg[ipv6PayloadLenOff:ipv6PayloadLenOff+2], uint16(headerLen-ipv6FixedLen+segPayLen))
		}

		// Patch TCP header.
		binary.BigEndian.PutUint32(seg[csumStart+tcpSeqOff:csumStart+tcpSeqOff+4], segSeq)
		seg[csumStart+tcpFlagsOff] = segFlags
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
		binary.BigEndian.PutUint16(seg[csumStart+tcpChecksumOff:csumStart+tcpChecksumOff+2], foldComplement(uint32(wide)))

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
