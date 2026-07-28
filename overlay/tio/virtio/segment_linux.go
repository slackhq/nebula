//go:build linux && !android
// +build linux,!android

// Package virtio implements the pure validation, header-correction, and
// per-segment slicing logic for kernel-supplied TSO/USO superpackets on
// IFF_VNET_HDR TUN devices. It is FD-free and depends only on the byte
// layout of the virtio_net_hdr and the IP/TCP/UDP headers it describes,
// so it can be unit-tested in isolation from the tio Queue runtime.
package virtio

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/slackhq/nebula/overlay/checksum"
)

// Protocol header size bounds used to validate / cap kernel-supplied offsets.
const (
	ipv4HeaderMinLen = 20 // IHL=5, no options
	ipv4HeaderMaxLen = 60 // IHL=15, max options
	ipv6FixedLen     = 40 // IPv6 base header; extensions would extend this
	tcpHeaderMinLen  = 20 // data-offset=5, no options
	tcpHeaderMaxLen  = 60 // data-offset=15, max options
)

// maxSegHdrLen bounds the L3+L4 header we snapshot before stamping each segment.
// The largest header the segmenter supports is IPv4 (max IHL 60) plus TCP (max data-offset 60) = 120 bytes
const maxSegHdrLen = ipv4HeaderMaxLen + tcpHeaderMaxLen // 120

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

// UDP header is fixed at 8 bytes: {sport, dport, length, checksum}.
const (
	udpHeaderLen   = 8
	udpLengthOff   = 4
	udpChecksumOff = 6
)

// tcpFinPshMask is cleared on every segment except the last of a TSO burst.
const tcpFinPshMask = 0x09 // FIN(0x01) | PSH(0x08)

// tcpCwrFlag is cleared on every segment except the first.
// Per RFC 3168 §6.1.2 the CWR bit signals a one-shot transition (the sender just halved its window)
// and must appear on the first segment of a TSO burst only.
const tcpCwrFlag = 0x80

// CheckValid rejects packets whose virtio_net_hdr/IP combination would
// cause a downstream miscompute. The TUN should never emit RSC_INFO and
// the GSO type must agree with the IP version nibble.
func CheckValid(pkt []byte, hdr Hdr) error {
	if hdr.Flags&unix.VIRTIO_NET_HDR_F_RSC_INFO != 0 {
		return fmt.Errorf("virtio RSC_INFO flag not supported on TUN reads")
	}
	if len(pkt) < ipv4HeaderMinLen {
		return fmt.Errorf("packet too short")
	}
	ipVersion := pkt[0] >> 4

	gsoType := hdr.GSOType()
	if hdr.HasECNFlag() && !(gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV4 || gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV6) {
		return fmt.Errorf("virtio GSO_ECN qualifier on non-TCP GSO type %#x", hdr.gsoType)
	}
	switch gsoType {
	case unix.VIRTIO_NET_HDR_GSO_TCPV4:
		if ipVersion != 4 {
			return fmt.Errorf("invalid IP version %d for GSO type %d", ipVersion, hdr.gsoType)
		}
	case unix.VIRTIO_NET_HDR_GSO_TCPV6:
		if ipVersion != 6 {
			return fmt.Errorf("invalid IP version %d for GSO type %d", ipVersion, hdr.gsoType)
		}
	case unix.VIRTIO_NET_HDR_GSO_UDP_L4:
		// USO carries either v4 or v6; the leading nibble disambiguates.
		if !(ipVersion == 4 || ipVersion == 6) {
			return fmt.Errorf("invalid IP version %d for GSO type %d", ipVersion, hdr.gsoType)
		}
	default:
		if !(ipVersion == 6 || ipVersion == 4) {
			return fmt.Errorf("invalid IP version %d for GSO type %d", ipVersion, hdr.gsoType)
		}
	}

	return nil
}

// CorrectHdrLen rewrites hdr.HdrLen based on the actual transport header length read out of pkt.
// The kernel's hdr.HdrLen on the FORWARD path can be the length of the entire first packet, so we don't trust it.
func CorrectHdrLen(pkt []byte, hdr *Hdr) error {
	// Thank you wireguard-go for documenting these edge-cases
	// Don't trust hdr.hdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a FORWARD path.
	// Instead, parse the transport header length and add it onto csumStart, which is synonymous for IP header length.

	if hdr.GSOType() == unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		hdr.HdrLen = hdr.CsumStart + 8
	} else {
		if len(pkt) <= int(hdr.CsumStart+tcpDataOffOff) {
			return errors.New("packet is too short")
		}

		tcpHLen := uint16(pkt[hdr.CsumStart+tcpDataOffOff] >> 4 * 4)
		if tcpHLen < tcpHeaderMinLen || tcpHLen > tcpHeaderMaxLen {
			return fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		hdr.HdrLen = hdr.CsumStart + tcpHLen
	}

	if len(pkt) < int(hdr.HdrLen) {
		return fmt.Errorf("length of packet (%d) < virtioNetHdr.HdrLen (%d)", len(pkt), hdr.HdrLen)
	}

	if hdr.HdrLen < hdr.CsumStart {
		return fmt.Errorf("virtioNetHdr.HdrLen (%d) < virtioNetHdr.CsumStart (%d)", hdr.HdrLen, hdr.CsumStart)
	}
	cSumAt := int(hdr.CsumStart + hdr.CsumOffset)
	if cSumAt+1 >= len(pkt) {
		return fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", cSumAt+1, len(pkt))
	}
	return nil
}

// segCount returns how many segments a payload of payLen bytes splits into at gsoSize,
// with a floor of one so a header-only superpacket still yields a single segment.
func segCount(payLen, gsoSize int) int {
	n := (payLen + gsoSize - 1) / gsoSize
	if n == 0 {
		return 1
	}
	return n
}

// basePseudoSum folds the part of the L4 pseudo-header sum that is identical
// for every segment: the source and destination addresses plus the protocol
// number. The per-segment L4 length is added by the caller inside the loop.
func basePseudoSum(pkt []byte, isV4 bool, proto uint32) uint32 {
	if isV4 {
		return uint32(checksum.Checksum(pkt[ipv4SrcOff:ipv4AddrsEnd], 0)) + proto
	}
	return uint32(checksum.Checksum(pkt[ipv6SrcOff:ipv6AddrsEnd], 0)) + proto
}

// baseIPv4HdrSum folds the IPv4 header checksum over the fields that stay constant across segments.
// csumStart is the L3 header length, which bounds a valid IHL.
func baseIPv4HdrSum(pkt []byte, csumStart int, zeroID bool) (uint32, error) {
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || ihl > csumStart {
		return 0, fmt.Errorf("bad IPv4 IHL: %d", ihl)
	}
	// total_len and the checksum field itself are always excluded, since both are rewritten per segment.
	sum := uint32(checksum.Checksum(pkt[:ihl], 0))
	sum += uint32(^binary.BigEndian.Uint16(pkt[ipv4TotalLenOff : ipv4TotalLenOff+2]))
	sum += uint32(^binary.BigEndian.Uint16(pkt[ipv4ChecksumOff : ipv4ChecksumOff+2]))
	if zeroID { //only zero the ID if requested
		sum += uint32(^binary.BigEndian.Uint16(pkt[ipv4IDOff : ipv4IDOff+2]))
	}
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	return sum, nil
}

// baseTCPHdrSum folds the TCP header checksum over everything the segment loop does not rewrite
func baseTCPHdrSum(pkt []byte, csumStart, headerLen int) uint32 {
	seq := binary.BigEndian.Uint32(pkt[csumStart+tcpSeqOff : csumStart+tcpSeqOff+4])
	flags := uint16(pkt[csumStart+tcpFlagsOff])

	sum := uint32(checksum.Checksum(pkt[csumStart:headerLen], 0))
	sum += uint32(^uint16(seq >> 16))
	sum += uint32(^uint16(seq))
	sum += uint32(^flags)
	sum += uint32(^binary.BigEndian.Uint16(pkt[csumStart+tcpChecksumOff : csumStart+tcpChecksumOff+2]))
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	return sum
}

// SegmentTCP walks a TSO superpacket pkt, yielding each segment as a slice into pkt.
// Per-segment plaintext is laid out by stamping a copy of the original L3+L4 header into pkt at offset i*gsoSize,
// where it sits immediately before that segment's payload chunk in the original buffer.
// pkt is consumed by this call and must not be inspected by the caller after the final yield.
func SegmentTCP(pkt []byte, hdrLenU, csumStartU, gsoSizeU uint16, yield func(seg []byte) error) error {
	if gsoSizeU == 0 {
		return fmt.Errorf("gso_size is zero")
	}
	if csumStartU == 0 {
		return fmt.Errorf("csum_start is zero")
	}

	headerLen := int(hdrLenU)
	csumStart := int(csumStartU)
	if headerLen > maxSegHdrLen {
		return fmt.Errorf("header len %d exceeds max %d", headerLen, maxSegHdrLen)
	}
	isV4 := pkt[0]>>4 == 4

	tcpHdrLen := int(pkt[csumStart+tcpDataOffOff]>>4) * 4
	payLen := len(pkt) - headerLen
	gsoSize := int(gsoSizeU)
	numSeg := segCount(payLen, gsoSize)

	origSeq := binary.BigEndian.Uint32(pkt[csumStart+tcpSeqOff : csumStart+tcpSeqOff+4])
	origFlags := pkt[csumStart+tcpFlagsOff]

	baseProtoSum := basePseudoSum(pkt, isV4, unix.IPPROTO_TCP)
	baseTcpHdrSum := baseTCPHdrSum(pkt, csumStart, headerLen)

	var origIPID uint16
	var baseIPHdrSum uint32
	if isV4 {
		origIPID = binary.BigEndian.Uint16(pkt[ipv4IDOff : ipv4IDOff+2])
		var err error
		// TSO bumps the ID per segment, so it stays out of the base sum.
		baseIPHdrSum, err = baseIPv4HdrSum(pkt, csumStart, true)
		if err != nil {
			return err
		}
	}

	// Snapshot the pristine L3+L4 header once. '
	// Every segment's header is stamped from this copy, so overlapping stamps (gsoSize < headerLen) can never corrupt the source.
	var savedHdr [maxSegHdrLen]byte
	copy(savedHdr[:headerLen], pkt[:headerLen])

	for i := 0; i < numSeg; i++ {
		segStart := i * gsoSize
		segEnd := segStart + gsoSize
		if segEnd > payLen {
			segEnd = payLen
		}
		segPayLen := segEnd - segStart
		segLen := headerLen + segPayLen
		headerOff := i * gsoSize

		// Stamp the header into place immediately before this segment's payload, sourced from the snapshot.
		// The per-segment patches below overwrite the variable fields. (seq/flags/cksum/totalLen/id)
		if i > 0 {
			// Iter 0's header is already at pkt[:headerLen] (identical to savedHdr), so only i >= 1 needs the stamp
			copy(pkt[headerOff:headerOff+headerLen], savedHdr[:headerLen])
		}
		seg := pkt[headerOff : headerOff+segLen]

		segSeq := origSeq + uint32(segStart)
		segFlags := origFlags
		if i != 0 {
			segFlags &^= tcpCwrFlag
		}
		if i != numSeg-1 {
			segFlags &^= tcpFinPshMask
		}
		totalLen := segLen

		if isV4 {
			segID := origIPID + uint16(i)
			binary.BigEndian.PutUint16(seg[ipv4TotalLenOff:ipv4TotalLenOff+2], uint16(totalLen))
			binary.BigEndian.PutUint16(seg[ipv4IDOff:ipv4IDOff+2], segID)
			ipSum := baseIPHdrSum + uint32(totalLen) + uint32(segID)
			binary.BigEndian.PutUint16(seg[ipv4ChecksumOff:ipv4ChecksumOff+2], foldComplement(ipSum))
		} else {
			binary.BigEndian.PutUint16(seg[ipv6PayloadLenOff:ipv6PayloadLenOff+2], uint16(headerLen-ipv6FixedLen+segPayLen))
		}

		binary.BigEndian.PutUint32(seg[csumStart+tcpSeqOff:csumStart+tcpSeqOff+4], segSeq)
		seg[csumStart+tcpFlagsOff] = segFlags

		tcpLen := tcpHdrLen + segPayLen
		// Payload bytes still live at their original offset in pkt.
		// The header slide above only writes into pkt[i*GSOSize : i*GSOSize+header], which is the tail of seg_{i-1}'s payload (already consumed)
		// and never overlaps seg_i's own payload at pkt[header+i*GSOSize : header+(i+1)*GSOSize].
		paySum := uint32(checksum.Checksum(pkt[headerLen+segStart:headerLen+segEnd], 0))
		wide := uint64(baseTcpHdrSum) + uint64(paySum) + uint64(baseProtoSum)
		wide += uint64(segSeq) + uint64(segFlags) + uint64(tcpLen)
		wide = (wide & 0xffffffff) + (wide >> 32)
		wide = (wide & 0xffffffff) + (wide >> 32)
		binary.BigEndian.PutUint16(seg[csumStart+tcpChecksumOff:csumStart+tcpChecksumOff+2], foldComplement(uint32(wide)))

		if err := yield(seg); err != nil {
			return err
		}
	}

	return nil
}

// SegmentUDP walks a USO superpacket, stamping a per-segment-patched copy of the original L3+L4 header
// into pkt at offset i*GSOSize and yielding pkt[i*GSOSize:i*GSOSize+segLen] to the caller.
// Per-segment patches are total_len + IPv4 csum (or IPv6 payload_len) plus the UDP length and checksum.
// pkt is consumed destructively.
func SegmentUDP(pkt []byte, hdrLenU, csumStartU, gsoSizeU uint16, yield func(seg []byte) error) error {
	if gsoSizeU == 0 {
		return fmt.Errorf("gso_size is zero")
	}
	if csumStartU == 0 {
		return fmt.Errorf("csum_start is zero")
	}

	isV4 := pkt[0]>>4 == 4
	headerLen := int(hdrLenU)
	csumStart := int(csumStartU)
	if headerLen > maxSegHdrLen {
		return fmt.Errorf("header len %d exceeds max %d", headerLen, maxSegHdrLen)
	}
	if headerLen-csumStart != udpHeaderLen {
		return fmt.Errorf("udp header len mismatch: %d", headerLen-csumStart)
	}

	payLen := len(pkt) - headerLen
	gsoSize := int(gsoSizeU)
	numSeg := segCount(payLen, gsoSize)

	baseProtoSum := basePseudoSum(pkt, isV4, unix.IPPROTO_UDP)

	var baseIPHdrSum uint32
	if isV4 {
		var err error
		// UDP GSO holds the ID constant across the burst, so it stays in the base sum.
		baseIPHdrSum, err = baseIPv4HdrSum(pkt, csumStart, false)
		if err != nil {
			return err
		}
	}

	// Snapshot the pristine L3+L4 header once and stamp every segment from it
	var savedHdr [maxSegHdrLen]byte
	copy(savedHdr[:headerLen], pkt[:headerLen])

	for i := 0; i < numSeg; i++ {
		segStart := i * gsoSize
		segEnd := segStart + gsoSize
		if segEnd > payLen {
			segEnd = payLen
		}
		segPayLen := segEnd - segStart
		segLen := headerLen + segPayLen
		headerOff := i * gsoSize

		if i > 0 {
			copy(pkt[headerOff:headerOff+headerLen], savedHdr[:headerLen])
		}
		seg := pkt[headerOff : headerOff+segLen]

		totalLen := segLen
		udpLen := udpHeaderLen + segPayLen

		if isV4 {
			binary.BigEndian.PutUint16(seg[ipv4TotalLenOff:ipv4TotalLenOff+2], uint16(totalLen))
			ipSum := baseIPHdrSum + uint32(totalLen)
			binary.BigEndian.PutUint16(seg[ipv4ChecksumOff:ipv4ChecksumOff+2], foldComplement(ipSum))
		} else {
			binary.BigEndian.PutUint16(seg[ipv6PayloadLenOff:ipv6PayloadLenOff+2], uint16(headerLen-ipv6FixedLen+segPayLen))
		}

		binary.BigEndian.PutUint16(seg[csumStart+udpLengthOff:csumStart+udpLengthOff+2], uint16(udpLen))

		// Sum the UDP header (length just written, checksum zeroed) together with
		// this segment's payload in one pass, seeded with the pseudo-header sum.
		seg[csumStart+udpChecksumOff], seg[csumStart+udpChecksumOff+1] = 0, 0
		pseudo := baseProtoSum + uint32(udpLen)
		pseudo = (pseudo & 0xffff) + (pseudo >> 16)
		pseudo = (pseudo & 0xffff) + (pseudo >> 16)
		csum := ^checksum.Checksum(seg[csumStart:], uint16(pseudo))
		if csum == 0 {
			csum = 0xffff
		}
		binary.BigEndian.PutUint16(seg[csumStart+udpChecksumOff:csumStart+udpChecksumOff+2], csum)

		if err := yield(seg); err != nil {
			return err
		}
	}

	return nil
}

// FinishChecksum computes the L4 checksum for a non-GSO packet that the kernel handed us with NEEDS_CSUM set.
// CsumStart / CsumOffset point at the 16-bit checksum field.
// We zero it, fold a full sum from the partial one that the kernel provided, and store the result.
func FinishChecksum(seg []byte, hdr Hdr) error {
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
	csum := ^checksum.Checksum(seg[cs:], partial)
	// RFC 768: UDP transmits a computed zero as all ones, since all-zero is the reserved "no checksum" value.
	if co == udpChecksumOff && csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(seg[cs+co:cs+co+2], csum)
	return nil
}

// foldComplement folds a 32-bit one's-complement partial sum to 16 bits and
// complements it, yielding the on-wire Internet checksum value.
func foldComplement(sum uint32) uint16 {
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	return ^uint16(sum)
}
