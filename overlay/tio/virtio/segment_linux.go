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

// tcpCwrFlag is cleared on every segment except the first. Per RFC 3168
// §6.1.2 the CWR bit signals a one-shot transition (the sender just halved
// its window) and must appear on the first segment of a TSO burst only.
const tcpCwrFlag = 0x80

// CheckValid rejects packets whose virtio_net_hdr/IP combination would
// cause a downstream miscompute. The TUN should never emit RSC_INFO and
// the GSO type must agree with the IP version nibble.
func CheckValid(pkt []byte, hdr Hdr) error {
	// When RSC_INFO is set the csum_start/csum_offset fields are repurposed to
	// carry coalescing info rather than checksum offsets. A TUN writing via
	// IFF_VNET_HDR should never emit this, but if it did we would silently
	// miscompute the segment checksums — refuse the packet instead.
	if hdr.Flags&unix.VIRTIO_NET_HDR_F_RSC_INFO != 0 {
		return fmt.Errorf("virtio RSC_INFO flag not supported on TUN reads")
	}
	if len(pkt) < ipv4HeaderMinLen {
		return fmt.Errorf("packet too short")
	}
	ipVersion := pkt[0] >> 4
	switch hdr.GSOType {
	case unix.VIRTIO_NET_HDR_GSO_TCPV4:
		if ipVersion != 4 {
			return fmt.Errorf("invalid IP version %d for GSO type %d", ipVersion, hdr.GSOType)
		}
	case unix.VIRTIO_NET_HDR_GSO_TCPV6:
		if ipVersion != 6 {
			return fmt.Errorf("invalid IP version %d for GSO type %d", ipVersion, hdr.GSOType)
		}
	case unix.VIRTIO_NET_HDR_GSO_UDP_L4:
		// USO carries either v4 or v6; the leading nibble disambiguates.
		if !(ipVersion == 4 || ipVersion == 6) {
			return fmt.Errorf("invalid IP version %d for GSO type %d", ipVersion, hdr.GSOType)
		}
	default:
		if !(ipVersion == 6 || ipVersion == 4) {
			return fmt.Errorf("invalid IP version %d for GSO type %d", ipVersion, hdr.GSOType)
		}
	}

	return nil
}

// CorrectHdrLen rewrites hdr.HdrLen based on the actual transport header
// length read out of pkt. The kernel's hdr.HdrLen on the FORWARD path can
// be the length of the entire first packet, so we don't trust it.
func CorrectHdrLen(pkt []byte, hdr *Hdr) error {
	// Thank you wireguard-go for documenting these edge-cases
	// Don't trust hdr.hdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a
	// FORWARD path. Instead, parse the transport header length and add it onto
	// csumStart, which is synonymous for IP header length.

	if hdr.GSOType == unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		hdr.HdrLen = hdr.CsumStart + 8
	} else {
		if len(pkt) <= int(hdr.CsumStart+tcpDataOffOff) {
			return errors.New("packet is too short")
		}

		tcpHLen := uint16(pkt[hdr.CsumStart+tcpDataOffOff] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			// A TCP header must be between 20 and 60 bytes in length.
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
	cSumAt := int(hdr.CsumStart + hdr.CsumStart)
	if cSumAt+1 >= len(pkt) {
		return fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", cSumAt+1, len(pkt))
	}
	return nil
}

// SegmentTCP walks a TSO superpacket pkt, yielding each segment as a
// slice into pkt itself. Per-segment plaintext is laid out by sliding a
// freshly-patched copy of the L3+L4 header into pkt at offset i*gsoSize,
// where it sits immediately before that segment's payload chunk in the
// original buffer. The slide is destructive: iter i's header write overwrites
// the last hdrLen bytes of seg_{i-1}'s payload, which is dead by the time
// the next iteration begins. pkt is consumed by this call and must not be
// inspected by the caller after the final yield.
func SegmentTCP(pkt []byte, hdrLenU, csumStartU, gsoSizeU uint16, yield func(seg []byte) error) error {
	if gsoSizeU == 0 {
		return fmt.Errorf("gso_size is zero")
	}
	if csumStartU == 0 {
		return fmt.Errorf("csum_start is zero")
	}

	headerLen := int(hdrLenU)
	csumStart := int(csumStartU)
	isV4 := pkt[0]>>4 == 4

	tcpHdrLen := int(pkt[csumStart+tcpDataOffOff]>>4) * 4
	payLen := len(pkt) - headerLen
	gsoSize := int(gsoSizeU)
	numSeg := (payLen + gsoSize - 1) / gsoSize
	if numSeg == 0 {
		numSeg = 1
	}

	origSeq := binary.BigEndian.Uint32(pkt[csumStart+tcpSeqOff : csumStart+tcpSeqOff+4])
	origFlags := pkt[csumStart+tcpFlagsOff]

	var tmp [tcpHeaderMaxLen]byte
	copy(tmp[:tcpHdrLen], pkt[csumStart:headerLen])
	tmp[tcpSeqOff], tmp[tcpSeqOff+1], tmp[tcpSeqOff+2], tmp[tcpSeqOff+3] = 0, 0, 0, 0
	tmp[tcpFlagsOff] = 0
	tmp[tcpChecksumOff], tmp[tcpChecksumOff+1] = 0, 0
	baseTcpHdrSum := uint32(checksum.Checksum(tmp[:tcpHdrLen], 0))

	var baseProtoSum uint32
	if isV4 {
		baseProtoSum = uint32(checksum.Checksum(pkt[ipv4SrcOff:ipv4AddrsEnd], 0))
	} else {
		baseProtoSum = uint32(checksum.Checksum(pkt[ipv6SrcOff:ipv6AddrsEnd], 0))
	}
	baseProtoSum += uint32(unix.IPPROTO_TCP)

	var origIPID uint16
	var baseIPHdrSum uint32
	if isV4 {
		origIPID = binary.BigEndian.Uint16(pkt[ipv4IDOff : ipv4IDOff+2])
		ihl := int(pkt[0]&0x0f) * 4
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

	for i := 0; i < numSeg; i++ {
		segStart := i * gsoSize
		segEnd := segStart + gsoSize
		if segEnd > payLen {
			segEnd = payLen
		}
		segPayLen := segEnd - segStart
		segLen := headerLen + segPayLen
		headerOff := i * gsoSize

		// Slide the header into place immediately before this segment's
		// payload. Iter 0's header is already at pkt[:headerLen]; for
		// i ≥ 1 we copy from there. The constant-byte fields of pkt[:headerLen]
		// survive iter 0's in-place patches (only seq/flags/cksum/totalLen/id
		// are touched), and iter 0's stale variable-field values are
		// overwritten by the per-segment patches below.
		if i > 0 {
			copy(pkt[headerOff:headerOff+headerLen], pkt[:headerLen])
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
		// Payload bytes still live at their original offset in pkt. The
		// header slide above only writes into pkt[i*G : i*G+H], which is
		// the tail of seg_{i-1}'s payload (already consumed) and never
		// overlaps seg_i's own payload at pkt[H+i*G : H+(i+1)*G].
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

// SegmentUDP walks a USO superpacket, sliding a per-segment-patched
// L3+L4 header into pkt at offset i*gsoSize and yielding pkt[i*G:i*G+segLen]
// to the caller. Per-segment patches are total_len + IPv4 csum (or IPv6
// payload_len) plus the UDP length and checksum. pkt is consumed
// destructively; see SegmentTCP for the layout reasoning.
//
// UDP-GSO leaves the IPv4 ID identical across segments (the kernel does not
// bump it), which is why the IP-level per-segment work is limited to
// total_len + IPv4 header checksum (v4) or payload_len (v6).
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
	if headerLen-csumStart != udpHeaderLen {
		return fmt.Errorf("udp header len mismatch: %d", headerLen-csumStart)
	}

	payLen := len(pkt) - headerLen
	gsoSize := int(gsoSizeU)
	numSeg := (payLen + gsoSize - 1) / gsoSize
	if numSeg == 0 {
		numSeg = 1
	}

	var udpTmp [udpHeaderLen]byte
	copy(udpTmp[:], pkt[csumStart:headerLen])
	udpTmp[udpLengthOff], udpTmp[udpLengthOff+1] = 0, 0
	udpTmp[udpChecksumOff], udpTmp[udpChecksumOff+1] = 0, 0
	baseUDPHdrSum := uint32(checksum.Checksum(udpTmp[:], 0))

	var baseProtoSum uint32
	if isV4 {
		baseProtoSum = uint32(checksum.Checksum(pkt[ipv4SrcOff:ipv4AddrsEnd], 0))
	} else {
		baseProtoSum = uint32(checksum.Checksum(pkt[ipv6SrcOff:ipv6AddrsEnd], 0))
	}
	baseProtoSum += uint32(unix.IPPROTO_UDP)

	var baseIPHdrSum uint32
	if isV4 {
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < ipv4HeaderMinLen || ihl > csumStart {
			return fmt.Errorf("bad IPv4 IHL: %d", ihl)
		}
		var ipTmp [ipv4HeaderMaxLen]byte
		copy(ipTmp[:ihl], pkt[:ihl])
		ipTmp[ipv4TotalLenOff], ipTmp[ipv4TotalLenOff+1] = 0, 0
		ipTmp[ipv4ChecksumOff], ipTmp[ipv4ChecksumOff+1] = 0, 0
		baseIPHdrSum = uint32(checksum.Checksum(ipTmp[:ihl], 0))
	}

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
			copy(pkt[headerOff:headerOff+headerLen], pkt[:headerLen])
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

		paySum := uint32(checksum.Checksum(pkt[headerLen+segStart:headerLen+segEnd], 0))
		wide := uint64(baseUDPHdrSum) + uint64(paySum) + uint64(baseProtoSum)
		wide += uint64(udpLen) + uint64(udpLen)
		wide = (wide & 0xffffffff) + (wide >> 32)
		wide = (wide & 0xffffffff) + (wide >> 32)
		csum := foldComplement(uint32(wide))
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

// FinishChecksum computes the L4 checksum for a non-GSO packet that the kernel
// handed us with NEEDS_CSUM set. csum_start / csum_offset point at the 16-bit
// checksum field; we zero it, fold a full sum (the field was pre-loaded with
// the pseudo-header partial sum by the kernel), and store the result.
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
	binary.BigEndian.PutUint16(seg[cs+co:cs+co+2], ^checksum.Checksum(seg[cs:], partial))
	return nil
}

// foldComplement folds a 32-bit one's-complement partial sum to 16 bits and
// complements it, yielding the on-wire Internet checksum value.
func foldComplement(sum uint32) uint16 {
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	return ^uint16(sum)
}
