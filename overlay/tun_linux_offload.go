//go:build linux && !android && !e2e_testing
// +build linux,!android,!e2e_testing

package overlay

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// Size of the legacy struct virtio_net_hdr that the kernel prepends/expects on
// a TUN opened with IFF_VNET_HDR (TUNSETVNETHDRSZ not set).
const virtioNetHdrLen = 10

// Maximum size we accept for a single read from a TUN with IFF_VNET_HDR. A
// TSO superpacket can be up to 64KiB of payload plus a single L2/L3/L4 header
// prefix plus the virtio header.
const tunReadBufSize = 65535

// Space for segmented output. Worst case is many small segments, each paying
// an IP+TCP header. 128KiB comfortably covers the 64KiB payload ceiling.
const tunSegBufSize = 131072

// tunSegBufCap is the total size we allocate for the per-reader segment
// buffer. It is sized as one worst-case TSO superpacket (tunSegBufSize) plus
// the same again as drain headroom so a ReadBatch wake can accumulate
// additional packets after an initial big read without overflowing.
const tunSegBufCap = tunSegBufSize * 2

// tunDrainCap caps how many packets a single ReadBatch will accumulate via
// the post-wake drain loop. Sized to soak up a burst of small ACKs while
// bounding how much work a single caller holds before handing off.
const tunDrainCap = 64

type virtioNetHdr struct {
	Flags      uint8
	GSOType    uint8
	HdrLen     uint16
	GSOSize    uint16
	CsumStart  uint16
	CsumOffset uint16
}

// decode reads a virtio_net_hdr in host byte order (TUN default; we never
// call TUNSETVNETLE so the kernel matches our endianness).
func (h *virtioNetHdr) decode(b []byte) {
	h.Flags = b[0]
	h.GSOType = b[1]
	h.HdrLen = binary.NativeEndian.Uint16(b[2:4])
	h.GSOSize = binary.NativeEndian.Uint16(b[4:6])
	h.CsumStart = binary.NativeEndian.Uint16(b[6:8])
	h.CsumOffset = binary.NativeEndian.Uint16(b[8:10])
}

// encode is the inverse of decode: writes the virtio_net_hdr fields into b
// (must be at least virtioNetHdrLen bytes). Used to emit a TSO superpacket
// on egress.
func (h *virtioNetHdr) encode(b []byte) {
	b[0] = h.Flags
	b[1] = h.GSOType
	binary.NativeEndian.PutUint16(b[2:4], h.HdrLen)
	binary.NativeEndian.PutUint16(b[4:6], h.GSOSize)
	binary.NativeEndian.PutUint16(b[6:8], h.CsumStart)
	binary.NativeEndian.PutUint16(b[8:10], h.CsumOffset)
}

// segmentInto splits a TUN-side packet described by hdr into one or more
// IP packets, each appended to *out as a slice of scratch. scratch must be
// sized to hold every segment (including replicated headers).
func segmentInto(pkt []byte, hdr virtioNetHdr, out *[][]byte, scratch []byte) error {
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
func finishChecksum(seg []byte, hdr virtioNetHdr) error {
	cs := int(hdr.CsumStart)
	co := int(hdr.CsumOffset)
	if cs+co+2 > len(seg) {
		return fmt.Errorf("csum offsets out of range: start=%d offset=%d len=%d", cs, co, len(seg))
	}
	// The kernel stores a partial pseudo-header sum at [cs+co:]; sum over the
	// L4 region starting at cs, folding the prior partial in as the seed.
	partial := uint32(binary.BigEndian.Uint16(seg[cs+co : cs+co+2]))
	seg[cs+co] = 0
	seg[cs+co+1] = 0
	sum := checksumBytes(seg[cs:], partial)
	binary.BigEndian.PutUint16(seg[cs+co:cs+co+2], checksumFold(sum))
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
func segmentTCP(pkt []byte, hdr virtioNetHdr, out *[][]byte, scratch []byte) error {
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
	baseTcpHdrSum := checksumBytes(tmp[:tcpHdrLen], 0)

	// Pseudo-header src+dst+proto contribution (tcpLen varies per segment).
	var baseProtoSum uint32
	if isV4 {
		baseProtoSum = checksumBytes(pkt[12:16], 0)
		baseProtoSum = checksumBytes(pkt[16:20], baseProtoSum)
	} else {
		baseProtoSum = checksumBytes(pkt[8:24], 0)
		baseProtoSum = checksumBytes(pkt[24:40], baseProtoSum)
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
		baseIPHdrSum = checksumBytes(ipTmp[:ihl], 0)
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
			binary.BigEndian.PutUint16(seg[10:12], checksumFold(ipSum))
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
		paySum := checksumBytes(payload[segStart:segEnd], 0)

		// Combine pre-folded uint32s into a wider accumulator, then fold. Using
		// uint64 guards against overflow when segSeq's high bits set.
		wide := uint64(baseTcpHdrSum) + uint64(paySum) + uint64(baseProtoSum)
		wide += uint64(segSeq) + uint64(segFlags) + uint64(tcpLen)
		wide = (wide & 0xffffffff) + (wide >> 32)
		wide = (wide & 0xffffffff) + (wide >> 32)
		binary.BigEndian.PutUint16(seg[csumStart+16:csumStart+18], checksumFold(uint32(wide)))

		*out = append(*out, seg)
	}

	return nil
}

// checksumBytes returns the Internet-checksum partial sum of b, seeded with
// initial. Result is a 32-bit accumulator; the caller folds to 16.
//
// Each 4-byte load is added directly into a 64-bit accumulator. Two parallel
// accumulators break the serial dependency through `sum` and let the CPU
// overlap independent adds. The final fold from 64 → 32 → 16 handles the
// carries that accumulated across the 32-bit lane boundary.
func checksumBytes(b []byte, initial uint32) uint32 {
	s0 := uint64(initial)
	var s1 uint64
	for len(b) >= 32 {
		s0 += uint64(binary.BigEndian.Uint32(b[0:4]))
		s1 += uint64(binary.BigEndian.Uint32(b[4:8]))
		s0 += uint64(binary.BigEndian.Uint32(b[8:12]))
		s1 += uint64(binary.BigEndian.Uint32(b[12:16]))
		s0 += uint64(binary.BigEndian.Uint32(b[16:20]))
		s1 += uint64(binary.BigEndian.Uint32(b[20:24]))
		s0 += uint64(binary.BigEndian.Uint32(b[24:28]))
		s1 += uint64(binary.BigEndian.Uint32(b[28:32]))
		b = b[32:]
	}
	sum := s0 + s1
	for len(b) >= 4 {
		sum += uint64(binary.BigEndian.Uint32(b[:4]))
		b = b[4:]
	}
	if len(b) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint64(b[0]) << 8
	}
	sum = (sum & 0xffffffff) + (sum >> 32)
	sum = (sum & 0xffffffff) + (sum >> 32)
	return uint32(sum)
}

func checksumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func pseudoHeaderIPv4(src, dst []byte, proto byte, tcpLen int) uint32 {
	sum := checksumBytes(src, 0)
	sum = checksumBytes(dst, sum)
	sum += uint32(proto)
	sum += uint32(tcpLen)
	return sum
}

func pseudoHeaderIPv6(src, dst []byte, proto byte, tcpLen int) uint32 {
	sum := checksumBytes(src, 0)
	sum = checksumBytes(dst, sum)
	sum += uint32(tcpLen >> 16)
	sum += uint32(tcpLen & 0xffff)
	sum += uint32(proto)
	return sum
}
