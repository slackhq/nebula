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
	if headerLen-csumStart < 20 {
		return fmt.Errorf("tcp header region too small: %d", headerLen-csumStart)
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

	var origIPID uint16
	if isV4 {
		origIPID = binary.BigEndian.Uint16(pkt[4:6])
	}

	off := 0
	for i := 0; i < numSeg; i++ {
		segStart := i * gso
		segEnd := segStart + gso
		if segEnd > payLen {
			segEnd = payLen
		}
		segPayLen := segEnd - segStart

		// Materialise IP+TCP header and this segment's payload chunk.
		copy(scratch[off:], pkt[:headerLen])
		copy(scratch[off+headerLen:], payload[segStart:segEnd])
		seg := scratch[off : off+headerLen+segPayLen]
		off += headerLen + segPayLen

		// Fix IP header: total/payload length, v4 ID, v4 header csum.
		if isV4 {
			ihl := int(seg[0]&0x0f) * 4
			if ihl < 20 || ihl > csumStart {
				return fmt.Errorf("bad IPv4 IHL: %d", ihl)
			}
			binary.BigEndian.PutUint16(seg[2:4], uint16(headerLen+segPayLen))
			binary.BigEndian.PutUint16(seg[4:6], origIPID+uint16(i))
			seg[10] = 0
			seg[11] = 0
			binary.BigEndian.PutUint16(seg[10:12], checksumFold(checksumBytes(seg[:ihl], 0)))
		} else {
			// IPv6 payload length excludes the 40-byte fixed header but
			// includes any extension headers that sit between [40:csumStart].
			binary.BigEndian.PutUint16(seg[4:6], uint16(headerLen-40+segPayLen))
		}

		// Fix TCP header: seq, flags, checksum.
		segSeq := origSeq + uint32(segStart)
		binary.BigEndian.PutUint32(seg[csumStart+4:csumStart+8], segSeq)
		if i != numSeg-1 {
			seg[csumStart+13] = origFlags &^ tcpFinPsh
		} else {
			seg[csumStart+13] = origFlags
		}
		seg[csumStart+16] = 0
		seg[csumStart+17] = 0

		tcpLen := headerLen - csumStart + segPayLen
		var psum uint32
		if isV4 {
			psum = pseudoHeaderIPv4(seg[12:16], seg[16:20], unix.IPPROTO_TCP, tcpLen)
		} else {
			psum = pseudoHeaderIPv6(seg[8:24], seg[24:40], unix.IPPROTO_TCP, tcpLen)
		}
		binary.BigEndian.PutUint16(seg[csumStart+16:csumStart+18], checksumFold(checksumBytes(seg[csumStart:csumStart+tcpLen], psum)))

		*out = append(*out, seg)
	}

	return nil
}

// checksumBytes returns the Internet-checksum partial sum of b, seeded with
// initial. Result is a 32-bit accumulator; the caller folds to 16.
//
// Wide-word variant: each 8-byte load contributes four 16-bit lanes to a
// 64-bit accumulator, cutting the number of loads, shifts, and slice reslices
// ~4x versus the naive Uint16 loop. The 64-bit accumulator has ample headroom
// — worst case is (initial=2^32) + (64KiB / 2) * 0xffff ≈ 2.5 * 10^9, far
// below 2^64 — so no mid-loop fold is needed.
func checksumBytes(b []byte, initial uint32) uint32 {
	sum := uint64(initial)
	for len(b) >= 16 {
		w1 := binary.BigEndian.Uint64(b[:8])
		w2 := binary.BigEndian.Uint64(b[8:16])
		sum += (w1 >> 48) + ((w1 >> 32) & 0xffff) + ((w1 >> 16) & 0xffff) + (w1 & 0xffff)
		sum += (w2 >> 48) + ((w2 >> 32) & 0xffff) + ((w2 >> 16) & 0xffff) + (w2 & 0xffff)
		b = b[16:]
	}
	if len(b) >= 8 {
		w := binary.BigEndian.Uint64(b[:8])
		sum += (w >> 48) + ((w >> 32) & 0xffff) + ((w >> 16) & 0xffff) + (w & 0xffff)
		b = b[8:]
	}
	if len(b) >= 4 {
		w := binary.BigEndian.Uint32(b[:4])
		sum += uint64(w>>16) + uint64(w&0xffff)
		b = b[4:]
	}
	if len(b) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint64(b[0]) << 8
	}
	// Fold 64 → 32. The checksum is one's complement, so carries are
	// end-around-added; once the high 32 bits are zero we're done.
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
