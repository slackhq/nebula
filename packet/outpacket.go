package packet

import (
	"github.com/slackhq/nebula/util/virtio"
	"golang.org/x/sys/unix"
)

type OutPacket struct {
	Segments [][]byte
	// SegmentHeaders maps to the first virtio.NetHdrSize+14 bytes of Segments[n]
	SegmentHeaders [][]byte
	// SegmentPayloads maps to the remaining bytes of Segments[n]
	SegmentPayloads [][]byte
	// SegmentIDs is the list of underlying buffer IDs of Segments.
	// SegmentIDs, Segments, SegmentHeaders, SegmentPayloads should all have the same length at all times!
	SegmentIDs []uint16
}

func NewOut() *OutPacket {
	out := new(OutPacket)
	out.Segments = make([][]byte, 0, 64)
	out.SegmentHeaders = make([][]byte, 0, 64)
	out.SegmentPayloads = make([][]byte, 0, 64)
	out.SegmentIDs = make([]uint16, 0, 64)
	return out
}

func (pkt *OutPacket) Reset() {
	pkt.Segments = pkt.Segments[:0]
	pkt.SegmentPayloads = pkt.SegmentPayloads[:0]
	pkt.SegmentHeaders = pkt.SegmentHeaders[:0]
	pkt.SegmentIDs = pkt.SegmentIDs[:0]
}

// DestroyLastSegment removes the contents of the last segment in the list.
// Use this to handle firewall drops or similar, but still hand the segment buffer back to the underlying driver.
// Implementations shall discard zero-length segments internally.
func (pkt *OutPacket) DestroyLastSegment() {
	if len(pkt.Segments) == 0 {
		return
	}
	lastSeg := len(pkt.SegmentIDs) - 1
	pkt.SegmentPayloads[lastSeg] = pkt.SegmentPayloads[lastSeg][:0]
	pkt.SegmentHeaders[lastSeg] = pkt.SegmentHeaders[lastSeg][:0]
	pkt.Segments[lastSeg] = pkt.Segments[lastSeg][:0]
}

func (pkt *OutPacket) UseSegment(segID uint16, seg []byte, isV6 bool) int {
	pkt.SegmentIDs = append(pkt.SegmentIDs, segID)
	pkt.Segments = append(pkt.Segments, seg) //todo do we need this?

	vhdr := virtio.NetHdr{ //todo
		Flags:      unix.VIRTIO_NET_HDR_F_DATA_VALID,
		GSOType:    unix.VIRTIO_NET_HDR_GSO_NONE,
		HdrLen:     0,
		GSOSize:    0,
		CsumStart:  0,
		CsumOffset: 0,
		NumBuffers: 0,
	}

	hdr := seg[0 : virtio.NetHdrSize+14]
	_ = vhdr.Encode(hdr)
	if isV6 {
		hdr[virtio.NetHdrSize+14-2] = 0x86
		hdr[virtio.NetHdrSize+14-1] = 0xdd
	} else {
		hdr[virtio.NetHdrSize+14-2] = 0x08
		hdr[virtio.NetHdrSize+14-1] = 0x00
	}

	pkt.SegmentHeaders = append(pkt.SegmentHeaders, hdr)
	pkt.SegmentPayloads = append(pkt.SegmentPayloads, seg[virtio.NetHdrSize+14:])
	return len(pkt.SegmentIDs) - 1
}
