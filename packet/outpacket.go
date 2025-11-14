package packet

import (
	"github.com/slackhq/nebula/util/virtio"
	"golang.org/x/sys/unix"
)

type OutPacket struct {
	Segments        [][]byte
	SegmentPayloads [][]byte
	SegmentHeaders  [][]byte
	SegmentIDs      []uint16
	//todo virtio header?
	SegSize      int
	SegCounter   int
	Valid        bool
	wasSegmented bool

	Scratch []byte
}

func NewOut() *OutPacket {
	out := new(OutPacket)
	out.Segments = make([][]byte, 0, 64)
	out.SegmentHeaders = make([][]byte, 0, 64)
	out.SegmentPayloads = make([][]byte, 0, 64)
	out.SegmentIDs = make([]uint16, 0, 64)
	out.Scratch = make([]byte, Size)
	return out
}

func (pkt *OutPacket) Reset() {
	pkt.Segments = pkt.Segments[:0]
	pkt.SegmentPayloads = pkt.SegmentPayloads[:0]
	pkt.SegmentHeaders = pkt.SegmentHeaders[:0]
	pkt.SegmentIDs = pkt.SegmentIDs[:0]
	pkt.SegSize = 0
	pkt.Valid = false
	pkt.wasSegmented = false
}

func (pkt *OutPacket) UseSegment(segID uint16, seg []byte, isV6 bool) int {
	pkt.Valid = true
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
