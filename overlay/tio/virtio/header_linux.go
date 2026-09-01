//go:build linux && !android

package virtio

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// Size is the on-wire length of struct virtio_net_hdr the kernel
// prepends/expects on a TUN opened with IFF_VNET_HDR (TUNSETVNETHDRSZ
// not set).
const Size = 10

// Hdr is the Go view of the legacy virtio_net_hdr.
type Hdr struct {
	Flags      uint8
	gsoType    uint8 //private to avoid mistakes wrt the 0x80 VIRTIO_NET_HDR_GSO_ECN flag, ORed with the other "GSO types"
	HdrLen     uint16
	GSOSize    uint16
	CsumStart  uint16
	CsumOffset uint16
}

func NewHeader(flags, gsoType uint8, hdrLen, gsoSize, csumStart, csumOffset uint16) Hdr {
	return Hdr{
		Flags:      flags,
		gsoType:    gsoType,
		HdrLen:     hdrLen,
		GSOSize:    gsoSize,
		CsumStart:  csumStart,
		CsumOffset: csumOffset,
	}
}

// Decode reads a virtio_net_hdr in host byte order (TUN default; we never
// call TUNSETVNETLE so the kernel matches our endianness).
func (h *Hdr) Decode(b []byte) {
	h.Flags = b[0]
	h.gsoType = b[1]
	h.HdrLen = binary.NativeEndian.Uint16(b[2:4])
	h.GSOSize = binary.NativeEndian.Uint16(b[4:6])
	h.CsumStart = binary.NativeEndian.Uint16(b[6:8])
	h.CsumOffset = binary.NativeEndian.Uint16(b[8:10])
}

func EncodeHeader(b []byte, flags, gsoType uint8, hdrLen, gsoSize, csumStart, csumOffset uint16) {
	b[0] = flags
	b[1] = gsoType
	binary.NativeEndian.PutUint16(b[2:4], hdrLen)
	binary.NativeEndian.PutUint16(b[4:6], gsoSize)
	binary.NativeEndian.PutUint16(b[6:8], csumStart)
	binary.NativeEndian.PutUint16(b[8:10], csumOffset)
}

// Encode is the inverse of Decode: writes the virtio_net_hdr fields into b
// (must be at least Size bytes). Used to emit a TSO superpacket on egress.
func (h *Hdr) Encode(b []byte) {
	EncodeHeader(b, h.Flags, h.gsoType, h.HdrLen, h.GSOSize, h.CsumStart, h.CsumOffset)
}

// GSOType returns gsoType with the ECN-flag masked out
func (h *Hdr) GSOType() uint8 {
	return h.gsoType &^ unix.VIRTIO_NET_HDR_GSO_ECN
}

func (h *Hdr) HasECNFlag() bool {
	return h.gsoType&unix.VIRTIO_NET_HDR_GSO_ECN != 0
}

func (h *Hdr) SetGSOType(x uint8) {
	h.gsoType = x
}
