package tio

import "encoding/binary"

// Size of the legacy struct virtio_net_hdr that the kernel prepends/expects on
// a TUN opened with IFF_VNET_HDR (TUNSETVNETHDRSZ not set).
const virtioNetHdrLen = 10

type VirtioNetHdr struct {
	Flags      uint8
	GSOType    uint8
	HdrLen     uint16
	GSOSize    uint16
	CsumStart  uint16
	CsumOffset uint16
}

// decode reads a virtio_net_hdr in host byte order (TUN default; we never
// call TUNSETVNETLE so the kernel matches our endianness).
func (h *VirtioNetHdr) decode(b []byte) {
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
func (h *VirtioNetHdr) encode(b []byte) {
	b[0] = h.Flags
	b[1] = h.GSOType
	binary.NativeEndian.PutUint16(b[2:4], h.HdrLen)
	binary.NativeEndian.PutUint16(b[4:6], h.GSOSize)
	binary.NativeEndian.PutUint16(b[6:8], h.CsumStart)
	binary.NativeEndian.PutUint16(b[8:10], h.CsumOffset)
}
