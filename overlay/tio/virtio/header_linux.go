//go:build linux && !android
// +build linux,!android

package virtio

import "encoding/binary"

// Size is the on-wire length of struct virtio_net_hdr the kernel
// prepends/expects on a TUN opened with IFF_VNET_HDR (TUNSETVNETHDRSZ
// not set).
const Size = 10

// Hdr is the Go view of the legacy virtio_net_hdr.
type Hdr struct {
	Flags      uint8
	GSOType    uint8
	HdrLen     uint16
	GSOSize    uint16
	CsumStart  uint16
	CsumOffset uint16
}

// Decode reads a virtio_net_hdr in host byte order (TUN default; we never
// call TUNSETVNETLE so the kernel matches our endianness).
func (h *Hdr) Decode(b []byte) {
	h.Flags = b[0]
	h.GSOType = b[1]
	h.HdrLen = binary.NativeEndian.Uint16(b[2:4])
	h.GSOSize = binary.NativeEndian.Uint16(b[4:6])
	h.CsumStart = binary.NativeEndian.Uint16(b[6:8])
	h.CsumOffset = binary.NativeEndian.Uint16(b[8:10])
}

// Encode is the inverse of Decode: writes the virtio_net_hdr fields into b
// (must be at least Size bytes). Used to emit a TSO superpacket on egress.
func (h *Hdr) Encode(b []byte) {
	b[0] = h.Flags
	b[1] = h.GSOType
	binary.NativeEndian.PutUint16(b[2:4], h.HdrLen)
	binary.NativeEndian.PutUint16(b[4:6], h.GSOSize)
	binary.NativeEndian.PutUint16(b[6:8], h.CsumStart)
	binary.NativeEndian.PutUint16(b[8:10], h.CsumOffset)
}
