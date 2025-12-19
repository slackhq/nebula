package virtio

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Workaround to make Go doc links work.
var _ unix.Errno

// NetHdrSize is the number of bytes needed to store a [NetHdr] in memory.
const NetHdrSize = 12

// ErrNetHdrBufferTooSmall is returned when a buffer is too small to fit a
// virtio_net_hdr.
var ErrNetHdrBufferTooSmall = errors.New("the buffer is too small to fit a virtio_net_hdr")

// NetHdr defines the virtio_net_hdr as described by the virtio specification.
type NetHdr struct {
	// Flags that describe the packet.
	// Possible values are:
	//   - [unix.VIRTIO_NET_HDR_F_NEEDS_CSUM]
	//   - [unix.VIRTIO_NET_HDR_F_DATA_VALID]
	//   - [unix.VIRTIO_NET_HDR_F_RSC_INFO]
	Flags uint8
	// GSOType contains the type of segmentation offload that should be used for
	// the packet.
	// Possible values are:
	//   - [unix.VIRTIO_NET_HDR_GSO_NONE]
	//   - [unix.VIRTIO_NET_HDR_GSO_TCPV4]
	//   - [unix.VIRTIO_NET_HDR_GSO_UDP]
	//   - [unix.VIRTIO_NET_HDR_GSO_TCPV6]
	//   - [unix.VIRTIO_NET_HDR_GSO_UDP_L4]
	//   - [unix.VIRTIO_NET_HDR_GSO_ECN]
	GSOType uint8
	// HdrLen contains the length of the headers that need to be replicated by
	// segmentation offloads. It's the number of bytes from the beginning of the
	// packet to the beginning of the transport payload.
	// Only used when [FeatureNetDriverHdrLen] is negotiated.
	HdrLen uint16
	// GSOSize contains the maximum size of each segmented packet beyond the
	// header (payload size). In case of TCP, this is the MSS.
	GSOSize uint16
	// CsumStart contains the offset within the packet from which on the
	// checksum should be computed.
	CsumStart uint16
	// CsumOffset specifies how many bytes after [NetHdr.CsumStart] the computed
	// 16-bit checksum should be inserted.
	CsumOffset uint16
	// NumBuffers contains the number of merged descriptor chains when
	// [FeatureNetMergeRXBuffers] is negotiated.
	// This field is only used for packets received by the driver and should be
	// zero for transmitted packets.
	NumBuffers uint16
}

// Decode decodes the [NetHdr] from the given byte slice. The slice must contain
// at least [NetHdrSize] bytes.
func (v *NetHdr) Decode(data []byte) error {
	if len(data) < NetHdrSize {
		return ErrNetHdrBufferTooSmall
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)), NetHdrSize), data[:NetHdrSize])
	return nil
}

// Encode encodes the [NetHdr] into the given byte slice. The slice must have
// room for at least [NetHdrSize] bytes.
func (v *NetHdr) Encode(data []byte) error {
	if len(data) < NetHdrSize {
		return ErrNetHdrBufferTooSmall
	}
	copy(data[:NetHdrSize], unsafe.Slice((*byte)(unsafe.Pointer(v)), NetHdrSize))
	return nil
}
