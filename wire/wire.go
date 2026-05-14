package wire

// TunPacket is the unit a read from a tun device returns.
// On supported platforms, it may be a superpacket, but a single TunPacket will never have more than one destination.
type TunPacket struct {
	// Bytes contains the actual packet
	Bytes []byte
	// Meta contains other information to help process the packet correctly, such as offsets for segmentation offloads
	// Fields in Meta should be as portable/platform-agnostic as possible.
	Meta GSOInfo
}

// GSOInfo describes a kernel-supplied superpacket sitting in Packet.Bytes.
// The zero value means "not a superpacket" — Bytes is one regular IP
// datagram and no segmentation is required.
type GSOInfo struct {
	// Size is the GSO segment size: max payload bytes per segment
	// (== TCP MSS for TSO, == UDP payload chunk for USO). Zero means
	// not a superpacket.
	Size uint16
	// HdrLen is the total L3+L4 header length within Bytes (already
	// corrected via correctHdrLen, so safe to slice on).
	HdrLen uint16
	// CsumStart is the L4 header offset inside Bytes (== L3 header
	// length).
	CsumStart uint16
	// Proto picks the L4 protocol (TCP or UDP) so the segmenter knows
	// which checksum/header layout to apply.
	Proto GSOProto
}

// GSOProto selects the L4 protocol for a GSO superpacket. Determines which
// VIRTIO_NET_HDR_GSO_* type the writer stamps and which checksum offset
// inside the transport header virtio NEEDS_CSUM expects.
type GSOProto uint8

const (
	GSOProtoNone GSOProto = iota
	GSOProtoTCP
	GSOProtoUDP
)

// IsSuperpacket reports whether g describes a multi-segment GSO/USO
// superpacket that needs segmentation before its bytes can be encrypted
// and sent on the wire.
func (g GSOInfo) IsSuperpacket() bool { return g.Size > 0 }
