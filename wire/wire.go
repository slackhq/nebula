package wire

// TunPacket is the unit a read from a tun device returns.
// On supported platforms, it may be a superpacket, but a single TunPacket will never have more than one destination.
type TunPacket struct {
	// Bytes contains the actual packet
	Bytes []byte
	// Meta contains other information to help process the packet correctly, such as offsets for segmentation offloads
	// Fields in Meta should be as portable/platform-agnostic as possible.
	Meta struct{}
}

// PerSegment invokes fn once per segment of pkt.
// This is a stub implementation that does not actually support segmentation
func (t *TunPacket) PerSegment(fn func(seg []byte) error) error {
	return fn(t.Bytes)
}
