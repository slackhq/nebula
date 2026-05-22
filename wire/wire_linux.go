package wire

import (
	"fmt"

	"github.com/slackhq/nebula/overlay/tio/virtio"
)

// PerSegment invokes fn once per segment of t. For non-GSO packets fn is
// called once with t.Bytes (no segmentation, no copy). For GSO/USO
// superpackets fn is called once per segment with a slice of t.Bytes
// holding that segment's plaintext (a freshly-patched L3+L4 header sliced
// in front of the original payload chunk). The slide is destructive: t is
// consumed by this call and its bytes are in an undefined state when
// PerSegment returns. Callers must not retain t or any earlier seg slice
// past fn's return for that segment. Aborts and returns the first error
// from fn or from per-segment construction.
func (t *TunPacket) PerSegment(fn func(seg []byte) error) error {
	if !t.Meta.IsSuperpacket() {
		return fn(t.Bytes)
	}
	switch t.Meta.Proto {
	case GSOProtoTCP:
		return virtio.SegmentTCP(t.Bytes, t.Meta.HdrLen, t.Meta.CsumStart, t.Meta.Size, fn)
	case GSOProtoUDP:
		return virtio.SegmentUDP(t.Bytes, t.Meta.HdrLen, t.Meta.CsumStart, t.Meta.Size, fn)
	default:
		return fmt.Errorf("unsupported gso proto: %d", t.Meta.Proto)
	}
}
