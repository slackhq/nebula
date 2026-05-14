//go:build !linux
// +build !linux

package wire

// PerSegment invokes fn once per segment of pkt.
// This is a stub implementation that does not actually support segmentation
func (t *TunPacket) PerSegment(fn func(seg []byte) error) error {
	return fn(t.Bytes)
}
