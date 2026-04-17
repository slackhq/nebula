package tio

import "fmt"

// SegmentSuperpacket invokes fn once per segment of pkt.
// This is a stub implementation that does not actually support segmentation
func SegmentSuperpacket(pkt Packet, fn func(seg []byte) error) error {
	if pkt.GSO.IsSuperpacket() {
		return fmt.Errorf("tio: GSO superpacket on platform without segmentation support")
	}
	return fn(pkt.Bytes)
}
