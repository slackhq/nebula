//go:build !linux || android

package tio

import "fmt"

func protoFromGSOType(_ uint8) (GSOProto, error) {
	return 0, fmt.Errorf("GSO unsupported")
}

func SegmentSuperpacket(pkt Packet, fn func(seg []byte) error) error {
	if pkt.GSO.IsSuperpacket() {
		return fmt.Errorf("tio: GSO superpacket on platform without segmentation support")
	}
	return fn(pkt.Bytes)
}
