//go:build !linux || android || e2e_testing

package tio

import "fmt"

func protoFromGSOType(_ uint8) (GSOProto, error) {
	return 0, fmt.Errorf("GSO unsupported")
}

// SegmentSuperpacket invokes fn once per segment of pkt. On non-Linux
// builds (and Android/e2e_testing) this package does not provide a Queue
// implementation, so any caller that does construct a Packet here can only
// be operating on non-superpacket bytes and the stub forwards them
// directly. A non-zero GSO field is a programming error from the caller
// and returns an explicit error rather than silently misbehaving.
func SegmentSuperpacket(pkt Packet, fn func(seg []byte) error) error {
	if pkt.GSO.IsSuperpacket() {
		return fmt.Errorf("tio: GSO superpacket on platform without segmentation support")
	}
	return fn(pkt.Bytes)
}
