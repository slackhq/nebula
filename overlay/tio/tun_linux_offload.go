//go:build linux && !android
// +build linux,!android

package tio

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/slackhq/nebula/overlay/tio/virtio"
)

// protoFromGSOType maps a virtio_net_hdr gsoType to the GSOProto value the
// segment-time helpers use. Returns an error for GSO_NONE or any unknown
// value. The caller should only invoke this on a confirmed superpacket.
func protoFromGSOType(t uint8) (GSOProto, error) {
	switch t &^ unix.VIRTIO_NET_HDR_GSO_ECN {
	case unix.VIRTIO_NET_HDR_GSO_TCPV4, unix.VIRTIO_NET_HDR_GSO_TCPV6:
		return GSOProtoTCP, nil
	case unix.VIRTIO_NET_HDR_GSO_UDP_L4:
		return GSOProtoUDP, nil
	default:
		return 0, fmt.Errorf("unsupported virtio gso type: %d", t)
	}
}

// gsoTypeFromProto is the reverse of protoFromGSOType
func gsoTypeFromProto(proto GSOProto, ipVer uint8) uint8 {
	switch {
	case proto == GSOProtoUDP && (ipVer == 4 || ipVer == 6):
		return unix.VIRTIO_NET_HDR_GSO_UDP_L4
	case ipVer == 6:
		return unix.VIRTIO_NET_HDR_GSO_TCPV6
	case ipVer == 4:
		return unix.VIRTIO_NET_HDR_GSO_TCPV4
	default:
		return unix.VIRTIO_NET_HDR_GSO_NONE
	}
}

// SegmentSuperpacket invokes fn once per segment of pkt.
// For non-GSO pkts fn is called once with pkt.Bytes.
// For GSO/USO superpackets, fn is called once per segment with a slice of pkt.Bytes holding that segment's plaintext
// (a freshly-patched L3+L4 header sliced in front of the original payload chunk).
// This slicing is destructive: pkt is consumed by this call.
// Aborts and returns the first error from fn or from per-segment construction.
func SegmentSuperpacket(pkt Packet, fn func(seg []byte) error) error {
	if !pkt.GSO.IsSuperpacket() {
		return fn(pkt.Bytes)
	}
	switch pkt.GSO.Proto {
	case GSOProtoTCP:
		return virtio.SegmentTCP(pkt.Bytes, pkt.GSO.HdrLen, pkt.GSO.CsumStart, pkt.GSO.Size, fn)
	case GSOProtoUDP:
		return virtio.SegmentUDP(pkt.Bytes, pkt.GSO.HdrLen, pkt.GSO.CsumStart, pkt.GSO.Size, fn)
	default:
		return fmt.Errorf("unsupported gso proto: %d", pkt.GSO.Proto)
	}
}
