//go:build linux && !android && !e2e_testing
// +build linux,!android,!e2e_testing

package tio

import (
	"fmt"

	"github.com/slackhq/nebula/wire"
	"golang.org/x/sys/unix"
)

// protoFromGSOType maps a virtio_net_hdr GSOType to the GSOProto value the
// segment-time helpers use. Returns an error for GSO_NONE or any unknown
// value — the caller should only invoke this on a confirmed superpacket.
func protoFromGSOType(t uint8) (wire.GSOProto, error) {
	switch t {
	case unix.VIRTIO_NET_HDR_GSO_TCPV4, unix.VIRTIO_NET_HDR_GSO_TCPV6:
		return wire.GSOProtoTCP, nil
	case unix.VIRTIO_NET_HDR_GSO_UDP_L4:
		return wire.GSOProtoUDP, nil
	default:
		return 0, fmt.Errorf("unsupported virtio gso type: %d", t)
	}
}
