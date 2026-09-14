package iputil

import (
	"encoding/binary"

	"github.com/slackhq/nebula/overlay/checksum"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const udpHeaderLen = 8

// SetTransportChecksum recomputes the TCP or UDP checksum of an IPv4 or IPv6
// packet in place.
//
// A kernel that offloads checksums to the NIC hands a packet to a tun with the
// transport checksum unfinished: only the pseudo-header sum is in the field and
// the rest is left for hardware that a tun does not have. A packet written
// straight back to that tun is dropped on re-entry unless the checksum is
// completed first. ICMP is left alone; it arrived complete on the kernels this
// was measured against.
//
// So is any packet whose transport header cannot be located: fragments, unknown
// extension headers and truncated packets. An IPv6 fragment header is declined
// even when it carries the whole datagram (RFC 6946 atomic fragment), because
// the walk reports only that a fragment header was present.
func SetTransportChecksum(packet []byte) {
	if len(packet) < 1 {
		return
	}
	switch int(packet[0] >> 4) {
	case ipv4.Version:
		setTransportChecksum4(packet)
	case ipv6.Version:
		setTransportChecksum6(packet)
	}
}

func setTransportChecksum4(packet []byte) {
	if len(packet) < ipv4.HeaderLen {
		return
	}
	ihl := int(packet[0]&0x0f) << 2
	end := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < ipv4.HeaderLen || end < ihl || end > len(packet) {
		return
	}
	// The checksum covers the whole datagram, which a fragment (MF set or a
	// non-zero offset) does not carry.
	if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return
	}

	transport, ok := transportExtent(packet[ihl:end], packet[9])
	if !ok {
		return
	}
	csum := ipv4PseudoheaderChecksum(packet[12:16], packet[16:20], uint32(packet[9]), uint32(len(transport)))
	writeTransportChecksum(transport, packet[9], csum)
}

func setTransportChecksum6(packet []byte) {
	if len(packet) < ipv6.HeaderLen {
		return
	}
	end := ipv6.HeaderLen + int(binary.BigEndian.Uint16(packet[4:6]))
	if end > len(packet) {
		return
	}

	// The checksum covers the whole datagram, which a fragment does not carry.
	// An unknown extension header hides where the transport header starts. A
	// chain longer than the walk's budget ends it early, at an offset that was
	// never checked against the packet.
	proto, offset, _, anyFragment, err := IPv6FindUpperProtocol(packet[:end])
	if err != nil || anyFragment || offset >= end {
		return
	}

	transport, ok := transportExtent(packet[offset:end], proto)
	if !ok {
		return
	}
	csum := ipv6PseudoheaderChecksum(packet[8:24], packet[24:40], uint32(proto), uint32(len(transport)))
	writeTransportChecksum(transport, proto, csum)
}

// transportExtent narrows a segment to the length its own header declares. UDP
// carries a Length field, and RFC 768 and RFC 8200 section 8.1 both make that
// field, not the IP payload extent, the length the pseudo-header counts and the
// checksum covers; a datagram padded out to a link's minimum frame is the usual
// way the two differ. TCP has no such field, so its segment runs to the end of
// the IP payload. A Length that overruns the bytes IP delivered describes a
// datagram that is not there.
func transportExtent(transport []byte, proto uint8) ([]byte, bool) {
	if proto != IPProtocolUDP {
		return transport, true
	}
	if len(transport) < udpHeaderLen {
		return nil, false
	}
	ulen := int(binary.BigEndian.Uint16(transport[4:6]))
	if ulen < udpHeaderLen || ulen > len(transport) {
		return nil, false
	}
	return transport[:ulen], true
}

// writeTransportChecksum stores the checksum of transport, taken over the
// pseudo-header sum csum, in the header's checksum field. A UDP checksum that
// computes to zero goes on the wire as 0xffff: zero means no checksum was
// computed (RFC 768), and over IPv6 the checksum is mandatory (RFC 8200
// section 8.1).
func writeTransportChecksum(transport []byte, proto uint8, csum uint32) {
	var at, minLen int
	switch proto {
	case IPProtocolTCP:
		at, minLen = 16, 20
	case IPProtocolUDP:
		at, minLen = 6, udpHeaderLen
	default:
		return
	}
	if len(transport) < minLen {
		return
	}

	transport[at], transport[at+1] = 0, 0
	sum := ^checksum.Checksum(transport, fold(csum))
	if sum == 0 && proto == IPProtocolUDP {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(transport[at:], sum)
}

// fold reduces a pseudo-header sum to the 16 bit seed Checksum takes. Carrying
// the high half back into the low half is what keeps the reduction lossless, so
// the seed sums exactly as the wider value would; 0xffff is its fixed point.
// Every term of that sum comes from a 16 bit field, so it stays far below the
// width at which the accumulator would wrap.
func fold(csum uint32) uint16 {
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return uint16(csum)
}
