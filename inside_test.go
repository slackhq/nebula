package nebula

import (
	"encoding/binary"
	"io"
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
)

// capturingTun is a tio.Queue that records what is written to it. A queue that
// discards writes is indistinguishable from a packet that was never forwarded.
type capturingTun struct {
	writes [][]byte
}

func (c *capturingTun) Read() ([]tio.Packet, error) { return nil, io.EOF }
func (c *capturingTun) Close() error                { return nil }

func (c *capturingTun) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func newSelfForwardInterface(myAddrs ...netip.Addr) (*Interface, *capturingTun) {
	vpnAddrs := &bart.Lite{}
	for _, a := range myAddrs {
		vpnAddrs.Insert(netip.PrefixFrom(a, a.BitLen()))
	}

	tun := &capturingTun{}
	return &Interface{
		l:                     test.NewLogger(),
		myVpnAddrsTable:       vpnAddrs,
		myBroadcastAddrsTable: &bart.Lite{},
		queues:                []tio.Queue{tun},
	}, tun
}

func consumeInside(f *Interface, packet []byte) {
	f.consumeInsidePacket(tio.Packet{Bytes: packet}, &firewall.ParsedPacket{}, make([]byte, 12), nil, make([]byte, mtu), 0, nil)
}

// l4Proto describes one upper-layer header for these tests: its IP next-header
// value, where its checksum field sits within the header, and how to build a
// minimal instance of it.
type l4Proto struct {
	name    string
	nextHdr uint8
	cksumAt int
	build   func() []byte
}

var (
	tcpSyn = l4Proto{"tcp", iputil.IPProtocolTCP, 16, func() []byte {
		h := make([]byte, 20)
		binary.BigEndian.PutUint16(h[0:2], 49152)
		binary.BigEndian.PutUint16(h[2:4], 443)
		binary.BigEndian.PutUint32(h[4:8], 0x11223344) // sequence
		h[12] = 5 << 4                                 // data offset, no options
		h[13] = 0x02                                   // SYN
		binary.BigEndian.PutUint16(h[14:16], 65535)    // window
		return h
	}}

	udpDatagram = l4Proto{"udp", iputil.IPProtocolUDP, 6, func() []byte {
		h := make([]byte, 8+4)
		binary.BigEndian.PutUint16(h[0:2], 49152)
		binary.BigEndian.PutUint16(h[2:4], 53)
		binary.BigEndian.PutUint16(h[4:6], uint16(len(h)))
		copy(h[8:], "ping")
		return h
	}}

	icmpEcho   = l4Proto{"icmp", iputil.IPProtocolICMP, 2, func() []byte { return echoRequest(8) }}
	icmpv6Echo = l4Proto{"icmpv6", iputil.IPProtocolICMPv6, 2, func() []byte { return echoRequest(128) }}
)

// echoRequest builds an echo request body. The type differs between ICMP and
// ICMPv6, the rest of the header does not.
func echoRequest(typ uint8) []byte {
	h := make([]byte, 8)
	h[0] = typ
	binary.BigEndian.PutUint16(h[4:6], 0xbeef) // identifier
	binary.BigEndian.PutUint16(h[6:8], 1)      // sequence
	return h
}

func buildIPv6(src, dst netip.Addr, p l4Proto) []byte {
	l4 := p.build()
	pkt := make([]byte, ipv6HeaderLen+len(l4))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(l4)))
	pkt[6] = p.nextHdr
	pkt[7] = 64
	copy(pkt[8:24], src.AsSlice())
	copy(pkt[24:40], dst.AsSlice())
	copy(pkt[ipv6HeaderLen:], l4)
	if l4 := pkt[ipv6HeaderLen:]; p.nextHdr == iputil.IPProtocolTCP || p.nextHdr == iputil.IPProtocolUDP {
		sum := ipv6PseudoheaderSum(src, dst, uint32(p.nextHdr), uint32(len(l4)))
		binary.BigEndian.PutUint16(l4[p.cksumAt:], ^fold(sumBytes(l4, sum)))
	}
	return pkt
}

func buildIPv4(src, dst netip.Addr, p l4Proto) []byte {
	l4 := p.build()
	pkt := make([]byte, ipv4HeaderLen+len(l4))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = p.nextHdr
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	copy(pkt[ipv4HeaderLen:], l4)
	if l4 := pkt[ipv4HeaderLen:]; p.nextHdr == iputil.IPProtocolTCP || p.nextHdr == iputil.IPProtocolUDP {
		sum := sumBytes(pkt[12:20], uint32(p.nextHdr)+uint32(len(l4)))
		binary.BigEndian.PutUint16(l4[p.cksumAt:], ^fold(sumBytes(l4, sum)))
	}
	return pkt
}

// ipv6PseudoheaderSum is the RFC 2460 section 8.1 pseudo-header sum: source,
// destination, a 32 bit upper-layer packet length and a 32 bit zero-padded next
// header. Kept local to the test so these assertions do not check nebula's
// checksum code against itself.
func ipv6PseudoheaderSum(src, dst netip.Addr, nextHeader, length uint32) uint32 {
	var csum uint32
	s, d := src.AsSlice(), dst.AsSlice()
	for i := 0; i < 16; i += 2 {
		csum += uint32(s[i])<<8 | uint32(s[i+1])
		csum += uint32(d[i])<<8 | uint32(d[i+1])
	}
	return csum + length + nextHeader
}

func sumBytes(b []byte, csum uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		csum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		csum += uint32(b[len(b)-1]) << 8
	}
	return csum
}

func fold(csum uint32) uint16 {
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return uint16(csum)
}

// l4ChecksumValid6 verifies an IPv6 upper-layer checksum the way a receiver
// does: the pseudo-header plus the whole upper-layer segment, checksum field
// included, folds to 0xffff. The next header field is the upper-layer protocol
// only while there are no extension headers, which is all this file builds.
func l4ChecksumValid6(pkt []byte) bool {
	src, _ := netip.AddrFromSlice(pkt[8:24])
	dst, _ := netip.AddrFromSlice(pkt[24:40])
	l4 := pkt[ipv6HeaderLen:]
	return fold(sumBytes(l4, ipv6PseudoheaderSum(src, dst, uint32(pkt[6]), uint32(len(l4))))) == 0xffff
}

// l4ChecksumValid4 is the IPv4 counterpart: the RFC 793/768 pseudo-header is
// source, destination, a zero byte, the protocol and the upper-layer length.
func l4ChecksumValid4(pkt []byte) bool {
	ihl := int(pkt[0]&0x0f) << 2
	l4 := pkt[ihl:]
	return fold(sumBytes(l4, sumBytes(pkt[12:20], uint32(pkt[9])+uint32(len(l4))))) == 0xffff
}

// TestConsumeInsidePacketSelfTraffic covers the self-addressed branch of
// consumeInsidePacket, taken where immediatelyForwardToSelf is set (see
// inside_bsd.go): the packet goes straight back to the tun, ahead of the
// firewall and the handshake.
func TestConsumeInsidePacketSelfTraffic(t *testing.T) {
	v4 := netip.MustParseAddr("100.100.1.42")
	v6 := netip.MustParseAddr("fd00::42")

	tests := []struct {
		name string
		addr netip.Addr
		pkt  []byte
	}{
		{"ipv4/tcp", v4, buildIPv4(v4, v4, tcpSyn)},
		{"ipv4/udp", v4, buildIPv4(v4, v4, udpDatagram)},
		{"ipv4/icmp", v4, buildIPv4(v4, v4, icmpEcho)},
		{"ipv6/tcp", v6, buildIPv6(v6, v6, tcpSyn)},
		{"ipv6/udp", v6, buildIPv6(v6, v6, udpDatagram)},
		{"ipv6/icmpv6", v6, buildIPv6(v6, v6, icmpv6Echo)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, tun := newSelfForwardInterface(tt.addr)
			// consumeInsidePacket writes through the slice it is handed, so a
			// packet that arrived with a valid checksum must come back out of
			// bytes taken before the call, unchanged.
			want := append([]byte(nil), tt.pkt...)
			consumeInside(f, tt.pkt)

			if immediatelyForwardToSelf {
				require.Len(t, tun.writes, 1)
				assert.Equal(t, want, tun.writes[0])
			} else {
				assert.Empty(t, tun.writes, "self traffic reaches the tun over loopback here and must be dropped")
			}
		})
	}
}

// TestConsumeInsidePacketSelfTrafficChecksum shows that the self-forward
// returns the bytes it was handed, so a packet that arrived with a wrong
// upper-layer checksum is written back with that same wrong checksum and the
// kernel drops it on re-entry.
//
// This is how a macOS host loses TCP and UDP to its own IPv6 overlay address:
// the kernel writes only the pseudo-header sum into the checksum field and
// defers completion to hardware offload, state that does not survive the
// crossing into userspace. Which kernels do this, for which protocols and IP
// versions, is a property of the kernel and belongs to a test against a live
// one; here the checksum is simply wrong, and the forward must make it right.
func TestConsumeInsidePacketSelfTrafficChecksum(t *testing.T) {
	if !immediatelyForwardToSelf {
		t.Skip("self traffic never reaches the tun on this platform")
	}
	versions := []struct {
		name  string
		addr  netip.Addr
		build func(src, dst netip.Addr, p l4Proto) []byte
		l4At  int
		valid func(pkt []byte) bool
	}{
		{"v4", netip.MustParseAddr("100.100.1.42"), buildIPv4, ipv4HeaderLen, l4ChecksumValid4},
		{"v6", netip.MustParseAddr("fd00::42"), buildIPv6, ipv6HeaderLen, l4ChecksumValid6},
	}
	for _, v := range versions {
		for _, p := range []l4Proto{tcpSyn, udpDatagram} {
			t.Run(v.name+"/"+p.name, func(t *testing.T) {
				pkt := v.build(v.addr, v.addr, p)
				binary.BigEndian.PutUint16(pkt[v.l4At+p.cksumAt:], 0x1234)
				require.False(t, v.valid(pkt), "the packet under test must start with a wrong checksum")
				f, tun := newSelfForwardInterface(v.addr)
				consumeInside(f, pkt)
				require.Len(t, tun.writes, 1)
				assert.True(t, v.valid(tun.writes[0]),
					"a forwarded %s packet must carry a valid checksum, got 0x%04x",
					p.name, binary.BigEndian.Uint16(tun.writes[0][v.l4At+p.cksumAt:]))
			})
		}
	}
}
