package iputil

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv6"
)

// serialize builds a packet with gopacket, whose checksums are computed
// independently of this package.
func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...))
	return append([]byte(nil), buf.Bytes()...)
}

// withExtensionHeader inserts an 8 byte IPv6 extension header of the given
// type between the IPv6 header and its payload. The transport checksum does not
// change: the pseudo-header counts only upper-layer bytes.
func withExtensionHeader(pkt []byte, typ layers.IPProtocol, hdr [8]byte) []byte {
	hdr[0] = pkt[6]
	out := make([]byte, 0, len(pkt)+8)
	out = append(out, pkt[:40]...)
	out = append(out, hdr[:]...)
	out = append(out, pkt[40:]...)
	out[6] = byte(typ)
	binary.BigEndian.PutUint16(out[4:6], binary.BigEndian.Uint16(pkt[4:6])+8)
	return out
}

// truncate copies the first n bytes into a buffer of exactly that capacity, so
// a read past the length panics instead of quietly succeeding.
func truncate(pkt []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, pkt)
	return out
}

// extChain builds an IPv6 packet fronted by n Destination Options headers. Each
// points at another one, so the walk spends its whole budget without reaching a
// transport header. lastExtLen inflates the final header's declared length,
// which is how the walk ends up past the end of the packet.
func extChain(n int, lastExtLen byte) []byte {
	pkt := make([]byte, ipv6.HeaderLen)
	pkt[0], pkt[6], pkt[7] = 0x60, 60, 64
	for i := range n {
		h := make([]byte, 8)
		h[0] = 60
		if i == n-1 {
			h[1] = lastExtLen
		}
		pkt = append(pkt, h...)
	}
	pkt = append(pkt, make([]byte, 20)...)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)-ipv6.HeaderLen))
	return pkt
}

func TestSetTransportChecksum(t *testing.T) {
	// Source and destination differ so that a pseudo-header built from the wrong
	// one, or from the two swapped, does not land on the same checksum anyway.
	v4 := func(proto layers.IPProtocol) *layers.IPv4 {
		return &layers.IPv4{Version: 4, TTL: 64, Id: 0x1234, Protocol: proto, SrcIP: net.IPv4(192, 0, 2, 1).To4(), DstIP: net.IPv4(198, 51, 100, 2).To4()}
	}
	v6 := func(proto layers.IPProtocol) *layers.IPv6 {
		return &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: proto, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8:1::2")}
	}
	tcp := func(ip gopacket.NetworkLayer) *layers.TCP {
		l := &layers.TCP{SrcPort: 49152, DstPort: 443, SYN: true, Window: 65535}
		require.NoError(t, l.SetNetworkLayerForChecksum(ip))
		return l
	}
	udp := func(ip gopacket.NetworkLayer) *layers.UDP {
		l := &layers.UDP{SrcPort: 49152, DstPort: 53}
		require.NoError(t, l.SetNetworkLayerForChecksum(ip))
		return l
	}
	payload := gopacket.Payload("self")
	nop := layers.IPv4Option{OptionType: 1, OptionLength: 1}

	ip4tcp := v4(layers.IPProtocolTCP)
	ip4opts := v4(layers.IPProtocolTCP)
	ip4opts.Options = []layers.IPv4Option{nop, nop, nop, nop}
	ip4udp := v4(layers.IPProtocolUDP)
	ip6tcp := v6(layers.IPProtocolTCP)
	ip6udp := v6(layers.IPProtocolUDP)
	hopByHop := [8]byte{0, 0, 1, 4} // next header, length 0, PadN of 4

	// Bytes past the length the IP header declares are not part of the
	// datagram and must not be summed.
	trailing4 := append(serialize(t, ip4tcp, tcp(ip4tcp), payload), []byte("trailing")...)
	trailing6 := append(serialize(t, ip6tcp, tcp(ip6tcp), payload), []byte("trailing")...)

	// A datagram padded out past the length UDP declares: the pseudo-header
	// counts the UDP Length field, so the checksum is the unpadded one.
	padded4 := append(serialize(t, ip4udp, udp(ip4udp), payload), []byte("pad!")...)
	binary.BigEndian.PutUint16(padded4[2:4], uint16(len(padded4)))
	padded6 := append(serialize(t, ip6udp, udp(ip6udp), payload), []byte("pad!")...)
	binary.BigEndian.PutUint16(padded6[4:6], uint16(len(padded6)-ipv6.HeaderLen))

	// Corrupting the checksum and asking for it back must yield gopacket's
	// packet, byte for byte.
	recomputed := []struct {
		name  string
		pkt   []byte
		cksum int
	}{
		{"v4 tcp", serialize(t, ip4tcp, tcp(ip4tcp), payload), 20 + 16},
		{"v4 tcp with ip options", serialize(t, ip4opts, tcp(ip4opts), payload), 24 + 16},
		{"v4 udp", serialize(t, ip4udp, udp(ip4udp), payload), 20 + 6},
		{"v4 tcp header only", serialize(t, ip4tcp, tcp(ip4tcp)), 20 + 16},
		{"v4 udp header only", serialize(t, ip4udp, udp(ip4udp)), 20 + 6},
		{"v6 tcp", serialize(t, ip6tcp, tcp(ip6tcp), payload), 40 + 16},
		{"v6 udp", serialize(t, ip6udp, udp(ip6udp), payload), 40 + 6},
		{"v6 udp header only", serialize(t, ip6udp, udp(ip6udp)), 40 + 6},
		{"v6 tcp behind hop-by-hop", withExtensionHeader(serialize(t, ip6tcp, tcp(ip6tcp), payload), layers.IPProtocolIPv6HopByHop, hopByHop), 48 + 16},
		{"v4 tcp with bytes past the total length", trailing4, 20 + 16},
		{"v6 tcp with bytes past the payload length", trailing6, 40 + 16},
		{"v4 udp padded past its declared length", padded4, 20 + 6},
		{"v6 udp padded past its declared length", padded6, 40 + 6},
	}
	for _, tt := range recomputed {
		t.Run(tt.name, func(t *testing.T) {
			got := append([]byte(nil), tt.pkt...)
			binary.BigEndian.PutUint16(got[tt.cksum:], 0x1234)
			require.NotEqual(t, tt.pkt, got)
			SetTransportChecksum(got)
			assert.Equal(t, tt.pkt, got)
		})
	}

	ip4frag := v4(layers.IPProtocolTCP)
	ip4frag.Flags = layers.IPv4MoreFragments
	ip4later := v4(layers.IPProtocolTCP)
	ip4later.FragOffset = 1
	ip4icmp := v4(layers.IPProtocolICMPv4)

	badIHL := serialize(t, ip4tcp, tcp(ip4tcp), payload)
	badIHL[0] = 0x44 // header length 16, shorter than an ipv4 header
	shortTotalLen := serialize(t, ip4tcp, tcp(ip4tcp), payload)
	binary.BigEndian.PutUint16(shortTotalLen[2:4], 10) // shorter than the header it introduces
	cutTCP := serialize(t, ip4tcp, tcp(ip4tcp), payload)
	binary.BigEndian.PutUint16(cutTCP[2:4], 20+19) // one byte short of a tcp header
	cutTCP = truncate(cutTCP, 20+19)
	cutUDP := serialize(t, ip4udp, udp(ip4udp), payload)
	binary.BigEndian.PutUint16(cutUDP[2:4], 20+7) // one byte short of a udp header
	cutUDP = truncate(cutUDP, 20+7)
	// Two bytes short, so a transport header survives whole and the minimum
	// length check cannot stand in for the bounds check.
	cutV6 := truncate(serialize(t, ip6tcp, tcp(ip6tcp), payload), 62)
	fragment := [8]byte{0, 0, 0, 1, 0, 0, 0, 1} // next header, reserved, offset 0 with M set, id
	overrun4 := serialize(t, ip4udp, udp(ip4udp), payload)
	binary.BigEndian.PutUint16(overrun4[24:26], uint16(len(overrun4)-20+1)) // one byte past what ip delivered
	overrun6 := serialize(t, ip6udp, udp(ip6udp), payload)
	binary.BigEndian.PutUint16(overrun6[44:46], uint16(len(overrun6)-ipv6.HeaderLen+1))
	shortUDPLen := serialize(t, ip4udp, udp(ip4udp), payload)
	binary.BigEndian.PutUint16(shortUDPLen[24:26], 7) // shorter than the header it counts

	// Where the checksum cannot be completed the packet is left as it came.
	untouched := []struct {
		name  string
		pkt   []byte
		cksum int
	}{
		{"v4 first fragment", serialize(t, ip4frag, tcp(ip4frag), payload), 20 + 16},
		{"v4 later fragment", serialize(t, ip4later, tcp(ip4later), payload), 20 + 16},
		{"v4 icmp", serialize(t, ip4icmp, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 1, Seq: 1}, payload), 20 + 2},
		{"v4 header length below the minimum", badIHL, 20 + 16},
		{"v4 total length below the header length", shortTotalLen, 20 + 16},
		{"v4 truncated below its total length", truncate(serialize(t, ip4tcp, tcp(ip4tcp), payload), 30), -1},
		{"v4 tcp header cut short", cutTCP, 20 + 16},
		{"v4 udp header cut short", cutUDP, -1},
		{"v6 fragment", withExtensionHeader(serialize(t, ip6tcp, tcp(ip6tcp), payload), layers.IPProtocolIPv6Fragment, fragment), 48 + 16},
		{"v6 truncated below its payload length", truncate(serialize(t, ip6tcp, tcp(ip6tcp), payload), 50), -1},
		{"v6 truncated with a whole transport header still present", cutV6, 40 + 16},
		{"v6 extension header chain longer than the walk", extChain(9, 0), 112 + 16},
		{"v6 extension header chain running past the packet", extChain(8, 255), 104 + 16},
		{"v4 udp length past the end of the datagram", overrun4, 20 + 6},
		{"v6 udp length past the end of the datagram", overrun6, 40 + 6},
		{"v4 udp length below a udp header", shortUDPLen, 20 + 6},
	}
	for _, tt := range untouched {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cksum >= 0 {
				binary.BigEndian.PutUint16(tt.pkt[tt.cksum:], 0x1234)
			}
			want := append([]byte(nil), tt.pkt...)
			SetTransportChecksum(tt.pkt)
			assert.Equal(t, want, tt.pkt)
		})
	}

	t.Run("too short to carry a header", func(t *testing.T) {
		for _, pkt := range [][]byte{nil, {}, {0x45}, {0x60}} {
			assert.NotPanics(t, func() { SetTransportChecksum(pkt) })
		}
	})

	t.Run("tcp checksum of zero goes out as zero", func(t *testing.T) {
		pkt := serialize(t, ip4tcp, tcp(ip4tcp), gopacket.Payload{0, 0})
		c := binary.BigEndian.Uint16(pkt[36:38])
		require.NotZero(t, c)
		// Only udp reserves zero to mean "not computed", so tcp keeps it.
		binary.BigEndian.PutUint16(pkt[40:42], c)
		SetTransportChecksum(pkt)
		assert.Zero(t, binary.BigEndian.Uint16(pkt[36:38]))
	})

	t.Run("udp checksum of zero goes out as 0xffff", func(t *testing.T) {
		pkt := serialize(t, ip4udp, udp(ip4udp), gopacket.Payload{0, 0})
		c := binary.BigEndian.Uint16(pkt[26:28])
		require.NotZero(t, c)
		// The one's complement sum is now 0xffff - c; adding c to the payload
		// makes it 0xffff, whose complement is zero.
		binary.BigEndian.PutUint16(pkt[28:30], c)
		SetTransportChecksum(pkt)
		assert.Equal(t, uint16(0xffff), binary.BigEndian.Uint16(pkt[26:28]))
	})
}

func TestFold(t *testing.T) {
	// 0xffff is the fold's fixed point, so a loop bound one notch tight never
	// terminates on it.
	for _, tt := range []struct {
		in   uint32
		want uint16
	}{
		{0, 0},
		{0xffff, 0xffff},
		{0x10000, 1},
		{0x1fffe, 0xffff},
		{0xffffffff, 0xffff},
	} {
		assert.Equal(t, tt.want, fold(tt.in))
	}
}
