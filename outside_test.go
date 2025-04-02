package nebula

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/slackhq/nebula/firewall"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

func Test_newPacket(t *testing.T) {
	p := &firewall.Packet{}

	// length fails
	err := newPacket([]byte{}, true, p)
	require.ErrorIs(t, err, ErrPacketTooShort)

	err = newPacket([]byte{0x40}, true, p)
	require.ErrorIs(t, err, ErrIPv4PacketTooShort)

	err = newPacket([]byte{0x60}, true, p)
	require.ErrorIs(t, err, ErrIPv6PacketTooShort)

	// length fail with ip options
	h := ipv4.Header{
		Version: 1,
		Len:     100,
		Src:     net.IPv4(10, 0, 0, 1),
		Dst:     net.IPv4(10, 0, 0, 2),
		Options: []byte{0, 1, 0, 2},
	}

	b, _ := h.Marshal()
	err = newPacket(b, true, p)
	require.ErrorIs(t, err, ErrIPv4InvalidHeaderLength)

	// not an ipv4 packet
	err = newPacket([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true, p)
	require.ErrorIs(t, err, ErrUnknownIPVersion)

	// invalid ihl
	err = newPacket([]byte{4<<4 | (8 >> 2 & 0x0f), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true, p)
	require.ErrorIs(t, err, ErrIPv4InvalidHeaderLength)

	// account for variable ip header length - incoming
	h = ipv4.Header{
		Version:  1,
		Len:      100,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Options:  []byte{0, 1, 0, 2},
		Protocol: firewall.ProtoTCP,
	}

	b, _ = h.Marshal()
	b = append(b, []byte{0, 3, 0, 4}...)
	err = newPacket(b, true, p)

	require.NoError(t, err)
	assert.Equal(t, uint8(firewall.ProtoTCP), p.Protocol)
	assert.Equal(t, netip.MustParseAddr("10.0.0.2"), p.LocalAddr)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), p.RemoteAddr)
	assert.Equal(t, uint16(3), p.RemotePort)
	assert.Equal(t, uint16(4), p.LocalPort)
	assert.False(t, p.Fragment)

	// account for variable ip header length - outgoing
	h = ipv4.Header{
		Version:  1,
		Protocol: 2,
		Len:      100,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Options:  []byte{0, 1, 0, 2},
	}

	b, _ = h.Marshal()
	b = append(b, []byte{0, 5, 0, 6}...)
	err = newPacket(b, false, p)

	require.NoError(t, err)
	assert.Equal(t, uint8(2), p.Protocol)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), p.LocalAddr)
	assert.Equal(t, netip.MustParseAddr("10.0.0.2"), p.RemoteAddr)
	assert.Equal(t, uint16(6), p.RemotePort)
	assert.Equal(t, uint16(5), p.LocalPort)
	assert.False(t, p.Fragment)
}

func Test_newPacket_v6(t *testing.T) {
	p := &firewall.Packet{}

	// invalid ipv6
	ip := layers.IPv6{
		Version:  6,
		HopLimit: 128,
		SrcIP:    net.IPv6linklocalallrouters,
		DstIP:    net.IPv6linklocalallnodes,
	}

	buffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		ComputeChecksums: false,
		FixLengths:       false,
	}
	err := gopacket.SerializeLayers(buffer, opt, &ip)
	require.NoError(t, err)

	err = newPacket(buffer.Bytes(), true, p)
	require.ErrorIs(t, err, ErrIPv6CouldNotFindPayload)

	// A good ICMP packet
	ip = layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   128,
		SrcIP:      net.IPv6linklocalallrouters,
		DstIP:      net.IPv6linklocalallnodes,
	}

	icmp := layers.ICMPv6{}

	buffer.Clear()
	err = gopacket.SerializeLayers(buffer, opt, &ip, &icmp)
	if err != nil {
		panic(err)
	}

	err = newPacket(buffer.Bytes(), true, p)
	require.NoError(t, err)
	assert.Equal(t, uint8(layers.IPProtocolICMPv6), p.Protocol)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.RemoteAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.LocalAddr)
	assert.Equal(t, uint16(0), p.RemotePort)
	assert.Equal(t, uint16(0), p.LocalPort)
	assert.False(t, p.Fragment)

	// A good ESP packet
	b := buffer.Bytes()
	b[6] = byte(layers.IPProtocolESP)
	err = newPacket(b, true, p)
	require.NoError(t, err)
	assert.Equal(t, uint8(layers.IPProtocolESP), p.Protocol)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.RemoteAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.LocalAddr)
	assert.Equal(t, uint16(0), p.RemotePort)
	assert.Equal(t, uint16(0), p.LocalPort)
	assert.False(t, p.Fragment)

	// A good None packet
	b = buffer.Bytes()
	b[6] = byte(layers.IPProtocolNoNextHeader)
	err = newPacket(b, true, p)
	require.NoError(t, err)
	assert.Equal(t, uint8(layers.IPProtocolNoNextHeader), p.Protocol)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.RemoteAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.LocalAddr)
	assert.Equal(t, uint16(0), p.RemotePort)
	assert.Equal(t, uint16(0), p.LocalPort)
	assert.False(t, p.Fragment)

	// An unknown protocol packet
	b = buffer.Bytes()
	b[6] = 255 // 255 is a reserved protocol number
	err = newPacket(b, true, p)
	require.ErrorIs(t, err, ErrIPv6CouldNotFindPayload)

	// A good UDP packet
	ip = layers.IPv6{
		Version:    6,
		NextHeader: firewall.ProtoUDP,
		HopLimit:   128,
		SrcIP:      net.IPv6linklocalallrouters,
		DstIP:      net.IPv6linklocalallnodes,
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(36123),
		DstPort: layers.UDPPort(22),
	}
	err = udp.SetNetworkLayerForChecksum(&ip)
	require.NoError(t, err)

	buffer.Clear()
	err = gopacket.SerializeLayers(buffer, opt, &ip, &udp, gopacket.Payload([]byte{0xde, 0xad, 0xbe, 0xef}))
	if err != nil {
		panic(err)
	}
	b = buffer.Bytes()

	// incoming
	err = newPacket(b, true, p)
	require.NoError(t, err)
	assert.Equal(t, uint8(firewall.ProtoUDP), p.Protocol)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.RemoteAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.LocalAddr)
	assert.Equal(t, uint16(36123), p.RemotePort)
	assert.Equal(t, uint16(22), p.LocalPort)
	assert.False(t, p.Fragment)

	// outgoing
	err = newPacket(b, false, p)
	require.NoError(t, err)
	assert.Equal(t, uint8(firewall.ProtoUDP), p.Protocol)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.LocalAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.RemoteAddr)
	assert.Equal(t, uint16(36123), p.LocalPort)
	assert.Equal(t, uint16(22), p.RemotePort)
	assert.False(t, p.Fragment)

	// Too short UDP packet
	err = newPacket(b[:len(b)-10], false, p) // pull off the last 10 bytes
	require.ErrorIs(t, err, ErrIPv6PacketTooShort)

	// A good TCP packet
	b[6] = byte(layers.IPProtocolTCP)

	// incoming
	err = newPacket(b, true, p)
	require.NoError(t, err)
	assert.Equal(t, uint8(firewall.ProtoTCP), p.Protocol)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.RemoteAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.LocalAddr)
	assert.Equal(t, uint16(36123), p.RemotePort)
	assert.Equal(t, uint16(22), p.LocalPort)
	assert.False(t, p.Fragment)

	// outgoing
	err = newPacket(b, false, p)
	require.NoError(t, err)
	assert.Equal(t, uint8(firewall.ProtoTCP), p.Protocol)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.LocalAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.RemoteAddr)
	assert.Equal(t, uint16(36123), p.LocalPort)
	assert.Equal(t, uint16(22), p.RemotePort)
	assert.False(t, p.Fragment)

	// Too short TCP packet
	err = newPacket(b[:len(b)-10], false, p) // pull off the last 10 bytes
	require.ErrorIs(t, err, ErrIPv6PacketTooShort)

	// A good UDP packet with an AH header
	ip = layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolAH,
		HopLimit:   128,
		SrcIP:      net.IPv6linklocalallrouters,
		DstIP:      net.IPv6linklocalallnodes,
	}

	ah := layers.IPSecAH{
		AuthenticationData: []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef},
	}
	ah.NextHeader = layers.IPProtocolUDP

	udpHeader := []byte{
		0x8d, 0x1b, // Source port 36123
		0x00, 0x16, // Destination port 22
		0x00, 0x00, // Length
		0x00, 0x00, // Checksum
	}

	buffer.Clear()
	err = ip.SerializeTo(buffer, opt)
	if err != nil {
		panic(err)
	}

	b = buffer.Bytes()
	ahb := serializeAH(&ah)
	b = append(b, ahb...)
	b = append(b, udpHeader...)

	err = newPacket(b, true, p)
	require.NoError(t, err)
	assert.Equal(t, uint8(firewall.ProtoUDP), p.Protocol)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.RemoteAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.LocalAddr)
	assert.Equal(t, uint16(36123), p.RemotePort)
	assert.Equal(t, uint16(22), p.LocalPort)
	assert.False(t, p.Fragment)

	// Invalid AH header
	b = buffer.Bytes()
	err = newPacket(b, true, p)
	require.ErrorIs(t, err, ErrIPv6CouldNotFindPayload)
}

func Test_newPacket_ipv6Fragment(t *testing.T) {
	p := &firewall.Packet{}

	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Fragment,
		HopLimit:   64,
		SrcIP:      net.IPv6linklocalallrouters,
		DstIP:      net.IPv6linklocalallnodes,
	}

	// First fragment
	fragHeader1 := []byte{
		uint8(layers.IPProtocolUDP), // Next Header (UDP)
		0x00,                        // Reserved
		0x00,                        // Fragment Offset high byte (0)
		0x01,                        // Fragment Offset low byte & flags (M=1)
		0x00, 0x00, 0x00, 0x01,      // Identification
	}

	udpHeader := []byte{
		0x8d, 0x1b, // Source port 36123
		0x00, 0x16, // Destination port 22
		0x00, 0x00, // Length
		0x00, 0x00, // Checksum
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := ip.SerializeTo(buffer, opts)
	if err != nil {
		t.Fatal(err)
	}

	firstFrag := buffer.Bytes()
	firstFrag = append(firstFrag, fragHeader1...)
	firstFrag = append(firstFrag, udpHeader...)
	firstFrag = append(firstFrag, []byte{0xde, 0xad, 0xbe, 0xef}...)

	// Test first fragment incoming
	err = newPacket(firstFrag, true, p)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.RemoteAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.LocalAddr)
	assert.Equal(t, uint8(layers.IPProtocolUDP), p.Protocol)
	assert.Equal(t, uint16(36123), p.RemotePort)
	assert.Equal(t, uint16(22), p.LocalPort)
	assert.False(t, p.Fragment)

	// Test first fragment outgoing
	err = newPacket(firstFrag, false, p)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.LocalAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.RemoteAddr)
	assert.Equal(t, uint8(layers.IPProtocolUDP), p.Protocol)
	assert.Equal(t, uint16(36123), p.LocalPort)
	assert.Equal(t, uint16(22), p.RemotePort)
	assert.False(t, p.Fragment)

	// Second fragment
	fragHeader2 := []byte{
		uint8(layers.IPProtocolUDP), // Next Header (UDP)
		0x00,                        // Reserved
		0xb9,                        // Fragment Offset high byte (185)
		0x01,                        // Fragment Offset low byte & flags (M=1)
		0x00, 0x00, 0x00, 0x01,      // Identification
	}

	buffer.Clear()
	err = ip.SerializeTo(buffer, opts)
	if err != nil {
		t.Fatal(err)
	}

	secondFrag := buffer.Bytes()
	secondFrag = append(secondFrag, fragHeader2...)
	secondFrag = append(secondFrag, []byte{0xde, 0xad, 0xbe, 0xef}...)

	// Test second fragment incoming
	err = newPacket(secondFrag, true, p)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.RemoteAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.LocalAddr)
	assert.Equal(t, uint8(layers.IPProtocolUDP), p.Protocol)
	assert.Equal(t, uint16(0), p.RemotePort)
	assert.Equal(t, uint16(0), p.LocalPort)
	assert.True(t, p.Fragment)

	// Test second fragment outgoing
	err = newPacket(secondFrag, false, p)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("ff02::2"), p.LocalAddr)
	assert.Equal(t, netip.MustParseAddr("ff02::1"), p.RemoteAddr)
	assert.Equal(t, uint8(layers.IPProtocolUDP), p.Protocol)
	assert.Equal(t, uint16(0), p.LocalPort)
	assert.Equal(t, uint16(0), p.RemotePort)
	assert.True(t, p.Fragment)

	// Too short of a fragment packet
	err = newPacket(secondFrag[:len(secondFrag)-10], false, p)
	require.ErrorIs(t, err, ErrIPv6PacketTooShort)
}

func BenchmarkParseV6(b *testing.B) {
	// Regular UDP packet
	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      net.IPv6linklocalallrouters,
		DstIP:      net.IPv6linklocalallnodes,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(36123),
		DstPort: layers.UDPPort(22),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: false,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts, ip, udp)
	if err != nil {
		b.Fatal(err)
	}
	normalPacket := buffer.Bytes()

	// First Fragment packet
	ipFrag := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Fragment,
		HopLimit:   64,
		SrcIP:      net.IPv6linklocalallrouters,
		DstIP:      net.IPv6linklocalallnodes,
	}

	fragHeader := []byte{
		uint8(layers.IPProtocolUDP), // Next Header (UDP)
		0x00,                        // Reserved
		0x00,                        // Fragment Offset high byte (0)
		0x01,                        // Fragment Offset low byte & flags (M=1)
		0x00, 0x00, 0x00, 0x01,      // Identification
	}

	udpHeader := []byte{
		0x8d, 0x7b, // Source port 36123
		0x00, 0x16, // Destination port 22
		0x00, 0x00, // Length
		0x00, 0x00, // Checksum
	}

	buffer.Clear()
	err = ipFrag.SerializeTo(buffer, opts)
	if err != nil {
		b.Fatal(err)
	}

	firstFrag := buffer.Bytes()
	firstFrag = append(firstFrag, fragHeader...)
	firstFrag = append(firstFrag, udpHeader...)
	firstFrag = append(firstFrag, []byte{0xde, 0xad, 0xbe, 0xef}...)

	// Second Fragment packet
	fragHeader[2] = 0xb9 // offset 185
	buffer.Clear()
	err = ipFrag.SerializeTo(buffer, opts)
	if err != nil {
		b.Fatal(err)
	}

	secondFrag := buffer.Bytes()
	secondFrag = append(secondFrag, fragHeader...)
	secondFrag = append(secondFrag, []byte{0xde, 0xad, 0xbe, 0xef}...)

	fp := &firewall.Packet{}

	b.Run("Normal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err = parseV6(normalPacket, true, fp); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("FirstFragment", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err = parseV6(firstFrag, true, fp); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SecondFragment", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err = parseV6(secondFrag, true, fp); err != nil {
				b.Fatal(err)
			}
		}
	})

	// Evil packet
	evilPacket := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6HopByHop,
		HopLimit:   64,
		SrcIP:      net.IPv6linklocalallrouters,
		DstIP:      net.IPv6linklocalallnodes,
	}

	hopHeader := []byte{
		uint8(layers.IPProtocolIPv6HopByHop), // Next Header (HopByHop)
		0x00,                                 // Length
		0x00, 0x00,                           // Options and padding
		0x00, 0x00, 0x00, 0x00, // More options and padding
	}

	lastHopHeader := []byte{
		uint8(layers.IPProtocolUDP), // Next Header (UDP)
		0x00,                        // Length
		0x00, 0x00,                  // Options and padding
		0x00, 0x00, 0x00, 0x00, // More options and padding
	}

	buffer.Clear()
	err = evilPacket.SerializeTo(buffer, opts)
	if err != nil {
		b.Fatal(err)
	}

	evilBytes := buffer.Bytes()
	for i := 0; i < 200; i++ {
		evilBytes = append(evilBytes, hopHeader...)
	}
	evilBytes = append(evilBytes, lastHopHeader...)
	evilBytes = append(evilBytes, udpHeader...)
	evilBytes = append(evilBytes, []byte{0xde, 0xad, 0xbe, 0xef}...)

	b.Run("200 HopByHop headers", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err = parseV6(evilBytes, false, fp); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Ensure authentication data is a multiple of 8 bytes by padding if necessary
func padAuthData(authData []byte) []byte {
	// Length of Authentication Data must be a multiple of 8 bytes
	paddingLength := (8 - (len(authData) % 8)) % 8 // Only pad if necessary
	if paddingLength > 0 {
		authData = append(authData, make([]byte, paddingLength)...)
	}
	return authData
}

// Custom function to manually serialize IPSecAH for both IPv4 and IPv6
func serializeAH(ah *layers.IPSecAH) []byte {
	buf := new(bytes.Buffer)

	// Ensure Authentication Data is a multiple of 8 bytes
	ah.AuthenticationData = padAuthData(ah.AuthenticationData)
	// Calculate Payload Length (in 32-bit words, minus 2)
	payloadLen := uint8((12+len(ah.AuthenticationData))/4) - 2

	// Serialize fields
	if err := binary.Write(buf, binary.BigEndian, ah.NextHeader); err != nil {
		panic(err)
	}
	if err := binary.Write(buf, binary.BigEndian, payloadLen); err != nil {
		panic(err)
	}
	if err := binary.Write(buf, binary.BigEndian, ah.Reserved); err != nil {
		panic(err)
	}
	if err := binary.Write(buf, binary.BigEndian, ah.SPI); err != nil {
		panic(err)
	}
	if err := binary.Write(buf, binary.BigEndian, ah.Seq); err != nil {
		panic(err)
	}
	if len(ah.AuthenticationData) > 0 {
		if err := binary.Write(buf, binary.BigEndian, ah.AuthenticationData); err != nil {
			panic(err)
		}
	}

	return buf.Bytes()
}
