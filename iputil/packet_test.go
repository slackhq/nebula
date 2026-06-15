package iputil

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func Test_CreateRejectPacket(t *testing.T) {
	h := ipv4.Header{
		Len:      20,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Protocol: 1, // ICMP
	}

	b, err := h.Marshal()
	if err != nil {
		t.Fatalf("h.Marhshal: %v", err)
	}
	b = append(b, []byte{0, 3, 0, 4}...)

	expectedLen := ipv4.HeaderLen + 8 + h.Len + 4
	out := make([]byte, expectedLen)
	rejectPacket := CreateRejectPacket(b, out)
	assert.NotNil(t, rejectPacket)
	assert.Len(t, rejectPacket, expectedLen)

	// ICMP with max header len
	h = ipv4.Header{
		Len:      60,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Protocol: 1, // ICMP
		Options:  make([]byte, 40),
	}

	b, err = h.Marshal()
	if err != nil {
		t.Fatalf("h.Marhshal: %v", err)
	}
	b = append(b, []byte{0, 3, 0, 4, 0, 0, 0, 0}...)

	expectedLen = MaxIPv4RejectPacketSize
	out = make([]byte, MaxRejectPacketSize)
	rejectPacket = CreateRejectPacket(b, out)
	assert.NotNil(t, rejectPacket)
	assert.Len(t, rejectPacket, expectedLen)

	// TCP with max header len
	h = ipv4.Header{
		Len:      60,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Protocol: 6, // TCP
		Options:  make([]byte, 40),
	}

	b, err = h.Marshal()
	if err != nil {
		t.Fatalf("h.Marhshal: %v", err)
	}
	b = append(b, []byte{0, 3, 0, 4}...)
	b = append(b, make([]byte, 16)...)

	expectedLen = ipv4.HeaderLen + 20
	out = make([]byte, expectedLen)
	rejectPacket = CreateRejectPacket(b, out)
	assert.NotNil(t, rejectPacket)
	assert.Len(t, rejectPacket, expectedLen)
}

func makeIPv6Packet(src, dst net.IP, nextHeader uint8, payload []byte) []byte {
	b := make([]byte, ipv6.HeaderLen+len(payload))
	b[0] = ipv6.Version << 4
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[6] = nextHeader
	b[7] = 64
	copy(b[8:24], src.To16())
	copy(b[24:40], dst.To16())
	copy(b[ipv6.HeaderLen:], payload)
	return b
}

func Test_CreateRejectPacketIPv6_ICMP(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	// Small UDP packet: entire original included in body
	udpPayload := make([]byte, 20)
	udpPayload[0] = 0x00 // src port high
	udpPayload[1] = 0x50 // src port low (80)
	udpPayload[2] = 0x01 // dst port high
	udpPayload[3] = 0xBB // dst port low (443)
	packet := makeIPv6Packet(src, dst, 17, udpPayload)

	out := make([]byte, MaxRejectPacketSize)
	rejectPacket := CreateRejectPacket(packet, out)
	assert.NotNil(t, rejectPacket)

	// Small packet fits entirely: 40 (ipv6 hdr) + 8 (icmpv6 hdr) + 60 (original)
	expectedLen := ipv6.HeaderLen + 8 + len(packet)
	assert.Len(t, rejectPacket, expectedLen)

	// Verify version
	assert.Equal(t, byte(ipv6.Version<<4), rejectPacket[0]&0xf0)
	// Verify next header is ICMPv6 (58)
	assert.Equal(t, byte(58), rejectPacket[6])
	// Verify src/dst are swapped
	assert.Equal(t, dst.To16(), net.IP(rejectPacket[8:24]))
	assert.Equal(t, src.To16(), net.IP(rejectPacket[24:40]))
	// Verify ICMPv6 type=1 (Dest Unreachable), code=1 (Administratively prohibited)
	assert.Equal(t, byte(1), rejectPacket[ipv6.HeaderLen])
	assert.Equal(t, byte(1), rejectPacket[ipv6.HeaderLen+1])
	// Verify entire original packet is included in body
	assert.Equal(t, packet, rejectPacket[ipv6.HeaderLen+8:])

	// Large packet: body is truncated to 1000 bytes
	largePkt := makeIPv6Packet(src, dst, 17, make([]byte, 1200))
	rejectPacket = CreateRejectPacket(largePkt, out)
	assert.NotNil(t, rejectPacket)
	assert.Len(t, rejectPacket, ipv6.HeaderLen+8+1000)
	assert.Equal(t, largePkt[:1000], rejectPacket[ipv6.HeaderLen+8:])
}

func Test_CreateRejectPacketIPv6_TCP(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	// TCP SYN packet (next header 6)
	tcpPayload := make([]byte, 20)
	tcpPayload[0] = 0x00 // src port high
	tcpPayload[1] = 0x50 // src port low (80)
	tcpPayload[2] = 0x01 // dst port high
	tcpPayload[3] = 0xBB // dst port low (443)
	binary.BigEndian.PutUint32(tcpPayload[4:], 1000) // seq
	binary.BigEndian.PutUint32(tcpPayload[8:], 0)    // ack seq
	tcpPayload[12] = (20 >> 2) << 4                  // data offset
	tcpPayload[13] = 0b00000010                      // SYN flag

	packet := makeIPv6Packet(src, dst, 6, tcpPayload)

	out := make([]byte, MaxRejectPacketSize)
	rejectPacket := CreateRejectPacket(packet, out)
	assert.NotNil(t, rejectPacket)

	// Expected: 40 (ipv6 hdr) + 20 (tcp RST)
	expectedLen := ipv6.HeaderLen + 20
	assert.Len(t, rejectPacket, expectedLen)

	// Verify version
	assert.Equal(t, byte(ipv6.Version<<4), rejectPacket[0]&0xf0)
	// Verify next header is TCP (6)
	assert.Equal(t, byte(6), rejectPacket[6])
	// Verify src/dst are swapped
	assert.Equal(t, dst.To16(), net.IP(rejectPacket[8:24]))
	assert.Equal(t, src.To16(), net.IP(rejectPacket[24:40]))
	// Verify ports are swapped
	tcpOut := rejectPacket[ipv6.HeaderLen:]
	assert.Equal(t, uint16(443), binary.BigEndian.Uint16(tcpOut[0:2]))
	assert.Equal(t, uint16(80), binary.BigEndian.Uint16(tcpOut[2:4]))
	// RST+ACK flags (since input was SYN without ACK)
	assert.Equal(t, byte(0b00010100), tcpOut[13])
	// ack_seq = original seq (1000) + SYN (1) + FIN (0) + segment data (0)
	assert.Equal(t, uint32(1001), binary.BigEndian.Uint32(tcpOut[8:]))
}

func Test_CreateRejectPacketIPv6_TCPWithACK(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	// TCP packet with ACK set
	tcpPayload := make([]byte, 20)
	tcpPayload[0] = 0x00
	tcpPayload[1] = 0x50
	tcpPayload[2] = 0x01
	tcpPayload[3] = 0xBB
	binary.BigEndian.PutUint32(tcpPayload[4:], 1000) // seq
	binary.BigEndian.PutUint32(tcpPayload[8:], 2000) // ack seq
	tcpPayload[12] = (20 >> 2) << 4                  // data offset
	tcpPayload[13] = 0b00010000                      // ACK flag

	packet := makeIPv6Packet(src, dst, 6, tcpPayload)

	out := make([]byte, MaxRejectPacketSize)
	rejectPacket := CreateRejectPacket(packet, out)
	assert.NotNil(t, rejectPacket)

	tcpOut := rejectPacket[ipv6.HeaderLen:]
	// RST only (no ACK) since input had ACK
	assert.Equal(t, byte(0b00000100), tcpOut[13])
	// seq = original ack_seq
	assert.Equal(t, uint32(2000), binary.BigEndian.Uint32(tcpOut[4:]))
}

func Test_CreateRejectPacketIPv6_TooShort(t *testing.T) {
	// Packet too short to be valid IPv6
	out := make([]byte, MaxRejectPacketSize)
	assert.Nil(t, CreateRejectPacket([]byte{0x60}, out))
	assert.Nil(t, CreateRejectPacket(make([]byte, 39), out))
}

func Test_CreateRejectPacketIPv6_ExtensionHeaders(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	// IPv6 + Hop-by-Hop extension header + TCP
	hopByHop := []byte{
		6,    // next header: TCP
		0,    // length (8 bytes total)
		0, 0, // padding
		0, 0, 0, 0,
	}
	tcpPayload := make([]byte, 20)
	tcpPayload[0] = 0x00
	tcpPayload[1] = 0x50
	tcpPayload[2] = 0x01
	tcpPayload[3] = 0xBB
	binary.BigEndian.PutUint32(tcpPayload[4:], 1000)
	binary.BigEndian.PutUint32(tcpPayload[8:], 2000)
	tcpPayload[12] = (20 >> 2) << 4
	tcpPayload[13] = 0b00010000 // ACK

	payload := append(hopByHop, tcpPayload...)
	packet := makeIPv6Packet(src, dst, 0, payload) // next header 0 = Hop-by-Hop

	out := make([]byte, MaxRejectPacketSize)
	rejectPacket := CreateRejectPacket(packet, out)
	assert.NotNil(t, rejectPacket)

	// Should produce TCP RST
	expectedLen := ipv6.HeaderLen + 20
	assert.Len(t, rejectPacket, expectedLen)
	assert.Equal(t, byte(6), rejectPacket[6]) // next header is TCP
	tcpOut := rejectPacket[ipv6.HeaderLen:]
	assert.Equal(t, byte(0b00000100), tcpOut[13]) // RST only
}
