package iputil

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv4"
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

	expectedLen = MaxRejectPacketSize
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
