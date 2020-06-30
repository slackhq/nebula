package nebula

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv4"
)

func Test_newPacket(t *testing.T) {
	p := &FirewallPacket{}

	// length fail
	err := newPacket([]byte{0, 1}, true, p)
	assert.EqualError(t, err, "packet is less than 20 bytes")

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

	assert.EqualError(t, err, "packet is less than 28 bytes, ip header len: 24")

	// not an ipv4 packet
	err = newPacket([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true, p)
	assert.EqualError(t, err, "packet is not ipv4, type: 0")

	// invalid ihl
	err = newPacket([]byte{4<<4 | (8 >> 2 & 0x0f), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true, p)
	assert.EqualError(t, err, "packet had an invalid header length: 8")

	// account for variable ip header length - incoming
	h = ipv4.Header{
		Version:  1,
		Len:      100,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Options:  []byte{0, 1, 0, 2},
		Protocol: fwProtoTCP,
	}

	b, _ = h.Marshal()
	b = append(b, []byte{0, 3, 0, 4}...)
	err = newPacket(b, true, p)

	assert.Nil(t, err)
	assert.Equal(t, p.Protocol, uint8(fwProtoTCP))
	assert.Equal(t, p.LocalIP, ip2int(net.IPv4(10, 0, 0, 2)))
	assert.Equal(t, p.RemoteIP, ip2int(net.IPv4(10, 0, 0, 1)))
	assert.Equal(t, p.RemotePort, uint16(3))
	assert.Equal(t, p.LocalPort, uint16(4))

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

	assert.Nil(t, err)
	assert.Equal(t, p.Protocol, uint8(2))
	assert.Equal(t, p.LocalIP, ip2int(net.IPv4(10, 0, 0, 1)))
	assert.Equal(t, p.RemoteIP, ip2int(net.IPv4(10, 0, 0, 2)))
	assert.Equal(t, p.RemotePort, uint16(6))
	assert.Equal(t, p.LocalPort, uint16(5))
}
