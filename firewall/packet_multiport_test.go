package firewall

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUDPSendPort(t *testing.T) {
	// One port or none always uses the base port
	assert.Zero(t, Packet{LocalPort: 51234, RemotePort: 443}.UDPSendPort(1))
	assert.Zero(t, Packet{LocalPort: 51234, RemotePort: 443}.UDPSendPort(0))

	// A flow always maps to the same port
	p := Packet{LocalPort: 51234, RemotePort: 443}
	first := p.UDPSendPort(100)
	for range 10 {
		assert.Equal(t, first, p.UDPSendPort(100))
	}

	// Packets without ports, like ICMP, get a random port in range
	seen := map[uint16]bool{}
	for range 1000 {
		port := Packet{}.UDPSendPort(100)
		assert.Less(t, port, uint16(100))
		seen[port] = true
	}
	assert.Greater(t, len(seen), 50)

	// Client ports against one server port spread over every port
	const buckets = 100
	counts := make([]int, buckets)
	for lp := 32768; lp < 32768+100*buckets; lp++ {
		counts[Packet{LocalPort: uint16(lp), RemotePort: 443}.UDPSendPort(buckets)]++
	}
	for i, c := range counts {
		assert.Greater(t, c, 50, "port %d", i)
		assert.Less(t, c, 150, "port %d", i)
	}
}
