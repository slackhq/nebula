package firewall

import (
	mathrand "math/rand"
)

// UDPSendPort calculates the UDP port to send from when using multiport mode.
// The result will be from [0, numBuckets)
func (fp Packet) UDPSendPort(numBuckets int) uint16 {
	if numBuckets <= 1 {
		return 0
	}

	// If there is no port (like an ICMP packet), pick a random UDP send port
	if fp.LocalPort == 0 {
		return uint16(mathrand.Intn(numBuckets))
	}

	// A decent enough 32bit hash function
	// Prospecting for Hash Functions
	// - https://nullprogram.com/blog/2018/07/31/
	// - https://github.com/skeeto/hash-prospector
	//   [16 21f0aaad 15 d35a2d97 15] = 0.10760229515479501
	x := (uint32(fp.LocalPort) << 16) | uint32(fp.RemotePort)
	x ^= x >> 16
	x *= 0x21f0aaad
	x ^= x >> 15
	x *= 0xd35a2d97
	x ^= x >> 15

	return uint16(x % uint32(numBuckets))
}
