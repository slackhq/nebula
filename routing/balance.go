package routing

import (
	"net/netip"

	"github.com/slackhq/nebula/firewall"
)

// Hashes the packet source and destination port and always returns a positive integer
// Based on 'Prospecting for Hash Functions'
//   - https://nullprogram.com/blog/2018/07/31/
//   - https://github.com/skeeto/hash-prospector
//     [16 21f0aaad 15 d35a2d97 15] = 0.10760229515479501
func hashPacket(p *firewall.Packet) int {
	x := (uint32(p.LocalPort) << 16) | uint32(p.RemotePort)
	x ^= x >> 16
	x *= 0x21f0aaad
	x ^= x >> 15
	x *= 0xd35a2d97
	x ^= x >> 15

	return int(x) & 0x7FFFFFFF
}

// For this function to work correctly it requires that the buckets for the gateways have been calculated
// If the contract is violated balancing will not work properly and the second return value will return false
func BalancePacket(fwPacket *firewall.Packet, gateways []Gateway) (netip.Addr, bool) {
	hash := hashPacket(fwPacket)

	for i := range gateways {
		if hash <= gateways[i].BucketUpperBound() {
			return gateways[i].Addr(), true
		}
	}

	// If you land here then the buckets for the gateways are not properly calculated
	// Fallback to random routing and let the caller know
	return gateways[hash%len(gateways)].Addr(), false
}
