package routing

import (
	"net/netip"

	"github.com/slackhq/nebula/firewall"
	"github.com/zeebo/xxh3"
)

// Hashes the packet and always returns a positive integer
func hashPacket(p *firewall.Packet) int {
	hasher := xxh3.Hasher{}

	hasher.Write(p.LocalAddr.AsSlice())
	hasher.Write(p.RemoteAddr.AsSlice())
	hasher.Write([]byte{
		byte(p.LocalPort & 0xFF),
		byte((p.LocalPort >> 8) & 0xFF),
		byte(p.RemotePort & 0xFF),
		byte((p.RemotePort >> 8) & 0xFF),
		byte(p.Protocol),
	})

	// Uses xxh3 as it is a fast hash with good distribution
	return int(hasher.Sum64() & 0x7FFFFFFF)
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
