package routing

import (
	"net/netip"

	"github.com/slackhq/nebula/firewall"
	"github.com/zeebo/xxh3"
)

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

func BalancePacket(fwPacket *firewall.Packet, gateways []Gateway) netip.Addr {
	hash := hashPacket(fwPacket)

	for i := range gateways {
		if hash <= gateways[i].UpperBound() {
			return gateways[i].Addr()
		}
	}

	// This should never happen
	panic("The packet hash value should always fall inside a gateway bucket")
}
