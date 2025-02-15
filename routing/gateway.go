package routing

import (
	"fmt"
	"net/netip"
)

type Gateway struct {
	ip         netip.Addr
	weight     int
	upperBound int
}

func NewGateway(ip netip.Addr, weight int) Gateway {
	return Gateway{ip: ip, weight: weight}
}

func (g *Gateway) UpperBound() int {
	return g.upperBound
}

func (g *Gateway) Ip() netip.Addr {
	return g.ip
}

func (g *Gateway) String() string {
	return fmt.Sprintf("%s:%d/%d", g.ip, g.weight, g.upperBound)
}

// Divide and round to nearest integer
func divideAndRound(v uint64, d uint64) uint64 {
	var tmp uint64 = v + d/2
	return tmp / d
}

// Implements Hash-Threshold mapping, equivalent to the implementation in the linux kernel.
func RebalanceGateways(gateways []Gateway) {

	var totalWeight int = 0
	for i := range gateways {
		totalWeight += gateways[i].weight
	}

	var loopWeight int = 0
	for i := range gateways {
		loopWeight += gateways[i].weight
		gateways[i].upperBound = int(divideAndRound(uint64(loopWeight)<<31, uint64(totalWeight))) - 1
	}

}
