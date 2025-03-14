package routing

import (
	"fmt"
	"net/netip"
)

const (
	// Sentinal value
	BucketNotCalculated = -1
)

type Gateways []Gateway

func (g Gateways) String() string {
	str := ""
	for i, gw := range g {
		str += gw.String()
		if i < len(g)-1 {
			str += ", "
		}
	}
	return str
}

type Gateway struct {
	addr             netip.Addr
	weight           int
	bucketUpperBound int
}

func NewGateway(addr netip.Addr, weight int) Gateway {
	return Gateway{addr: addr, weight: weight, bucketUpperBound: BucketNotCalculated}
}

func (g *Gateway) BucketUpperBound() int {
	return g.bucketUpperBound
}

func (g *Gateway) Addr() netip.Addr {
	return g.addr
}

func (g *Gateway) String() string {
	return fmt.Sprintf("{addr: %s, weight: %d}", g.addr, g.weight)
}

// Divide and round to nearest integer
func divideAndRound(v uint64, d uint64) uint64 {
	var tmp uint64 = v + d/2
	return tmp / d
}

// Implements Hash-Threshold mapping, equivalent to the implementation in the linux kernel.
// After this function returns each gateway will have a
// positive bucketUpperBound with a maximum value of 2147483647 (INT_MAX)
func CalculateBucketsForGateways(gateways []Gateway) {

	var totalWeight int = 0
	for i := range gateways {
		totalWeight += gateways[i].weight
	}

	var loopWeight int = 0
	for i := range gateways {
		loopWeight += gateways[i].weight
		gateways[i].bucketUpperBound = int(divideAndRound(uint64(loopWeight)<<31, uint64(totalWeight))) - 1
	}

}
