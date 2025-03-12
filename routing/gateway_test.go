package routing

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRebalance3_2Split(t *testing.T) {
	gateways := []Gateway{}

	gateways = append(gateways, Gateway{addr: netip.Addr{}, weight: 10})
	gateways = append(gateways, Gateway{addr: netip.Addr{}, weight: 5})

	RebalanceGateways(gateways)

	assert.Equal(t, 1431655764, gateways[0].upperBound) // INT_MAX/3*2
	assert.Equal(t, 2147483647, gateways[1].upperBound) // INT_MAX
}

func TestRebalanceEqualSplit(t *testing.T) {
	gateways := []Gateway{}

	gateways = append(gateways, Gateway{addr: netip.Addr{}, weight: 1})
	gateways = append(gateways, Gateway{addr: netip.Addr{}, weight: 1})
	gateways = append(gateways, Gateway{addr: netip.Addr{}, weight: 1})

	RebalanceGateways(gateways)

	assert.Equal(t, 715827882, gateways[0].upperBound)  // INT_MAX/3
	assert.Equal(t, 1431655764, gateways[1].upperBound) // INT_MAX/3*2
	assert.Equal(t, 2147483647, gateways[2].upperBound) // INT_MAX
}
