package routing

import (
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/firewall"
	"github.com/stretchr/testify/assert"
)

func TestPacketsAreBalancedEqually(t *testing.T) {

	gateways := []Gateway{}

	gw1Addr := netip.MustParseAddr("1.0.0.1")
	gw2Addr := netip.MustParseAddr("1.0.0.2")
	gw3Addr := netip.MustParseAddr("1.0.0.3")

	gateways = append(gateways, NewGateway(gw1Addr, 1))
	gateways = append(gateways, NewGateway(gw2Addr, 1))
	gateways = append(gateways, NewGateway(gw3Addr, 1))

	CalculateBucketsForGateways(gateways)

	gw1count := 0
	gw2count := 0
	gw3count := 0

	iterationCount := uint16(65535)
	for i := uint16(0); i < iterationCount; i++ {
		packet := firewall.Packet{
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  i,
			RemotePort: 65535 - i,
			Protocol:   6, // TCP
			Fragment:   false,
		}

		selectedGw, ok := BalancePacket(&packet, gateways)
		assert.True(t, ok)

		switch selectedGw {
		case gw1Addr:
			gw1count += 1
		case gw2Addr:
			gw2count += 1
		case gw3Addr:
			gw3count += 1
		}

	}

	// Assert packets are balanced, allow variation of up to 100 packets per gateway
	assert.InDeltaf(t, iterationCount/3, gw1count, 100, "Expected %d +/- 100, but got %d", iterationCount/3, gw1count)
	assert.InDeltaf(t, iterationCount/3, gw2count, 100, "Expected %d +/- 100, but got %d", iterationCount/3, gw1count)
	assert.InDeltaf(t, iterationCount/3, gw3count, 100, "Expected %d +/- 100, but got %d", iterationCount/3, gw1count)

}

func TestPacketsAreBalancedByPriority(t *testing.T) {

	gateways := []Gateway{}

	gw1Addr := netip.MustParseAddr("1.0.0.1")
	gw2Addr := netip.MustParseAddr("1.0.0.2")

	gateways = append(gateways, NewGateway(gw1Addr, 10))
	gateways = append(gateways, NewGateway(gw2Addr, 5))

	CalculateBucketsForGateways(gateways)

	gw1count := 0
	gw2count := 0

	iterationCount := uint16(65535)
	for i := uint16(0); i < iterationCount; i++ {
		packet := firewall.Packet{
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  i,
			RemotePort: 65535 - i,
			Protocol:   6, // TCP
			Fragment:   false,
		}

		selectedGw, ok := BalancePacket(&packet, gateways)
		assert.True(t, ok)

		switch selectedGw {
		case gw1Addr:
			gw1count += 1
		case gw2Addr:
			gw2count += 1
		}

	}

	iterationCountAsFloat := float32(iterationCount)

	assert.InDeltaf(t, iterationCountAsFloat*(2.0/3.0), gw1count, 100, "Expected %d +/- 100, but got %d", iterationCountAsFloat*(2.0/3.0), gw1count)
	assert.InDeltaf(t, iterationCountAsFloat*(1.0/3.0), gw2count, 100, "Expected %d +/- 100, but got %d", iterationCountAsFloat*(1.0/3.0), gw2count)
}

func TestBalancePacketDistributsRandomlyAndReturnsFalseIfBucketsNotCalculated(t *testing.T) {
	gateways := []Gateway{}

	gw1Addr := netip.MustParseAddr("1.0.0.1")
	gw2Addr := netip.MustParseAddr("1.0.0.2")

	gateways = append(gateways, NewGateway(gw1Addr, 10))
	gateways = append(gateways, NewGateway(gw2Addr, 5))

	iterationCount := uint16(65535)
	gw1count := 0
	gw2count := 0

	for i := uint16(0); i < iterationCount; i++ {
		packet := firewall.Packet{
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  i,
			RemotePort: 65535 - i,
			Protocol:   6, // TCP
			Fragment:   false,
		}

		selectedGw, ok := BalancePacket(&packet, gateways)
		assert.False(t, ok)

		switch selectedGw {
		case gw1Addr:
			gw1count += 1
		case gw2Addr:
			gw2count += 1
		}

	}

	assert.Equal(t, int(iterationCount), (gw1count + gw2count))
	assert.NotEqual(t, 0, gw1count)
	assert.NotEqual(t, 0, gw2count)

}
