package nebula

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDownGateways(t *testing.T) {
	g := newDownGateways()
	gw := netip.MustParseAddr("10.128.0.2")
	other := netip.MustParseAddr("10.128.0.9")

	// A timeout for an address the routing path never asked about is not kept, so the table only ever holds gateways
	g.timedOut(other)
	assert.Empty(t, g.m)

	assert.False(t, g.isDown(gw), "a gateway seen for the first time is not down")
	assert.Len(t, g.m, 1)

	g.timedOut(gw)
	assert.True(t, g.isDown(gw))

	g.completed([]netip.Addr{other, gw})
	assert.False(t, g.isDown(gw), "a completed handshake marks the gateway up")
	assert.Len(t, g.m, 1)
}
