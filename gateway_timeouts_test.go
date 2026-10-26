package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGatewayTimeouts(t *testing.T) {
	g := newGatewayTimeouts()
	gw := netip.MustParseAddr("10.128.0.2")
	other := netip.MustParseAddr("10.128.0.9")

	// A timeout for an address the routing path never asked about is not kept, so the table only ever holds gateways
	g.timedOut(other)
	assert.Empty(t, g.m)

	assert.False(t, g.recentlyTimedOut(gw, time.Minute), "a gateway seen for the first time has no timeout")
	assert.Len(t, g.m, 1)

	g.timedOut(gw)
	assert.True(t, g.recentlyTimedOut(gw, time.Minute))
	assert.False(t, g.recentlyTimedOut(gw, 0), "a timeout older than the window no longer counts")

	g.completed([]netip.Addr{other, gw})
	assert.False(t, g.recentlyTimedOut(gw, time.Minute), "a completed handshake clears the timeout")
	assert.Len(t, g.m, 1)
}
