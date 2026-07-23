package udp

import (
	"context"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMonitor(t *testing.T, ctx context.Context, cfg string) *NetworkChangeMonitor {
	t.Helper()
	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString(cfg))
	return NewNetworkChangeMonitor(ctx, l, c)
}

func TestNetworkChangeMonitorDefaultsOn(t *testing.T) {
	// Says nothing about rebinding, so this covers the default.
	m := newMonitor(t, context.Background(), "listen:\n  host: 0.0.0.0\n")
	assert.True(t, m.enabled, "should default to on")
}

func TestNetworkChangeMonitorDisabledIsANoOp(t *testing.T) {
	m := newMonitor(t, context.Background(), "listen:\n  rebind_on_network_change: false\n")
	require.False(t, m.enabled)

	// Must return without opening a socket. If it watched anything this would block.
	m.Start(func() {})
}

func TestNetworkChangeMonitorNilRebindIsANoOp(t *testing.T) {
	// Nothing to rebind, so there is no point watching, on any platform.
	m := newMonitor(t, context.Background(), "listen:\n  rebind_on_network_change: true\n")
	m.Start(nil)
}
