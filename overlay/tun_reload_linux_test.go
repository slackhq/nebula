//go:build !e2e_testing

package overlay

import (
	"net/netip"
	"os"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Only tun.mtu changes. The system calls fail without a real device, what matters is the routes nebula keeps
func TestReloadMTUOnlyKeepsRoutes(t *testing.T) {
	routes := "  unsafe_routes:\n    - route: 192.168.100.0/24\n      via: 10.1.0.1\n"
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString("tun:\n  mtu: 1300\n"+routes))

	tn := &tun{
		l:                test.NewLogger(),
		vpnNetworks:      []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")},
		ioctlFd:          ^uintptr(0),
		routesFromSystem: map[netip.Prefix]routing.Gateways{},
	}
	require.NoError(t, tn.reload(c, true, nil))

	require.NoError(t, c.ReloadConfigString("tun:\n  mtu: 1400\n"+routes).Err)
	_ = tn.reload(c, false, nil)

	got := *tn.Routes.Load()
	require.Len(t, got, 1)
	assert.Equal(t, netip.MustParsePrefix("192.168.100.0/24"), got[0].Cidr)
	assert.Equal(t, 1400, got[0].MTU)
	assert.Equal(t, 1400, tn.DefaultMTU)
}

// The device mtu has to fit the largest route mtu, wherever it sits in the list
func TestReloadMaxMTUIsTheLargestRoute(t *testing.T) {
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString("tun:\n  mtu: 1300\n  unsafe_routes:\n"+
		"    - route: 192.168.100.0/24\n      via: 10.1.0.1\n      mtu: 1500\n"+
		"    - route: 192.168.101.0/24\n      via: 10.1.0.1\n      mtu: 1400\n"))

	tn := &tun{
		l:                test.NewLogger(),
		vpnNetworks:      []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")},
		ioctlFd:          ^uintptr(0),
		routesFromSystem: map[netip.Prefix]routing.Gateways{},
	}
	require.NoError(t, tn.reload(c, true, nil))
	assert.Equal(t, 1500, tn.MaxMTU)
	assert.Equal(t, 1300, tn.DefaultMTU)
}

// There is no device behind this tun, so adding a route always fails. Removing one is refused without root, as root the
// kernel answers that the route isn't there, which is what we wanted
func TestReloadRouteFailures(t *testing.T) {
	route := "tun:\n  mtu: 1300\n  unsafe_routes:\n    - route: 192.168.100.0/24\n      via: 10.1.0.1\n"
	cases := []struct {
		name      string
		from, to  string
		wantFails bool
	}{
		{"added", "tun:\n  mtu: 1300\n", route, true},
		{"removed", route, "tun:\n  mtu: 1300\n", os.Geteuid() != 0},
		{"unchanged", route, route + "punchy:\n  punch: true\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := config.NewC(test.NewLogger())
			require.NoError(t, c.LoadString(tc.from))
			tn := &tun{
				l:                test.NewLogger(),
				vpnNetworks:      []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")},
				ioctlFd:          ^uintptr(0),
				routesFromSystem: map[netip.Prefix]routing.Gateways{},
			}
			require.NoError(t, tn.reload(c, true, nil))
			c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
				require.NoError(t, tn.reload(c, false, r))
			})

			res := c.ReloadConfigString(tc.to)
			require.NoError(t, res.Err)
			assert.Equal(t, tc.wantFails, res.Failed)
		})
	}
}

// Keys only read when the device is created need a restart to apply
func TestTunReloadRestartKeys(t *testing.T) {
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString("tun:\n  dev: nebrk0\n"))
	tn, err := NewDeviceFromConfig(c, test.NewLogger(), []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")}, 1)
	if err != nil {
		t.Skipf("can't create a tun device here: %v", err)
	}
	t.Cleanup(func() { _ = tn.Close() })

	res := c.ReloadConfigString("tun:\n  disabled: true\n  dev: nebrk1\n  tx_queue: 100\n")
	require.NoError(t, res.Err)
	assert.ElementsMatch(t, []string{"tun.disabled", "tun.dev", "tun.tx_queue"}, res.RestartKeys)
}
