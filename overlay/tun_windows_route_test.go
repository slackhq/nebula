//go:build windows && !e2e_testing

package overlay

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type routeTest struct {
	c    *config.C
	tun  *winTun
	luid winipcfg.LUID
	log  *bytes.Buffer
}

// newRouteTest makes a wintun device of its own, before installing tun.unsafe_routes from cfg
func newRouteTest(t *testing.T, cfg string) *routeTest {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a wintun device needs an elevated process")
	}
	if err := checkWinTunExists(); err != nil {
		t.Skipf("wintun.dll is not where nebula looks for it: %v", err)
	}
	rt := &routeTest{log: &bytes.Buffer{}}
	l := test.NewLoggerWithOutput(rt.log)
	rt.c = config.NewC(l)
	require.NoError(t, rt.c.LoadString(cfg))
	var err error
	rt.tun, err = newTun(rt.c, l, []netip.Prefix{netip.MustParsePrefix("10.250.0.1/24")}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rt.tun.Close() })
	rt.luid = winipcfg.LUID(rt.tun.tun.LUID())
	return rt
}

func (rt *routeTest) metric(t *testing.T, cidr string) uint32 {
	t.Helper()
	p := netip.MustParsePrefix(cidr)
	row, err := rt.luid.Route(p, unspecifiedNextHop(p))
	require.NoError(t, err)
	return row.Metric
}

func unsafeRoutes(routes ...string) string {
	var b strings.Builder
	b.WriteString("tun:\n  dev: nebroutetest\n  unsafe_routes:\n")
	// cidr[@metric][!], the ! for install: false
	for _, r := range routes {
		r, noInstall := strings.CutSuffix(r, "!")
		cidr, metric, _ := strings.Cut(r, "@")
		fmt.Fprintf(&b, "    - route: %s\n      via: 10.250.0.2\n", cidr)
		if metric != "" {
			fmt.Fprintf(&b, "      metric: %s\n", metric)
		}
		if noInstall {
			b.WriteString("      install: false\n")
		}
	}
	return b.String()
}

// A reload that adds a route re-adds the ones already installed, Windows refusing those as already there isn't a failure
func TestWinTun_ReloadKeepsInstalledRoutes(t *testing.T) {
	forFamilies(t, func(t *testing.T, a, b string) {
		rt := newRouteTest(t, unsafeRoutes(a))
		require.NoError(t, rt.tun.Activate())

		require.NoError(t, rt.c.ReloadConfigString(unsafeRoutes(a, b)))
		assert.NotContains(t, rt.log.String(), "Failed to add route")
		rt.metric(t, a)
		rt.metric(t, b)
	})
}

// Windows calls a route the same by destination and next hop, so a changed metric is set on the installed route in
// place rather than deleted and added, which would leave a moment with no route
func TestWinTun_ReloadMetricChangeApplies(t *testing.T) {
	forFamilies(t, func(t *testing.T, a, b string) {
		rt := newRouteTest(t, unsafeRoutes(a+"@100"))
		require.NoError(t, rt.tun.Activate())
		require.Equal(t, uint32(100), rt.metric(t, a))

		require.NoError(t, rt.c.ReloadConfigString(unsafeRoutes(a+"@200")))
		assert.NotContains(t, rt.log.String(), "Failed to add route")
		assert.NotContains(t, rt.log.String(), "Removed route")
		assert.Equal(t, uint32(200), rt.metric(t, a))
	})
}

// A route someone else put on the device with another metric is brought to ours, at startup too
func TestWinTun_ForeignRouteGetsOurMetric(t *testing.T) {
	forFamilies(t, func(t *testing.T, a, b string) {
		rt := newRouteTest(t, unsafeRoutes(a+"@100"))
		p := netip.MustParsePrefix(a)
		require.NoError(t, rt.luid.AddRoute(p, unspecifiedNextHop(p), 50))

		require.NoError(t, rt.tun.Activate())
		assert.Equal(t, uint32(100), rt.metric(t, a))
		assert.Contains(t, rt.log.String(), "level=INFO msg=\"Updated route metric\"")
	})
}

// A CIDR listed twice is installed once, by its last entry, and reloads leave it there instead of flipping between the
// two metrics
func TestWinTun_DuplicateCidrInstallsTheLastEntry(t *testing.T) {
	forFamilies(t, func(t *testing.T, a, b string) {
		rt := newRouteTest(t, unsafeRoutes(a+"@100", a+"@200"))
		require.NoError(t, rt.tun.Activate())
		assert.Equal(t, uint32(200), rt.metric(t, a))

		require.NoError(t, rt.c.ReloadConfigString(unsafeRoutes(a+"@100", a+"@200", b)))
		assert.Equal(t, uint32(200), rt.metric(t, a))
		assert.NotContains(t, rt.log.String(), "Updated route metric")
		assert.NotContains(t, rt.log.String(), "Failed to add route")
	})
}

// Dropping the duplicate that wasn't installed leaves the installed route alone. Windows deletes by destination and
// next hop, deleting the dropped one would take the live route with it
func TestWinTun_DroppingAnUninstalledDuplicateKeepsTheRoute(t *testing.T) {
	forFamilies(t, func(t *testing.T, a, b string) {
		rt := newRouteTest(t, unsafeRoutes(a+"@100", a+"@200"))
		require.NoError(t, rt.tun.Activate())

		require.NoError(t, rt.c.ReloadConfigString(unsafeRoutes(a+"@200")))
		assert.NotContains(t, rt.log.String(), "Removed route")
		assert.Equal(t, uint32(200), rt.metric(t, a))
	})
}

// A reload ends where a fresh start with the same config would, a CIDR whose last entry says not to install it is
// removed
func TestWinTun_ReloadMatchesAFreshStart(t *testing.T) {
	forFamilies(t, func(t *testing.T, a, b string) {
		cidr := netip.MustParsePrefix(a)
		routes := unsafeRoutes(a+"@100", a+"@100!")

		fresh := newRouteTest(t, routes)
		require.NoError(t, fresh.tun.Activate())
		_, err := fresh.luid.Route(cidr, unspecifiedNextHop(cidr))
		require.Error(t, err, "a fresh start installed it")
		require.NoError(t, fresh.tun.Close())

		rt := newRouteTest(t, unsafeRoutes(a+"@100"))
		require.NoError(t, rt.tun.Activate())
		require.NoError(t, rt.c.ReloadConfigString(routes))
		_, err = rt.luid.Route(cidr, unspecifiedNextHop(cidr))
		assert.Error(t, err, "the reload left it installed")
	})
}

// forFamilies runs f with two unsafe_routes CIDRs of each address family, the tun's own network stays IPv4
func forFamilies(t *testing.T, f func(t *testing.T, a, b string)) {
	t.Run("ipv4", func(t *testing.T) { f(t, "10.251.1.0/24", "10.251.2.0/24") })
	t.Run("ipv6", func(t *testing.T) { f(t, "fd00:251:1::/64", "fd00:251:2::/64") })
}
