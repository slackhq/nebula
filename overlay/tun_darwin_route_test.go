//go:build darwin && !ios && !e2e_testing

package overlay

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Every mac routes loopback through lo0
func TestRouteInterfaceIn(t *testing.T) {
	msgs, err := fetchRoutes()
	require.NoError(t, err)
	routeInterface := func(s string) int { return routeInterfaceIn(msgs, netip.MustParsePrefix(s)) }

	lo0, err := net.InterfaceByName("lo0")
	require.NoError(t, err)

	assert.Equal(t, lo0.Index, routeInterface("127.0.0.0/8"))
	assert.Equal(t, lo0.Index, routeInterface("127.0.0.1/32"), "a host route has no netmask")
	assert.Equal(t, lo0.Index, routeInterface("::1/128"))
	assert.Equal(t, 0, routeInterface("127.0.0.0/16"), "only an exact prefix counts")

	// Most macs also list the default route scoped to their other interfaces
	out, err := exec.Command("route", "-n", "get", "default").Output()
	require.NoError(t, err)
	var name string
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "interface: "); ok {
			name = v
		}
	}
	if name == "" {
		t.Skip("no default route")
	}
	def, err := net.InterfaceByName(name)
	require.NoError(t, err)
	assert.Equal(t, def.Index, routeInterface("0.0.0.0/0"))
}

func TestRouteInterfaceIn_SkipsScopedCopies(t *testing.T) {
	route := func(index, flags int) netroute.Message {
		addrs := make([]netroute.Addr, unix.RTAX_MAX)
		addrs[unix.RTAX_DST] = &netroute.Inet4Addr{IP: [4]byte{192, 168, 1, 0}}
		addrs[unix.RTAX_NETMASK] = &netroute.Inet4Addr{IP: [4]byte{255, 255, 255, 0}}
		return &netroute.RouteMessage{Index: index, Flags: flags, Addrs: addrs}
	}
	p := netip.MustParsePrefix("192.168.1.0/24")
	assert.Equal(t, 7, routeInterfaceIn([]netroute.Message{route(4, unix.RTF_UP|unix.RTF_IFSCOPE), route(7, unix.RTF_UP)}, p))
	assert.Equal(t, 0, routeInterfaceIn([]netroute.Message{route(4, unix.RTF_UP|unix.RTF_IFSCOPE)}, p))
}

// A reload can happen before Activate
func TestTunRoutesBeforeActivate(t *testing.T) {
	tn := &tun{l: test.NewLogger()}
	routes := []Route{{
		Cidr:    netip.MustParsePrefix("10.253.1.0/24"),
		Via:     routing.Gateways{routing.NewGateway(netip.MustParseAddr("10.250.0.2"), 1)},
		Install: true,
	}}
	tn.Routes.Store(&routes)

	assert.NoError(t, tn.addRoutes(true))
	assert.NoError(t, tn.removeRoutes(routes))
}

// A tun.routes entry with no via is never installed, so removing it must not delete a route for the same cidr that
// belongs to someone else
func TestTunReloadLeavesRoutesItNeverInstalled(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a utun and adding routes needs root")
	}
	lo0, err := net.InterfaceByName("lo0")
	require.NoError(t, err)
	cidr := "10.250.0.128/25"
	require.NoError(t, exec.Command("route", "-q", "-n", "add", "-net", cidr, "-interface", "lo0").Run())
	t.Cleanup(func() { _ = exec.Command("route", "-q", "-n", "delete", "-net", cidr).Run() })

	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString("tun:\n  routes:\n    - route: "+cidr+"\n      mtu: 1300\n"))
	tn, err := newTun(c, l, []netip.Prefix{netip.MustParsePrefix("10.250.0.1/24")}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tn.Close() })
	require.NoError(t, tn.Activate())

	require.NoError(t, c.ReloadConfigString("tun: {}\n"))
	msgs, err := fetchRoutes()
	require.NoError(t, err)
	assert.Equal(t, lo0.Index, routeInterfaceIn(msgs, netip.MustParsePrefix(cidr)))
}

func TestRouteRemoved(t *testing.T) {
	cidr := netip.MustParsePrefix("192.168.1.0/24")
	via := routing.Gateways{routing.NewGateway(netip.MustParseAddr("10.250.0.2"), 1)}
	routes := []Route{{Cidr: cidr, Via: via, Install: true}}
	msg := func(typ, flags int, dst, mask [4]byte) []byte {
		m := &netroute.RouteMessage{
			Version: unix.RTM_VERSION,
			Type:    typ,
			Flags:   flags,
			Addrs: []netroute.Addr{
				unix.RTAX_DST:     &netroute.Inet4Addr{IP: dst},
				unix.RTAX_GATEWAY: &netroute.LinkAddr{Index: 4},
				unix.RTAX_NETMASK: &netroute.Inet4Addr{IP: mask},
			},
		}
		b, err := m.Marshal()
		require.NoError(t, err)
		return b
	}
	lan, mask := [4]byte{192, 168, 1, 0}, [4]byte{255, 255, 255, 0}

	assert.True(t, routeRemoved(msg(unix.RTM_DELETE, unix.RTF_UP, lan, mask), routes))
	assert.False(t, routeRemoved(msg(unix.RTM_ADD, unix.RTF_UP, lan, mask), routes))
	assert.False(t, routeRemoved(msg(unix.RTM_DELETE, unix.RTF_UP|unix.RTF_IFSCOPE, lan, mask), routes), "a scoped route never held the prefix")
	assert.False(t, routeRemoved(msg(unix.RTM_DELETE, unix.RTF_UP, lan, [4]byte{255, 255, 0, 0}), routes), "only an exact prefix counts")
	assert.False(t, routeRemoved(msg(unix.RTM_DELETE, unix.RTF_UP, lan, mask), []Route{{Cidr: cidr, Install: true}}), "a route with no via is never installed")
	assert.False(t, routeRemoved(msg(unix.RTM_DELETE, unix.RTF_UP, lan, mask), []Route{{Cidr: cidr, Via: via}}), "install: false")
}

// newRouteTestTun is a tun for the root tests below whose unsafe_route cidr is already routed through lo0, like a lan
// that was up when nebula started
func newRouteTestTun(t *testing.T, cidr string) (*tun, *config.C, *net.Interface) {
	if os.Geteuid() != 0 {
		t.Skip("creating a utun and adding routes needs root")
	}
	lo0, err := net.InterfaceByName("lo0")
	require.NoError(t, err)
	require.NoError(t, exec.Command("route", "-q", "-n", "add", "-net", cidr, "-interface", "lo0").Run())
	t.Cleanup(func() { _ = exec.Command("route", "-q", "-n", "delete", "-net", cidr).Run() })

	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString("tun:\n  unsafe_routes:\n    - route: "+cidr+"\n      via: 10.250.0.2\n"))
	tn, err := newTun(c, l, []netip.Prefix{netip.MustParsePrefix("10.250.0.1/24")}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tn.Close() })
	require.NoError(t, tn.Activate())

	msgs, err := fetchRoutes()
	require.NoError(t, err)
	require.Equal(t, lo0.Index, routeInterfaceIn(msgs, netip.MustParsePrefix(cidr)), "an existing route keeps its prefix")
	return tn, c, lo0
}

// Leaving the lan that held an unsafe_route's prefix must not need a restart to get the unsafe_route
func TestTunAddsRouteOnceItsPrefixIsFree(t *testing.T) {
	cidr := "10.251.0.0/24"
	tn, _, _ := newRouteTestTun(t, cidr)

	require.NoError(t, exec.Command("route", "-q", "-n", "delete", "-net", cidr).Run())
	assert.Eventually(t, func() bool {
		msgs, err := fetchRoutes()
		return err == nil && routeInterfaceIn(msgs, netip.MustParsePrefix(cidr)) == tn.linkAddr.Load().Index
	}, 5*time.Second, 50*time.Millisecond)
}

// The kernel deletes a route by prefix alone, so dropping an unsafe_route someone else holds must not delete theirs
func TestTunReloadLeavesRouteItYielded(t *testing.T) {
	cidr := "10.251.1.0/24"
	_, c, lo0 := newRouteTestTun(t, cidr)

	require.NoError(t, c.ReloadConfigString("tun: {}\n"))
	msgs, err := fetchRoutes()
	require.NoError(t, err)
	assert.Equal(t, lo0.Index, routeInterfaceIn(msgs, netip.MustParsePrefix(cidr)))
}
