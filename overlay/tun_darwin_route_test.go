//go:build darwin && !ios && !e2e_testing

package overlay

import (
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

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
