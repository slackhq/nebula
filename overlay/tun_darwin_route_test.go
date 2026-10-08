//go:build darwin && !ios && !e2e_testing

package overlay

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Every mac routes loopback through lo0
func TestRouteInterface(t *testing.T) {
	lo0, err := net.InterfaceByName("lo0")
	require.NoError(t, err)

	assert.Equal(t, lo0.Index, routeInterface(netip.MustParsePrefix("127.0.0.0/8")))
	assert.Equal(t, lo0.Index, routeInterface(netip.MustParsePrefix("127.0.0.1/32")), "a host route has no netmask")
	assert.Equal(t, lo0.Index, routeInterface(netip.MustParsePrefix("::1/128")))
	assert.Equal(t, 0, routeInterface(netip.MustParsePrefix("127.0.0.0/16")), "only an exact prefix counts")
	assert.Equal(t, 0, routeInterface(netip.MustParsePrefix("10.253.253.0/24")))

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
	assert.Equal(t, def.Index, routeInterface(netip.MustParsePrefix("0.0.0.0/0")))
}

func unsafeRoutesConfig(cidrs ...string) string {
	s := "tun:\n  unsafe_routes:\n"
	for _, c := range cidrs {
		s += "    - route: " + c + "\n      via: 10.250.0.2\n"
	}
	return s
}

func TestTunReloadExistingRoutes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a utun and adding routes needs root")
	}
	lo0, err := net.InterfaceByName("lo0")
	require.NoError(t, err)
	foreign := "10.253.3.0/24"
	require.NoError(t, exec.Command("route", "-q", "-n", "add", "-net", foreign, "-interface", "lo0").Run())
	t.Cleanup(func() { _ = exec.Command("route", "-q", "-n", "delete", "-net", foreign).Run() })

	logs := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(logs)
	c := config.NewC(l)
	require.NoError(t, c.LoadString(unsafeRoutesConfig("10.253.1.0/24")))
	tn, err := newTun(c, l, []netip.Prefix{netip.MustParsePrefix("10.250.0.1/24")}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tn.Close() })
	require.NoError(t, tn.Activate())
	logs.Reset()

	require.NoError(t, c.ReloadConfigString(unsafeRoutesConfig("10.253.1.0/24", "10.253.2.0/24", foreign)))
	assert.NotContains(t, logs.String(), "route=10.253.1.0/24", "a route already through our tun was warned about")
	assert.Contains(t, logs.String(), "level=WARN msg=\"unable to add unsafe_route, the destination is already routed through another interface\" route="+foreign)
	assert.Equal(t, tn.linkAddr.Index, routeInterface(netip.MustParsePrefix("10.253.1.0/24")))
	assert.Equal(t, tn.linkAddr.Index, routeInterface(netip.MustParsePrefix("10.253.2.0/24")))
	assert.Equal(t, lo0.Index, routeInterface(netip.MustParsePrefix(foreign)), "someone else's route was taken over")
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
