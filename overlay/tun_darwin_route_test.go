//go:build darwin && !ios && !e2e_testing

package overlay

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
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

// Captured on macOS 15.6 while adding and removing 198.51.100.77/24 on a feth
const (
	// The kernel deleting the address's subnet route. It packs its sockaddrs without padding, x/net/route can't parse it
	kernelSubnetDelete = "870005022300000000010002070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010020000c63364000000000000000000141223000600000000000000000000000000000007ffffffffffff"
	addressRemoved     = "5000050db400000001010000230000000000000007020000ffffff00141223000606060066657468373766657468004d10020000c633644d000000000000000010020000c63364ff0000000000000000"
	// With no interface address, which x/net/route skips
	interfaceChanged = "7000050e000000004288000023000000060000060e000000dc05000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000073e5ce6a0000000000000000000001000000000000000000"
)

func TestRoutesMayBeFreed(t *testing.T) {
	cidr := netip.MustParsePrefix("192.168.1.0/24")
	via := routing.Gateways{routing.NewGateway(netip.MustParseAddr("10.250.0.2"), 1)}
	routes := []Route{{Cidr: cidr, Via: via, Install: true}}
	// A request like route(8) sends, the kernel echoes it to every routing socket
	request := func(typ, flags int, dst, mask [4]byte) []byte {
		m := &netroute.RouteMessage{
			Version: unix.RTM_VERSION,
			Type:    typ,
			Flags:   flags,
			ID:      1234,
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
	raw := func(s string) []byte {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		return b
	}
	lan, mask := [4]byte{192, 168, 1, 0}, [4]byte{255, 255, 255, 0}

	assert.True(t, routesMayBeFreed(request(unix.RTM_DELETE, unix.RTF_UP, lan, mask), routes))
	assert.False(t, routesMayBeFreed(request(unix.RTM_ADD, unix.RTF_UP, lan, mask), routes))
	assert.False(t, routesMayBeFreed(request(unix.RTM_DELETE, unix.RTF_UP|unix.RTF_IFSCOPE, lan, mask), routes), "a scoped route never held the prefix")
	assert.False(t, routesMayBeFreed(request(unix.RTM_DELETE, unix.RTF_UP, lan, [4]byte{255, 255, 0, 0}), routes), "only an exact prefix counts")
	assert.False(t, routesMayBeFreed(request(unix.RTM_DELETE, unix.RTF_UP, lan, mask), []Route{{Cidr: cidr, Install: true}}), "a route with no via is never installed")
	assert.False(t, routesMayBeFreed(request(unix.RTM_DELETE, unix.RTF_UP, lan, mask), []Route{{Cidr: cidr, Via: via}}), "install: false")

	failed := request(unix.RTM_DELETE, unix.RTF_UP, lan, mask)
	binary.NativeEndian.PutUint32(failed[24:28], uint32(unix.ESRCH))
	assert.False(t, routesMayBeFreed(failed, routes), "a failed request is echoed too")

	_, err := netroute.ParseRIB(unix.NET_RT_DUMP, raw(kernelSubnetDelete))
	require.Error(t, err, "if x/net/route learns to parse these, match their prefix instead")
	assert.True(t, routesMayBeFreed(raw(kernelSubnetDelete), routes), "the kernel's own deletes could be any prefix")
	neighbor := raw(kernelSubnetDelete)
	binary.NativeEndian.PutUint32(neighbor[8:12], unix.RTF_UP|unix.RTF_HOST|unix.RTF_LLINFO)
	assert.False(t, routesMayBeFreed(neighbor, routes), "a neighbor expiring")

	assert.True(t, routesMayBeFreed(raw(addressRemoved), routes))
	assert.True(t, routesMayBeFreed(raw(interfaceChanged), routes), "detaching an interface deletes its routes without a message for each")
}

// newRouteTestTun is an activated tun for the root tests below with an unsafe_route for each of cidrs. sweep replaces
// the minute between sweeps when it isn't zero.
func newRouteTestTun(t *testing.T, sweep time.Duration, cidrs ...string) (*tun, *config.C, string) {
	requireRoot(t)

	cfg := "tun:\n  unsafe_routes:\n"
	for _, cidr := range cidrs {
		via := "10.250.0.2"
		if netip.MustParsePrefix(cidr).Addr().Is6() {
			via = "fd00:250::2"
		}
		cfg += "    - route: " + cidr + "\n      via: " + via + "\n"
	}

	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString(cfg))
	tn, err := newTun(c, l, []netip.Prefix{netip.MustParsePrefix("10.250.0.1/24"), netip.MustParsePrefix("fd00:250::1/64")}, false)
	require.NoError(t, err)
	if sweep != 0 {
		tn.routeSweepEvery = sweep
	}
	t.Cleanup(func() { _ = tn.Close() })
	require.NoError(t, tn.Activate())
	return tn, c, cfg
}

func requireRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating interfaces and adding routes needs root")
	}
}

// routeVia is the index of the interface that routes cidr, 0 if none does
func routeVia(t *testing.T, cidr string) int {
	msgs, err := fetchRoutes()
	require.NoError(t, err)
	return routeInterfaceIn(msgs, netip.MustParsePrefix(cidr))
}

func routeArgs(action, cidr string, extra ...string) []string {
	args := []string{"-q", "-n", action}
	if netip.MustParsePrefix(cidr).Addr().Is6() {
		args = append(args, "-inet6")
	}
	return append(append(args, "-net", cidr), extra...)
}

func routeCmd(t *testing.T, action, cidr string, extra ...string) {
	out, err := exec.Command("route", routeArgs(action, cidr, extra...)...).CombinedOutput()
	require.NoError(t, err, string(out))
}

// cleanupRoute deletes cidr's route when the test ends, whoever holds it
func cleanupRoute(t *testing.T, cidr string) {
	t.Cleanup(func() { _ = exec.Command("route", routeArgs("delete", cidr)...).Run() })
}

// routeThroughLo0 routes cidr through lo0, like a lan nebula started on
func routeThroughLo0(t *testing.T, cidr string) int {
	requireRoot(t)
	routeCmd(t, "add", cidr, "-interface", "lo0")
	cleanupRoute(t, cidr)
	lo0, err := net.InterfaceByName("lo0")
	require.NoError(t, err)
	return lo0.Index
}

// Leaving the lan that held an unsafe_route's prefix must not need a restart to get the unsafe_route
func TestTunAddsRouteOnceItsPrefixIsFree(t *testing.T) {
	for _, cidr := range []string{"10.251.0.0/24", "2001:db8:251::/64"} {
		t.Run(cidr, func(t *testing.T) {
			lo0 := routeThroughLo0(t, cidr)
			tn, _, _ := newRouteTestTun(t, 0, cidr)
			require.Equal(t, lo0, routeVia(t, cidr), "an existing route keeps its prefix")

			routeCmd(t, "delete", cidr)
			assert.Eventually(t, func() bool { return routeVia(t, cidr) == tn.linkAddr.Load().Index }, 5*time.Second, 50*time.Millisecond)
		})
	}
}

// The kernel deletes a route by prefix alone, so dropping an unsafe_route someone else holds must not delete theirs
func TestTunReloadLeavesRouteItYielded(t *testing.T) {
	cidr := "10.251.1.0/24"
	lo0 := routeThroughLo0(t, cidr)
	_, c, _ := newRouteTestTun(t, 0, cidr)

	require.NoError(t, c.ReloadConfigString("tun: {}\n"))
	assert.Equal(t, lo0, routeVia(t, cidr))
}

// configd takes a prefix by deleting the route holding it and adding its own. Ours goes back once theirs is removed
func TestTunYieldsToARouteThatReplacesIt(t *testing.T) {
	cidr := "10.251.3.0/24"
	tn, _, _ := newRouteTestTun(t, 0, cidr)
	ours := tn.linkAddr.Load().Index
	require.Equal(t, ours, routeVia(t, cidr))

	cleanupRoute(t, cidr)
	out, err := exec.Command("sh", "-c", "route -q -n delete -net "+cidr+" && route -q -n add -net "+cidr+" -interface lo0").CombinedOutput()
	require.NoError(t, err, string(out))
	lo0, err := net.InterfaceByName("lo0")
	require.NoError(t, err)
	time.Sleep(2 * routeRetryDelay)
	require.Equal(t, lo0.Index, routeVia(t, cidr))

	routeCmd(t, "delete", cidr)
	assert.Eventually(t, func() bool { return routeVia(t, cidr) == ours }, 5*time.Second, 50*time.Millisecond)
}

// A route someone deleted, with nothing in its place, stays gone until a reload, so they can put their own there
func TestTunLeavesRouteDeletedByHand(t *testing.T) {
	cidr := "10.251.4.0/24"
	tn, c, cfg := newRouteTestTun(t, 200*time.Millisecond, cidr)
	ours := tn.linkAddr.Load().Index
	require.Equal(t, ours, routeVia(t, cidr))

	routeCmd(t, "delete", cidr)
	assert.Never(t, func() bool { return routeVia(t, cidr) != 0 }, 3*routeRetryDelay, 50*time.Millisecond)

	// A reload with nothing changed is how to ask for it back
	require.NoError(t, c.ReloadConfigString(cfg))
	assert.Equal(t, ours, routeVia(t, cidr))
}

// Detaching an interface deletes its routes without a routing socket message for each, like unplugging the dock whose
// ethernet configd routed the lan through
func TestTunAddsRouteWhenItsInterfaceDetaches(t *testing.T) {
	requireRoot(t)
	var feth string
	for i := 100; i < 200 && feth == ""; i++ {
		if _, err := net.InterfaceByName(fmt.Sprintf("feth%d", i)); err != nil {
			feth = fmt.Sprintf("feth%d", i)
		}
	}
	require.NotEmpty(t, feth)
	require.NoError(t, exec.Command("ifconfig", feth, "create").Run())
	t.Cleanup(func() { _ = exec.Command("ifconfig", feth, "destroy").Run() })
	require.NoError(t, exec.Command("ifconfig", feth, "inet", "198.51.100.5/24", "up").Run())

	// Static, like the lan routes configd installs
	cidr := "10.251.2.0/24"
	routeCmd(t, "add", cidr, "-interface", feth)
	cleanupRoute(t, cidr)
	ifc, err := net.InterfaceByName(feth)
	require.NoError(t, err)

	tn, _, _ := newRouteTestTun(t, 0, cidr)
	require.Equal(t, ifc.Index, routeVia(t, cidr))

	// Losing the address first leaves the route, the reconcile finds it still held
	require.NoError(t, exec.Command("ifconfig", feth, "inet", "198.51.100.5", "-alias").Run())
	time.Sleep(2 * routeRetryDelay)
	require.Equal(t, ifc.Index, routeVia(t, cidr))

	// Only RTM_IFINFO says the interface went, its route goes with no message of its own
	require.NoError(t, exec.Command("ifconfig", feth, "destroy").Run())
	assert.Eventually(t, func() bool { return routeVia(t, cidr) == tn.linkAddr.Load().Index }, 5*time.Second, 50*time.Millisecond)
}

// The routing socket drops what doesn't fit its buffer without a word, the sweep finds what it missed
func TestTunSweepAddsRouteTheWatcherMissed(t *testing.T) {
	cidr := "10.251.5.0/24"
	routeThroughLo0(t, cidr)
	tn, _, _ := newRouteTestTun(t, 200*time.Millisecond, cidr)

	tn.routesMu.Lock()
	require.NoError(t, tn.routeWatch.Close())
	tn.routesMu.Unlock()

	routeCmd(t, "delete", cidr)
	assert.Eventually(t, func() bool { return routeVia(t, cidr) == tn.linkAddr.Load().Index }, 5*time.Second, 50*time.Millisecond)
}
