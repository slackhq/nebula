//go:build linux && !android && !e2e_testing

package overlay

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/DefinedNet/netlink"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// An unsafe_route with the same destination and metric as a lan's route must not replace it. Ours waits behind theirs
// and takes over when the lan goes away. Run as root, or unprivileged with `unshare -rn`.
func TestTunRouteLeavesAnotherDevicesRoute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating links and adding routes needs root")
	}

	lan := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "nebrt0"}, PeerName: "nebrt1"}
	require.NoError(t, netlink.LinkAdd(lan))
	t.Cleanup(func() { _ = netlink.LinkDel(lan) })
	peer, err := netlink.LinkByName("nebrt1")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(lan))
	require.NoError(t, netlink.LinkSetUp(peer))

	lanAddrs := []*netlink.Addr{
		{IPNet: &net.IPNet{IP: net.ParseIP("198.51.100.5"), Mask: net.CIDRMask(24, 32)}},
		{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8:1::5"), Mask: net.CIDRMask(64, 128)}, Flags: unix.IFA_F_NODAD},
	}
	for _, a := range lanAddrs {
		require.NoError(t, netlink.AddrAdd(lan, a))
	}

	l := test.NewLogger()
	c := config.NewC(l)
	// The kernel puts a v4 lan route at metric 0, our default, and a v6 one at 256
	require.NoError(t, c.LoadString(`
tun:
  dev: nebrt2
  unsafe_routes:
    - route: 198.51.100.0/24
      via: 10.250.0.2
    - route: 2001:db8:1::/64
      via: fd00:250::2
      metric: 256
`))
	tn, err := newTun(c, l, []netip.Prefix{netip.MustParsePrefix("10.250.0.1/24"), netip.MustParsePrefix("fd00:250::1/64")}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tn.Close() })
	require.NoError(t, tn.Activate())

	via := func(dst string) int {
		routes, err := netlink.RouteGet(net.ParseIP(dst))
		require.NoError(t, err)
		require.NotEmpty(t, routes)
		return routes[0].LinkIndex
	}
	devices := func(dst string) []int {
		_, n, err := net.ParseCIDR(dst)
		require.NoError(t, err)
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Dst: n}, netlink.RT_FILTER_DST)
		require.NoError(t, err)
		var out []int
		for _, r := range routes {
			out = append(out, r.LinkIndex)
		}
		return out
	}

	for _, dst := range []string{"198.51.100.0/24", "2001:db8:1::/64"} {
		assert.ElementsMatch(t, []int{lan.Index, tn.deviceIndex}, devices(dst), dst)
	}
	assert.Equal(t, lan.Index, via("198.51.100.9"))
	assert.Equal(t, lan.Index, via("2001:db8:1::9"))

	// Leaving the lan
	for _, a := range lanAddrs {
		require.NoError(t, netlink.AddrDel(lan, a))
	}
	assert.Equal(t, tn.deviceIndex, via("198.51.100.9"))
	assert.Equal(t, tn.deviceIndex, via("2001:db8:1::9"))

	// Dropping the unsafe_routes removes only ours
	for _, a := range lanAddrs {
		require.NoError(t, netlink.AddrAdd(lan, a))
	}
	require.NoError(t, c.ReloadConfigString("tun:\n  dev: nebrt2\n"))
	for _, dst := range []string{"198.51.100.0/24", "2001:db8:1::/64"} {
		assert.Equal(t, []int{lan.Index}, devices(dst), dst)
	}
}

// The route for our own vpn network is replaced to set its mtu, which must not take a lan's route for the same network
func TestTunVpnNetworkLeavesAnotherDevicesRoute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating links and adding routes needs root")
	}

	lan := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "nebrt0"}, PeerName: "nebrt1"}
	require.NoError(t, netlink.LinkAdd(lan))
	t.Cleanup(func() { _ = netlink.LinkDel(lan) })
	require.NoError(t, netlink.LinkSetUp(lan))
	require.NoError(t, netlink.AddrAdd(lan, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.250.0.5"), Mask: net.CIDRMask(24, 32)}}))

	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString("tun:\n  dev: nebrt2\n"))
	tn, err := newTun(c, l, []netip.Prefix{netip.MustParsePrefix("10.250.0.1/24")}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tn.Close() })
	require.NoError(t, tn.Activate())

	_, n, err := net.ParseCIDR("10.250.0.0/24")
	require.NoError(t, err)
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: n}, netlink.RT_FILTER_DST)
	require.NoError(t, err)
	var devices []int
	for _, r := range routes {
		devices = append(devices, r.LinkIndex)
		if r.LinkIndex == tn.deviceIndex {
			assert.Equal(t, tn.DefaultMTU, r.MTU, "ours still carries the mtu")
		}
	}
	assert.ElementsMatch(t, []int{lan.Index, tn.deviceIndex}, devices)
}
