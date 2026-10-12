//go:build darwin && !ios && !e2e_testing

package overlay

import (
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// routedThrough returns the interface index of the unscoped route for exactly p, or 0 if there is none
func routedThrough(p netip.Prefix) int {
	rib, err := netroute.FetchRIB(unix.AF_UNSPEC, unix.NET_RT_DUMP, 0)
	if err != nil {
		return 0
	}
	msgs, err := netroute.ParseRIB(netroute.RIBTypeRoute, rib)
	if err != nil {
		return 0
	}

	for _, m := range msgs {
		rm, ok := m.(*netroute.RouteMessage)
		if !ok || rm.Flags&unix.RTF_IFSCOPE != 0 || len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		var dst, mask []byte
		switch a := rm.Addrs[unix.RTAX_DST].(type) {
		case *netroute.Inet4Addr:
			dst = a.IP[:]
		case *netroute.Inet6Addr:
			dst = a.IP[:]
		}
		switch a := rm.Addrs[unix.RTAX_NETMASK].(type) {
		case *netroute.Inet4Addr:
			mask = a.IP[:]
		case *netroute.Inet6Addr:
			mask = a.IP[:]
		}
		if slices.Equal(dst, p.Masked().Addr().AsSlice()) && slices.Equal(mask, prefixToMask(p).AsSlice()) {
			return rm.Index
		}
	}
	return 0
}

// Needs root to create the utun, run with sudo
func TestTunActivate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a utun needs root")
	}

	l := test.NewLogger()
	networks := []netip.Prefix{netip.MustParsePrefix("10.253.40.1/24"), netip.MustParsePrefix("fd00:1931::1/64")}

	tn, err := newTun(config.NewC(l), l, networks, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tn.Close() })
	require.NoError(t, tn.Activate())

	// Single addresses, so nothing mistakes the networks for an attached LAN
	iface, err := net.InterfaceByName(tn.Device)
	require.NoError(t, err)
	addrs, err := iface.Addrs()
	require.NoError(t, err)
	var got []string
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
			got = append(got, ipn.String())
		}
	}
	assert.ElementsMatch(t, []string{"10.253.40.1/32", "fd00:1931::1/128"}, got)

	// Routed explicitly through the tun
	for _, n := range networks {
		assert.Equal(t, tn.linkAddr.Index, routedThrough(n), "%v is routed through the tun", n)
	}

	// A second tun with an overlapping network fails rather than taking the first one's route
	tn2, err := newTun(config.NewC(l), l, []netip.Prefix{netip.MustParsePrefix("10.253.40.2/24")}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tn2.Close() })
	assert.ErrorIs(t, tn2.Activate(), unix.EEXIST)
	assert.Equal(t, tn.linkAddr.Index, routedThrough(networks[0]))
}
