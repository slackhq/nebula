//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reportedAddrs is what the lighthouse would hand a peer asking where vpnAddr is.
func reportedAddrs(t *testing.T, lh *nebula.Control, vpnAddr netip.Addr) []netip.AddrPort {
	t.Helper()
	cm := lh.QueryLighthouse(vpnAddr)
	if cm == nil {
		return nil
	}
	var out []netip.AddrPort
	for _, c := range *cm {
		out = append(out, c.Reported...)
		out = append(out, c.Learned...)
	}
	return out
}

// waitForLighthouseMsg routes until a lighthouse message lands on lh, or gives up. Reports whether one arrived.
func waitForLighthouseMsg(t *testing.T, r *router.R, lh *nebula.Control, wait time.Duration) bool {
	t.Helper()
	h := &header.H{}
	return r.RouteForAllExitFuncOrTimeout(wait, func(p *udp.Packet, c *nebula.Control) router.ExitType {
		if c != lh {
			return router.KeepRouting
		}
		// Punches are a single byte and never parse, they are just not what we are after
		if err := h.Parse(p.Data); err != nil {
			return router.KeepRouting
		}
		if h.Type == header.LightHouse {
			return router.RouteAndExit
		}
		return router.KeepRouting
	})
}

// A laptop that changes networks has to tell the lighthouse promptly, otherwise the lighthouse keeps handing peers
// the old address and their punches land nowhere. On a long lighthouse interval the only thing that closes that
// window is the rebind, which on darwin the network change monitor drives. The e2e build compiles the monitor out,
// so we call RebindUDPServer directly, which is the same thing the monitor does.
func TestRebindSendsLighthouseUpdate(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	lhControl, lhVpnIpNet, lhUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "lh", "10.128.0.1/24", m{
		"lighthouse": m{"am_lighthouse": true},
	})

	// 600s interval, so nothing scheduled can send an update during this test. A rebind is the only thing that can.
	myControl, _, _, _ := newSimpleServer(cert.Version2, ca, caKey, "me", "10.128.0.2/24", m{
		"lighthouse": m{
			"hosts":    []any{lhVpnIpNet[0].Addr().String()},
			"interval": 600,
		},
		"static_host_map": m{
			lhVpnIpNet[0].Addr().String(): []any{lhUdpAddr.String()},
		},
	})

	r := router.NewR(t, lhControl, myControl)
	defer r.RenderFlow()

	lhControl.Start()
	myControl.Start()

	// Let the startup registration finish, then clear everything it left behind
	require.True(t, waitForLighthouseMsg(t, r, lhControl, time.Second*5), "expected an initial registration")
	r.RouteFor(time.Millisecond * 400)

	// Nothing should be talking to the lighthouse on its own now
	require.False(t, waitForLighthouseMsg(t, r, lhControl, time.Millisecond*200),
		"nothing should reach the lighthouse before the rebind")

	myControl.RebindUDPServer()

	assert.True(t, waitForLighthouseMsg(t, r, lhControl, time.Second*5),
		"a rebind should push an update to the lighthouse rather than waiting out the interval")

	lhControl.Stop()
	myControl.Stop()
}

// The other half of a rebind: every live tunnel requeries the lighthouse on its next send. That query is what makes
// the lighthouse tell the peer to punch toward our new address, which is the part that actually revives a tunnel
// whose remote NAT state died while we were on a different network.
func TestRebindRequeriesPeersOnNextSend(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	lhControl, lhVpnIpNet, lhUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "lh", "10.128.0.1/24", m{
		"lighthouse": m{"am_lighthouse": true},
	})

	lhCfg := m{
		"lighthouse": m{
			"hosts":    []any{lhVpnIpNet[0].Addr().String()},
			"interval": 600,
			// Without this the peers advertise this machine's real addresses and then try to punch at them,
			// which the router has no route for.
			"local_allow_list": m{
				"10.0.0.0/24": true,
				"::/0":        false,
			},
		},
		"static_host_map": m{
			lhVpnIpNet[0].Addr().String(): []any{lhUdpAddr.String()},
		},
	}

	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "me", "10.128.0.2/24", lhCfg)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "them", "10.128.0.3/24", lhCfg)

	r := router.NewR(t, lhControl, myControl, theirControl)
	defer r.RenderFlow()

	lhControl.Start()
	myControl.Start()
	theirControl.Start()
	r.RouteFor(time.Millisecond * 500)

	// Point the peers at each other directly, this test is about the rebind and not about lighthouse discovery
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("initial")))
	r.RouteFor(time.Second)
	require.NotNil(t, myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false), "expected a tunnel to them")
	r.RouteFor(time.Millisecond * 300)

	// Assert on what the peer sees rather than on lighthouse traffic. A query for them makes the lighthouse send
	// them a punch notification, which is the whole point. Our own update to the lighthouse sends them nothing,
	// so this cannot be satisfied by the update the rebind itself pushes.
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("quiet")))
	require.False(t, waitForLighthouseMsg(t, r, theirControl, time.Millisecond*300),
		"an ordinary send should not requery the lighthouse")

	myControl.RebindUDPServer()
	r.RouteFor(time.Millisecond * 300) // let the update the rebind itself sends pass by

	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("after rebind")))
	assert.True(t, waitForLighthouseMsg(t, r, theirControl, time.Second*5),
		"the first send after a rebind should requery the lighthouse, which then tells the peer to punch at us")

	lhControl.Stop()
	myControl.Stop()
	theirControl.Stop()
}

// The scenario this whole thing exists for: a laptop sleeps at the office and wakes up at home on a new address.
// Until it tells the lighthouse, the lighthouse keeps handing peers the office address, so their punches land
// nowhere and the tunnel stays dead. On a long interval the rebind is the only thing that closes that window.
func TestRebindAdvertisesNewAddressAfterMove(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	lhControl, lhVpnIpNet, lhUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "lh", "10.128.0.1/24", m{
		"lighthouse": m{"am_lighthouse": true},
	})

	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "me", "10.128.0.2/24", m{
		"lighthouse": m{
			"hosts":    []any{lhVpnIpNet[0].Addr().String()},
			"interval": 600,
		},
		"static_host_map": m{
			lhVpnIpNet[0].Addr().String(): []any{lhUdpAddr.String()},
		},
	})

	// Advertise wherever we currently are rather than this machine's real NICs, read fresh each time so a move
	// is picked up.
	myControl.SetLocalAddrsFn(func(*nebula.LocalAllowList) []netip.Addr {
		return []netip.Addr{myControl.GetUDPAddr().Addr()}
	})

	r := router.NewR(t, lhControl, myControl)
	defer r.RenderFlow()

	lhControl.Start()
	myControl.Start()

	require.True(t, waitForLighthouseMsg(t, r, lhControl, time.Second*5), "expected an initial registration")
	r.RouteFor(time.Millisecond * 400)

	require.Contains(t, reportedAddrs(t, lhControl, myVpnIpNet[0].Addr()), myUdpAddr,
		"the lighthouse should know the address we started on")

	// Wake up somewhere else
	newAddr := netip.MustParseAddrPort("10.0.0.99:4242")
	myControl.SetUDPAddr(newAddr)
	r.AddRoute(newAddr.Addr(), newAddr.Port(), myControl)

	// Nothing has told the lighthouse, and with interval 600 nothing scheduled will
	r.RouteFor(time.Millisecond * 400)
	require.NotContains(t, reportedAddrs(t, lhControl, myVpnIpNet[0].Addr()), newAddr,
		"the lighthouse should still be handing out the old address before the rebind")

	myControl.RebindUDPServer()
	require.True(t, waitForLighthouseMsg(t, r, lhControl, time.Second*5), "expected an update after the rebind")
	r.RouteFor(time.Millisecond * 400)

	assert.Contains(t, reportedAddrs(t, lhControl, myVpnIpNet[0].Addr()), newAddr,
		"after the rebind the lighthouse should hand peers our new address")

	lhControl.Stop()
	myControl.Stop()
}
