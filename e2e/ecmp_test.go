//go:build e2e_testing

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ecmpVip = "192.168.6.10/32"

type ecmpNet struct {
	me, g1, g2 *nebula.Control
	myAddr     netip.Addr
	vip        netip.Addr
	gateways   []netip.Addr
	r          *router.R
	nextPort   uint16
}

// newECMPNet builds me with one route to a VIP through two gateways that both carry it as an unsafe network.
func newECMPNet(t *testing.T, myOverrides m) *ecmpNet {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	g1, g1Net, g1Udp, _ := newSimpleServerWithUdpAndUnsafeNetworks(cert.Version2, ca, caKey, "g1", "10.128.0.2/24", netip.MustParseAddrPort("10.64.0.2:4242"), ecmpVip, nil)
	g2, g2Net, g2Udp, _ := newSimpleServerWithUdpAndUnsafeNetworks(cert.Version2, ca, caKey, "g2", "10.128.0.3/24", netip.MustParseAddrPort("10.64.0.3:4242"), ecmpVip, nil)
	gateways := []netip.Addr{g1Net[0].Addr(), g2Net[0].Addr()}

	overrides := m{
		"tun": m{
			"unsafe_routes": []m{{
				"route": ecmpVip,
				"via":   []m{{"gateway": gateways[0].String()}, {"gateway": gateways[1].String()}},
			}},
		},
	}
	for k, v := range myOverrides {
		overrides[k] = v
	}
	me, myNet, _, _ := newSimpleServerWithUdp(cert.Version2, ca, caKey, "me", "10.128.0.1/24", netip.MustParseAddrPort("10.64.0.1:4242"), overrides)
	me.InjectLightHouseAddr(gateways[0], g1Udp)
	me.InjectLightHouseAddr(gateways[1], g2Udp)

	me.Start()
	g1.Start()
	g2.Start()
	t.Cleanup(func() {
		me.Stop()
		g1.Stop()
		g2.Stop()
	})

	return &ecmpNet{
		me:       me,
		g1:       g1,
		g2:       g2,
		myAddr:   myNet[0].Addr(),
		vip:      netip.MustParsePrefix(ecmpVip).Addr(),
		gateways: gateways,
		r:        router.NewR(t, me, g1, g2),
		nextPort: 20000,
	}
}

// portFor returns a source port not used before whose flow to the VIP hashes to gateways[idx].
func (n *ecmpNet) portFor(t *testing.T, idx int) uint16 {
	gws := make(routing.Gateways, len(n.gateways))
	for i, g := range n.gateways {
		gws[i] = routing.NewGateway(g, 1)
	}
	routing.CalculateBucketsForGateways(gws)
	for ; n.nextPort < 60000; n.nextPort++ {
		gw, _ := routing.BalancePacket(&firewall.Packet{LocalPort: n.nextPort, RemotePort: 80}, gws)
		if gw == n.gateways[idx] {
			n.nextPort++
			return n.nextPort - 1
		}
	}
	t.Fatal("no port hashes to the gateway")
	return 0
}

func (n *ecmpNet) send(port uint16, data string) {
	n.me.InjectTunPacket(BuildTunUDPPacket(n.vip, 80, n.myAddr, port, []byte(data)))
}

// route delivers packets until a data message reaches want or timeout passes, dropping everything sent to or from the
// controls in drop. It returns whether want got a data message, and how many data messages went to other controls.
func (n *ecmpNet) route(timeout time.Duration, want *nebula.Control, drop ...*nebula.Control) (bool, int) {
	h := &header.H{}
	others := 0
	got := n.r.RouteForAllExitFuncOrTimeout(timeout, func(p *udp.Packet, to *nebula.Control) router.ExitType {
		for _, d := range drop {
			if to == d || p.From == d.GetUDPAddr() {
				return router.Drop
			}
		}
		if err := h.Parse(p.Data); err != nil {
			panic(err)
		}
		if h.Type == header.Message && h.Subtype == header.MessageNone {
			if to == want {
				return router.RouteAndExit
			}
			others++
		}
		return router.KeepRouting
	})
	return got, others
}

// routeUntil routes, dropping everything sent to or from the controls in drop, until done reports true. It returns how many
// data messages were delivered meanwhile.
func (n *ecmpNet) routeUntil(t *testing.T, done func() bool, drop ...*nebula.Control) int {
	deadline := time.Now().Add(10 * time.Second)
	delivered := 0
	for !done() {
		require.True(t, time.Now().Before(deadline), "timed out waiting for routing condition")
		_, others := n.route(20*time.Millisecond, nil, drop...)
		delivered += others
	}
	return delivered
}

// timeOutG2 waits, with g2 unreachable, for a handshake with g2 to start and then time out. It returns how many data
// messages were delivered meanwhile.
func (n *ecmpNet) timeOutG2(t *testing.T) int {
	pending := func() bool { return n.me.HasPendingHandshake(n.gateways[1]) }
	delivered := n.routeUntil(t, pending, n.g2)
	return delivered + n.routeUntil(t, func() bool { return !pending() }, n.g2)
}

// warmG1 stands up a tunnel to g1 only, so that g2 is the gateway without one.
func (n *ecmpNet) warmG1(t *testing.T) {
	port := n.portFor(t, 0)
	n.send(port, "warm")
	got, _ := n.route(5*time.Second, n.g1, n.g2)
	require.True(t, got, "warm packet never reached g1")
	assertUdpPacket(t, []byte("warm"), n.g1.GetFromTun(true), n.myAddr, n.vip, port, 80)
	// Clear any handshake with g2 the warm packet started, so g2 starts with no tunnel and no handshake
	n.me.KillPendingTunnel(n.gateways[1])
}

func TestECMPHoldsPacketsForHashedGateway(t *testing.T) {
	t.Parallel()
	n := newECMPNet(t, nil)
	defer n.r.RenderFlow()
	n.warmG1(t)

	t.Log("A flow that hashes to g2, which has no tunnel yet, waits for g2 rather than going to g1")
	port := n.portFor(t, 1)
	n.send(port, "first")
	got, others := n.route(5*time.Second, n.g2)
	require.True(t, got, "first packet never reached g2")
	assert.Zero(t, others, "first packet went to another gateway")
	assertUdpPacket(t, []byte("first"), n.g2.GetFromTun(true), n.myAddr, n.vip, port, 80)

	t.Log("The rest of the flow follows it to g2")
	n.send(port, "second")
	got, others = n.route(5*time.Second, n.g2)
	require.True(t, got, "second packet never reached g2")
	assert.Zero(t, others, "second packet went to another gateway")
	assertUdpPacket(t, []byte("second"), n.g2.GetFromTun(true), n.myAddr, n.vip, port, 80)
}

func TestECMPFallsBackAfterHashedGatewayTimesOut(t *testing.T) {
	t.Parallel()
	n := newECMPNet(t, m{"handshakes": m{"try_interval": "100ms", "retries": 2}})
	defer n.r.RenderFlow()
	n.warmG1(t)

	t.Log("While g2 is unreachable, a flow that hashes to it is held for g2's handshake, never sent to g1")
	n.send(n.portFor(t, 1), "held")
	assert.Zero(t, n.timeOutG2(t), "held packet went to g1")

	t.Log("Once g2's handshake has timed out, new flows that hash to g2 go to g1 right away")
	port := n.portFor(t, 1)
	n.send(port, "fallback")
	got, _ := n.route(time.Second, n.g1, n.g2)
	require.True(t, got, "fallback packet never reached g1")
	assertUdpPacket(t, []byte("fallback"), n.g1.GetFromTun(true), n.myAddr, n.vip, port, 80)

	t.Log("When g2 is reachable again, the handshake the fallback started completes and flows that hash to g2 go to it")
	n.routeUntil(t, func() bool { return n.me.HasTunnel(n.gateways[1]) })
	port = n.portFor(t, 1)
	n.send(port, "recovered")
	got, others := n.route(5*time.Second, n.g2)
	require.True(t, got, "packet after recovery never reached g2")
	assert.Zero(t, others, "packet after recovery went to another gateway")
	assertUdpPacket(t, []byte("recovered"), n.g2.GetFromTun(true), n.myAddr, n.vip, port, 80)
}

func TestECMPDownGatewayRecoversOnFirstFlow(t *testing.T) {
	t.Parallel()
	n := newECMPNet(t, m{"handshakes": m{"try_interval": "100ms", "retries": 2}})
	defer n.r.RenderFlow()
	n.warmG1(t)

	t.Log("g2's handshake times out while g2 is unreachable")
	n.send(n.portFor(t, 1), "held")
	n.timeOutG2(t)

	t.Log("g2 comes back while nothing is sent to it, so it is still down to us")
	n.r.RouteFor(time.Second)

	t.Log("The next flow that hashes to g2 goes to g1, and starts the handshake that marks g2 up")
	// This is the one-handshake window ecmpGateways documents: a flow started here is split if it outlives the
	// handshake, since its later packets go to g2
	port := n.portFor(t, 1)
	n.send(port, "noticed")
	got, _ := n.route(time.Second, n.g1)
	require.True(t, got, "packet never reached g1")
	assertUdpPacket(t, []byte("noticed"), n.g1.GetFromTun(true), n.myAddr, n.vip, port, 80)
	n.routeUntil(t, func() bool { return n.me.HasTunnel(n.gateways[1]) })

	t.Log("Flows after that go to g2")
	port = n.portFor(t, 1)
	n.send(port, "recovered")
	got, others := n.route(5*time.Second, n.g2)
	require.True(t, got, "packet never reached g2")
	assert.Zero(t, others, "packet went to another gateway after g2 recovered")
	assertUdpPacket(t, []byte("recovered"), n.g2.GetFromTun(true), n.myAddr, n.vip, port, 80)
}

func TestECMPFallsBackRightAwayWhenTunnelDies(t *testing.T) {
	t.Parallel()
	n := newECMPNet(t, nil)
	defer n.r.RenderFlow()
	n.warmG1(t)

	t.Log("Stand up a tunnel to g2 as well")
	port := n.portFor(t, 1)
	n.send(port, "warm")
	got, _ := n.route(5*time.Second, n.g2)
	require.True(t, got, "warm packet never reached g2")
	assertUdpPacket(t, []byte("warm"), n.g2.GetFromTun(true), n.myAddr, n.vip, port, 80)

	t.Log("g2 becomes unreachable with its tunnel up, and the connection manager finds the tunnel dead")
	n.send(port, "lost")
	n.routeUntil(t, func() bool { return !n.me.HasTunnel(n.gateways[1]) }, n.g2)

	t.Log("New flows that hash to g2 go to g1 right away, without waiting for a handshake with g2 to time out")
	port = n.portFor(t, 1)
	n.send(port, "fallback")
	got, _ = n.route(time.Second, n.g1, n.g2)
	require.True(t, got, "packet waited for g2 after its tunnel was found dead")
	assertUdpPacket(t, []byte("fallback"), n.g1.GetFromTun(true), n.myAddr, n.vip, port, 80)
}
