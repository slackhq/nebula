//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/handshake/fragment"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const hybridCurve = cert.Curve_P384_MLKEM1024_MLDSA87

// hybridConfig is the config every hybrid node in these tests starts from: repair fragments go right behind the data,
// which keeps the router's packet order deterministic.
func hybridConfig() m {
	return m{"handshakes": m{"repair_delay": "0s"}}
}

// isHybrid reports whether h is a hybrid handshake packet, a fragment or a cookie reply.
func isHybrid(h *header.H) bool {
	return h != nil && (h.Subtype == header.HandshakeIXHybrid || h.Subtype == header.HandshakeIXHybridFragmented)
}

// hybridTally counts handshake packets by pattern and message.
type hybridTally struct {
	sync.Mutex
	hybrid, classical int
	msg3              int
	maxLen            int
}

func (ht *hybridTally) observe(p *udp.Packet) {
	h, _ := handshakeOf(p)
	if h == nil {
		return
	}
	ht.Lock()
	defer ht.Unlock()
	if isHybrid(h) {
		ht.hybrid++
		ht.maxLen = max(ht.maxLen, len(p.Data))
		if h.MessageCounter == 3 {
			ht.msg3++
		}
	} else {
		ht.classical++
	}
}

func isType(p *udp.Packet, t header.MessageType) bool {
	h := &header.H{}
	return h.Parse(p.Data) == nil && h.Type == t
}

func isRelayed(p *udp.Packet) bool {
	outer := &header.H{}
	return outer.Parse(p.Data) == nil && outer.Type == header.Message && outer.Subtype == header.MessageRelay
}

// hybridCA signs the certificates of hybrid nodes.
type hybridCA struct {
	ca  cert.Certificate
	key []byte
}

func newHybridCA(t *testing.T) hybridCA {
	t.Helper()
	if err := cert.HybridAvailable(); err != nil {
		t.Skip(err)
	}
	now := time.Now()
	c, _, key, _ := cert_test.NewTestCaCert(cert.Version2, hybridCurve, now, now.Add(10*time.Minute), nil, nil, []string{})
	return hybridCA{ca: c, key: key}
}

// server starts a node on the hybrid curve, with a v2 hybrid certificate signed by the CA, which it trusts.
func (ca hybridCA) server(name, network string, overrides m) (*nebula.Control, []netip.Prefix, netip.AddrPort) {
	nets := []netip.Prefix{netip.MustParsePrefix(network)}
	c, _, keyPEM, _ := cert_test.NewTestCert(cert.Version2, hybridCurve, ca.ca, ca.key, name, ca.ca.NotBefore(), ca.ca.NotAfter(), nets, nil, []string{})
	control, vpn, udpAddr, _ := newServer([]cert.Certificate{ca.ca}, []cert.Certificate{c}, keyPEM, overrides)
	return control, vpn, udpAddr
}

// newHybridPair builds two hybrid nodes, me initiating to them.
func newHybridPair(t *testing.T, mine, theirs m) (myControl, theirControl *nebula.Control, myVpn, theirVpn []netip.Prefix, myUdp, theirUdp netip.AddrPort, r *router.R) {
	t.Helper()
	ca := newHybridCA(t)
	myControl, myVpn, myUdp = ca.server("me", "10.128.0.1/24", mine)
	theirControl, theirVpn, theirUdp = ca.server("them", "10.128.0.2/24", theirs)
	myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
	r = router.NewR(t, myControl, theirControl)
	myControl.Start()
	theirControl.Start()
	return
}

// routeUntilTunnelData routes until tunnel data reaches to. fn sees every packet first, and anything but KeepRouting
// from it is what happens to the packet.
func routeUntilTunnelData(t *testing.T, r *router.R, to *nebula.Control, timeout time.Duration, fn func(p *udp.Packet, receiver *nebula.Control) router.ExitType) bool {
	t.Helper()
	return r.RouteForAllExitFuncOrTimeout(timeout, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		if fn != nil {
			if e := fn(p, receiver); e != router.KeepRouting {
				return e
			}
		}
		if isTunnelData(p, receiver, to) {
			return router.RouteAndExit
		}
		return router.KeepRouting
	})
}

// peerCurve is the curve of the certificate c's tunnel to vpnAddr was made with.
func peerCurve(t *testing.T, c *nebula.Control, vpnAddr netip.Addr) cert.Curve {
	t.Helper()
	hi := c.GetHostInfoByVpnAddr(vpnAddr, false)
	require.NotNil(t, hi)
	return hi.Cert.Curve()
}

func TestHybridHandshake(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, myUdp, theirUdp, r := newHybridPair(t, hybridConfig(), hybridConfig())
	defer r.RenderFlow()

	var tally hybridTally
	var recvErrors int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilTunnelData(t, r, theirControl, 5*time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		tally.observe(p)
		if isType(p, header.RecvError) {
			recvErrors++
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Zero(t, tally.classical, "a hybrid node makes hybrid handshakes only")
	assert.GreaterOrEqual(t, tally.hybrid, 8+9+2, "all three messages travel as several fragments")
	assert.Positive(t, tally.msg3)
	assert.LessOrEqual(t, tally.maxLen, fragment.MaxPacketLen)
	assert.Zero(t, recvErrors)

	assertHostInfoPair(t, myUdp, theirUdp, myVpn, theirVpn, myControl, theirControl)
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)
	for _, c := range []*nebula.Control{myControl, theirControl} {
		assert.Empty(t, c.ListHostmapIndexes(true), "no pending index may outlive the handshake")
	}
	assert.Equal(t, hybridCurve, peerCurve(t, myControl, theirVpn[0].Addr()))
	assert.Equal(t, hybridCurve, peerCurve(t, theirControl, myVpn[0].Addr()))

	myControl.Stop()
	theirControl.Stop()
}

// TestHybridFragmentNever checks handshakes.fragment: never, which only covers classical handshakes, does not stop a
// hybrid one: it has no unfragmented form.
func TestHybridFragmentNever(t *testing.T) {
	t.Parallel()
	never := func() m { return m{"handshakes": m{"repair_delay": "0s", "fragment": "never"}} }
	myControl, theirControl, myVpn, theirVpn, _, _, r := newHybridPair(t, never(), never())
	defer r.RenderFlow()

	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilTunnelData(t, r, theirControl, 5*time.Second, nil), "tunnel never came up")
	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Equal(t, hybridCurve, peerCurve(t, myControl, theirVpn[0].Addr()))

	myControl.Stop()
	theirControl.Stop()
}

// TestHybridAndClassicalNeverMeet has a classical node and a hybrid node try to reach each other, each way. Curves
// never mix in a handshake, so each side's msg1 goes unanswered and neither ends up with a tunnel.
func TestHybridAndClassicalNeverMeet(t *testing.T) {
	t.Parallel()
	hca := newHybridCA(t)
	now := time.Now()
	cca, _, ccaKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, now, now.Add(10*time.Minute), nil, nil, []string{})
	// Each trusts both CAs, so only the curves keep them apart.
	trustBoth := func() m {
		cfg := hybridConfig()
		b1, _ := hca.ca.MarshalPEM()
		b2, _ := cca.MarshalPEM()
		cfg["pki"] = m{"ca": string(b1) + string(b2)}
		return cfg
	}
	hybridControl, hybridVpn, hybridUdp := hca.server("hybrid", "10.128.0.1/24", trustBoth())
	classicalCert, _, classicalKey, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, cca, ccaKey, "classical", cca.NotBefore(), cca.NotAfter(), []netip.Prefix{netip.MustParsePrefix("10.128.0.2/24")}, nil, []string{})
	classicalControl, classicalVpn, classicalUdp, _ := newServer([]cert.Certificate{cca, hca.ca}, []cert.Certificate{classicalCert}, classicalKey, trustBoth())
	hybridControl.InjectLightHouseAddr(classicalVpn[0].Addr(), classicalUdp)
	classicalControl.InjectLightHouseAddr(hybridVpn[0].Addr(), hybridUdp)
	r := router.NewR(t, hybridControl, classicalControl)
	defer r.RenderFlow()
	hybridControl.Start()
	classicalControl.Start()

	var tally hybridTally
	var msg2 int
	route := func(to *nebula.Control) bool {
		return routeUntilTunnelData(t, r, to, time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
			tally.observe(p)
			if h, _ := handshakeOf(p); h != nil && h.MessageCounter >= 2 {
				msg2++
			}
			return router.KeepRouting
		})
	}

	hybridControl.InjectTunPacket(BuildTunUDPPacket(classicalVpn[0].Addr(), 80, hybridVpn[0].Addr(), 80, []byte("Hi from hybrid")))
	assert.False(t, route(classicalControl), "a hybrid node can not reach a classical one")
	classicalControl.InjectTunPacket(BuildTunUDPPacket(hybridVpn[0].Addr(), 80, classicalVpn[0].Addr(), 80, []byte("Hi from classical")))
	assert.False(t, route(hybridControl), "nor the other way around")

	assert.Positive(t, tally.hybrid, "the hybrid node tried")
	assert.Positive(t, tally.classical, "the classical node tried")
	assert.Zero(t, msg2, "neither msg1 was answered")
	assert.Nil(t, hybridControl.GetHostInfoByVpnAddr(classicalVpn[0].Addr(), false))
	assert.Nil(t, classicalControl.GetHostInfoByVpnAddr(hybridVpn[0].Addr(), false))

	hybridControl.Stop()
	classicalControl.Stop()
}

// TestHybridConfirmationLost loses the responder's confirmation. The initiator keeps resending msg3, and the responder,
// already done, confirms again rather than leave the initiator to tear the tunnel down.
func TestHybridConfirmationLost(t *testing.T) {
	t.Parallel()
	// Three retries make the handshake timeout 400ms, so the wait below outlasts it.
	mine := hybridConfig()
	mine["handshakes"].(m)["retries"] = 3
	myControl, theirControl, myVpn, theirVpn, _, _, r := newHybridPair(t, mine, hybridConfig())
	defer r.RenderFlow()

	var tally hybridTally
	var droppedConfirms, confirms int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	r.RouteForAllExitFuncOrTimeout(2*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		tally.observe(p)
		if receiver == myControl && isType(p, header.Test) {
			if droppedConfirms == 0 {
				droppedConfirms++
				return router.Drop
			}
			confirms++
			return router.RouteAndExit
		}
		return router.KeepRouting
	})

	assert.Equal(t, 1, droppedConfirms)
	assert.Positive(t, confirms, "the responder confirms again")
	assert.Greater(t, tally.msg3, 4, "msg3 was resent with fresh symbols")
	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)

	// Long past the handshake timeout, the tunnel must still be there.
	time.Sleep(700 * time.Millisecond)
	r.FlushAll()
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

// TestHybridNeverConfirmed loses every msg3. The responder never completes, must not answer the initiator's data with
// RecvErrors meanwhile, and the initiator closes the tunnel at the handshake timeout.
func TestHybridNeverConfirmed(t *testing.T) {
	t.Parallel()
	mine := hybridConfig()
	mine["handshakes"].(m)["retries"] = 3
	theirs := hybridConfig()
	theirs["handshakes"].(m)["retries"] = 3
	myControl, theirControl, myVpn, theirVpn, _, _, r := newHybridPair(t, mine, theirs)
	defer r.RenderFlow()

	var recvErrors, dropped int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	r.RouteForAllExitFuncOrTimeout(1500*time.Millisecond, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		if h, fh := handshakeOf(p); fh != nil && h.MessageCounter == 3 {
			dropped++
			return router.Drop
		}
		if isType(p, header.RecvError) {
			recvErrors++
		}
		return router.KeepRouting
	})

	assert.Greater(t, dropped, 4, "msg3 is resent")
	assert.Zero(t, recvErrors, "data for a pending responder is dropped quietly")
	assert.Nil(t, theirControl.GetHostInfoByVpnAddr(myVpn[0].Addr(), false), "the responder never completes")
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(theirVpn[0].Addr(), false), "the initiator gave up on the tunnel")
	assert.Empty(t, theirControl.ListHostmapIndexes(true), "the pending responder expired")

	myControl.Stop()
	theirControl.Stop()
}

func TestHybridRelays(t *testing.T) {
	t.Parallel()
	ca := newHybridCA(t)
	useRelays := hybridConfig()
	useRelays["relay"] = m{"use_relays": true}
	amRelay := hybridConfig()
	amRelay["relay"] = m{"am_relay": true}
	myControl, myVpnIpNet, _ := ca.server("me     ", "10.128.0.1/24", useRelays)
	relayControl, relayVpnIpNet, relayUdpAddr := ca.server("relay  ", "10.128.0.128/24", amRelay)
	theirControl, theirVpnIpNet, theirUdpAddr := ca.server("them   ", "10.128.0.2/24", useRelays)

	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	var relayedMsg3, relayedClassical int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilTunnelData(t, r, theirControl, 10*time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		if isRelayed(p) {
			if h, fh := handshakeOf(p); isHybrid(h) && fh != nil {
				assert.LessOrEqual(t, len(p.Data), fragment.MaxPacketLen+32, "a relayed fragment fits the IPv6 minimum MTU")
				if h.MessageCounter == 3 {
					relayedMsg3++
				}
			} else if h != nil {
				relayedClassical++
			}
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	assert.Positive(t, relayedMsg3, "msg3 goes through the relay too")
	assert.Zero(t, relayedClassical)
	assert.Equal(t, hybridCurve, peerCurve(t, myControl, theirVpnIpNet[0].Addr()))
	r.RenderHostmaps("Final hostmaps", myControl, relayControl, theirControl)

	myControl.Stop()
	relayControl.Stop()
	theirControl.Stop()
}

// TestHybridBackToBack rebuilds the tunnel more times than the responder's per-source quota allows messages in
// progress, faster than its table expires entries. The repair fragments trailing each completed msg1 must not count
// against that quota, or later handshakes stall.
func TestHybridBackToBack(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, _, theirUdp, r := newHybridPair(t, hybridConfig(), hybridConfig())
	defer r.RenderFlow()

	for i := range 6 {
		// Closing the last tunnel forgets the peer's address.
		myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
		myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
		require.True(t, routeUntilTunnelData(t, r, theirControl, 5*time.Second, nil), "tunnel %d never came up", i)
		theirControl.GetFromTun(true)
		// Let the trailing repair fragments land before tearing down.
		r.RouteForAllExitFuncOrTimeout(50*time.Millisecond, func(*udp.Packet, *nebula.Control) router.ExitType { return router.KeepRouting })

		assert.Equal(t, hybridCurve, peerCurve(t, myControl, theirVpn[0].Addr()), "tunnel %d is hybrid", i)
		assert.Equal(t, hybridCurve, peerCurve(t, theirControl, myVpn[0].Addr()), "tunnel %d is hybrid", i)

		myControl.CloseTunnel(theirVpn[0].Addr(), true)
		theirControl.CloseTunnel(myVpn[0].Addr(), true)
	}

	myControl.Stop()
	theirControl.Stop()
}

// TestHybridWrongResponder gives the initiator a stale address for its peer that belongs to another hybrid host now,
// so both answer its msg1. Their msg2 bursts interleave at the initiator and each must fill its own slot: the tunnel to
// the right host comes up within two attempts, one if its answer completes first and two if the other host's does,
// which the initiator blocks and retries past. A single slot that emptied on every FragID change would run to the
// handshake timeout.
func TestHybridWrongResponder(t *testing.T) {
	t.Parallel()
	ca := newHybridCA(t)
	myControl, myVpn, myUdp := ca.server("me", "10.128.0.1/24", hybridConfig())
	theirControl, theirVpn, theirUdp := ca.server("them", "10.128.0.2/24", hybridConfig())
	otherControl, otherVpn, otherUdp := ca.server("other", "10.128.0.3/24", hybridConfig())
	myControl.InjectLightHouseAddr(theirVpn[0].Addr(), otherUdp)
	myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)

	r := router.NewR(t, myControl, theirControl, otherControl)
	defer r.RenderFlow()
	myControl.Start()
	theirControl.Start()
	otherControl.Start()

	msg2ByFragID := map[uint32]int{}
	var classical []string
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilTunnelData(t, r, theirControl, 5*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		if h, fh := handshakeOf(p); h != nil {
			switch {
			case !isHybrid(h):
				classical = append(classical, fmt.Sprintf("counter=%d to=%s", h.MessageCounter, p.To))
			case fh == nil:
			case h.MessageCounter == 2 && receiver == myControl:
				msg2ByFragID[fh.FragID]++
			}
		}
		return router.KeepRouting
	}), "tunnel never came up")
	t.Logf("msg2 fragments by FragID: %v", msg2ByFragID)

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.GreaterOrEqual(t, len(msg2ByFragID), 2, "both hosts answered")
	// A responder only resends msg2 when the initiator retries, so every FragID staying at one burst means each
	// interleaved answer completed in its own slot.
	for fragID, n := range msg2ByFragID {
		assert.LessOrEqual(t, n, 9+3, "responder %d had to resend msg2", fragID)
	}
	assert.Empty(t, classical, "a hybrid node never offers a classical attempt")

	assertHostInfoPair(t, myUdp, theirUdp, myVpn, theirVpn, myControl, theirControl)
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(otherVpn[0].Addr(), false), "no tunnel to the other host")
	assert.Empty(t, myControl.ListHostmapIndexes(true), "no pending index may outlive the handshake")

	myControl.Stop()
	theirControl.Stop()
	otherControl.Stop()
}

// relayedHybridNodes starts me, a relay and them, all hybrid, with me knowing them directly and through the relay.
func relayedHybridNodes(t *testing.T, mine m) (myControl, relayControl, theirControl *nebula.Control, myVpn, theirVpn []netip.Prefix, myUdp, theirUdp netip.AddrPort, r *router.R) {
	t.Helper()
	ca := newHybridCA(t)
	useRelays := mine
	useRelays["relay"] = m{"use_relays": true}
	theirs := hybridConfig()
	theirs["relay"] = m{"use_relays": true}
	amRelay := hybridConfig()
	amRelay["relay"] = m{"am_relay": true}
	myControl, myVpn, myUdp = ca.server("me     ", "10.128.0.1/24", useRelays)
	relayControl, relayVpn, relayUdp := ca.server("relay  ", "10.128.0.128/24", amRelay)
	theirControl, theirVpn, theirUdp = ca.server("them   ", "10.128.0.2/24", theirs)

	myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
	myControl.InjectLightHouseAddr(relayVpn[0].Addr(), relayUdp)
	myControl.InjectRelays(theirVpn[0].Addr(), []netip.Addr{relayVpn[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)

	r = router.NewR(t, myControl, relayControl, theirControl)
	myControl.Start()
	relayControl.Start()
	theirControl.Start()
	return
}

// TestHybridMsg2LostDirect loses every msg2 fragment the responder sends directly, as a responder answering from the
// wrong interface would. msg1 also reaches it through a relay, and that copy must be answered on the relay as soon as
// it completes, not refused because the direct copy was just answered.
func TestHybridMsg2LostDirect(t *testing.T) {
	t.Parallel()
	myControl, relayControl, theirControl, myVpn, theirVpn, _, theirUdp, r := relayedHybridNodes(t, hybridConfig())
	defer r.RenderFlow()

	var relayedMsg1, directMsg2, relayedMsg2 int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilTunnelData(t, r, theirControl, 10*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		h, fh := handshakeOf(p)
		if !isHybrid(h) || fh == nil {
			return router.KeepRouting
		}
		relayed := isRelayed(p)
		switch {
		case h.MessageCounter == 1 && relayed && receiver == theirControl:
			relayedMsg1++
		case h.MessageCounter == 2 && !relayed && p.From == theirUdp && receiver == myControl:
			directMsg2++
			return router.Drop
		case h.MessageCounter == 2 && relayed && receiver == myControl:
			relayedMsg2++
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.GreaterOrEqual(t, directMsg2, 9, "the direct answer was sent and lost")
	assert.GreaterOrEqual(t, relayedMsg2, 9, "the relayed copy of msg1 got its own answer")
	assert.LessOrEqual(t, relayedMsg1, 8+3, "the first copy of msg1 through the relay is answered, no relayed retry is needed")

	myControl.Stop()
	relayControl.Stop()
	theirControl.Stop()
}

// TestHybridOneWayDirect loses everything the responder sends directly, not just msg2, so only the relay carries
// anything back. msg3 comes by the relay, since that is where msg2 got through, and the responder must then send by the
// relay too: its confirmation, and its replies.
func TestHybridOneWayDirect(t *testing.T) {
	t.Parallel()
	mine := hybridConfig()
	// The relay takes about a second to come up in this harness; 8 retries make the handshake timeout 3.6s, which the
	// end of the test waits out.
	mine["handshakes"].(m)["retries"] = 8
	myControl, relayControl, theirControl, myVpn, theirVpn, _, theirUdp, r := relayedHybridNodes(t, mine)
	defer r.RenderFlow()

	oneWay := func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		if p.From == theirUdp && receiver == myControl {
			return router.Drop
		}
		return router.KeepRouting
	}

	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilTunnelData(t, r, theirControl, 10*time.Second, oneWay), "tunnel never came up")
	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)

	theirControl.InjectTunPacket(BuildTunUDPPacket(myVpn[0].Addr(), 80, theirVpn[0].Addr(), 80, []byte("Hi from them")))
	require.True(t, routeUntilTunnelData(t, r, myControl, 3*time.Second, oneWay), "the reply never came back")
	assertUdpPacket(t, []byte("Hi from them"), myControl.GetFromTun(true), theirVpn[0].Addr(), myVpn[0].Addr(), 80, 80)

	// Well past the handshake timeout, the initiator must still have the tunnel.
	r.RouteForAllExitFuncOrTimeout(4*time.Second, oneWay)
	require.NotNil(t, myControl.GetHostInfoByVpnAddr(theirVpn[0].Addr(), false), "the initiator heard back, so it kept the tunnel")
	assert.Equal(t, hybridCurve, peerCurve(t, myControl, theirVpn[0].Addr()))

	myControl.Stop()
	relayControl.Stop()
	theirControl.Stop()
}

// TestHybridRelayPromotion has msg2 complete by the relay although the direct path works both ways, as it often does
// on real networks where the tunnel to the relay is already up and the direct path still needs a punch. Both ends
// start relayed, and the usual promotion moves them to direct.
func TestHybridRelayPromotion(t *testing.T) {
	t.Parallel()
	mine := hybridConfig()
	mine["counters"] = m{"try_promote": 5}
	myControl, relayControl, theirControl, myVpn, theirVpn, myUdp, theirUdp, r := relayedHybridNodes(t, mine)
	defer r.RenderFlow()
	t.Cleanup(func() {
		myControl.Stop()
		relayControl.Stop()
		theirControl.Stop()
	})

	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("first")))
	require.True(t, routeUntilTunnelData(t, r, theirControl, 10*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		if h, fh := handshakeOf(p); isHybrid(h) && fh != nil && h.MessageCounter == 2 && !isRelayed(p) && p.From == theirUdp && receiver == myControl {
			return router.Drop
		}
		return router.KeepRouting
	}), "tunnel never came up")
	theirControl.GetFromTun(true)

	theirs := theirControl.GetHostInfoByVpnAddr(myVpn[0].Addr(), false)
	require.NotNil(t, theirs)
	assert.False(t, theirs.CurrentRemote.IsValid(), "msg3 came by the relay, so the responder starts relayed")
	assert.Equal(t, hybridCurve, theirs.Cert.Curve())

	route := func(to *nebula.Control) bool {
		return routeUntilTunnelData(t, r, to, 300*time.Millisecond, nil)
	}
	var toThem, toMe int
	for range 20 {
		myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("to them")))
		if route(theirControl) {
			theirControl.GetFromTun(true)
			toThem++
		}
		theirControl.InjectTunPacket(BuildTunUDPPacket(myVpn[0].Addr(), 80, theirVpn[0].Addr(), 80, []byte("to me")))
		if route(myControl) {
			myControl.GetFromTun(true)
			toMe++
		}
	}
	assert.Equal(t, 20, toThem)
	assert.Equal(t, 20, toMe)
	assert.Equal(t, theirUdp, myControl.GetHostInfoByVpnAddr(theirVpn[0].Addr(), false).CurrentRemote, "the initiator promoted to direct")
	assert.Equal(t, myUdp, theirControl.GetHostInfoByVpnAddr(myVpn[0].Addr(), false).CurrentRemote, "the responder promoted to direct")
}

// TestHybridHandshakeLoss drops data fragments of both messages; the repair fragments must carry the handshake without
// a retry.
func TestHybridHandshakeLoss(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, _, _, r := newHybridPair(t, hybridConfig(), hybridConfig())
	defer r.RenderFlow()

	var msg1Fragments int
	dropped := 0
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilTunnelData(t, r, theirControl, 5*time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		if h, fh := handshakeOf(p); isHybrid(h) && fh != nil {
			// Two data fragments of msg1, and the first of msg2.
			if (h.MessageCounter == 1 && int(fh.Index) < 2) || (h.MessageCounter == 2 && fh.Index == 0) {
				dropped++
				return router.Drop
			}
			if h.MessageCounter == 1 {
				msg1Fragments++
			}
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Equal(t, 3, dropped)
	assert.Equal(t, 8+3-2, msg1Fragments, "the first attempt should succeed from repair fragments, with no retry")
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

// TestHybridResendFreshSymbols loses the responder's whole first msg2. The initiator's retry offers fresh msg1 symbols,
// the pending responder recognises the repeat and resends msg2 with symbols it has not sent before.
func TestHybridResendFreshSymbols(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, _, _, r := newHybridPair(t, hybridConfig(), hybridConfig())
	defer r.RenderFlow()

	var firstMsg2, freshMsg2, freshMsg1 int
	fragIDs := map[uint32]bool{}
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilTunnelData(t, r, theirControl, 10*time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		h, fh := handshakeOf(p)
		switch {
		case fh != nil && h.MessageCounter == 2 && fh.Index < 12:
			fragIDs[fh.FragID] = true
			firstMsg2++
			return router.Drop
		case fh != nil && h.MessageCounter == 2:
			fragIDs[fh.FragID] = true
			freshMsg2++
		case fh != nil && h.MessageCounter == 1 && fh.Index >= 11:
			freshMsg1++
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Equal(t, 12, firstMsg2, "the first msg2 is 9 data and 3 repair fragments")
	assert.Positive(t, freshMsg1, "the retry offers fresh msg1 symbols")
	assert.Positive(t, freshMsg2, "the resend offers fresh msg2 symbols")
	assert.Len(t, fragIDs, 1, "the retry is answered by the same pending responder, not a second one")
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)
	assert.Empty(t, theirControl.ListHostmapIndexes(true))

	myControl.Stop()
	theirControl.Stop()
}

// TestHybridTimeoutReleasesIndexes lets a hybrid handshake time out, and checks no index is left behind on either side.
func TestHybridTimeoutReleasesIndexes(t *testing.T) {
	t.Parallel()
	mine := hybridConfig()
	mine["handshakes"].(m)["retries"] = 2
	theirs := hybridConfig()
	theirs["handshakes"].(m)["retries"] = 2
	myControl, theirControl, myVpn, theirVpn, _, _, r := newHybridPair(t, mine, theirs)
	defer r.RenderFlow()

	var tally hybridTally
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	r.RouteForAllExitFuncOrTimeout(1500*time.Millisecond, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		tally.observe(p)
		// msg1 gets through, every answer is lost.
		if receiver == myControl {
			return router.Drop
		}
		return router.KeepRouting
	})

	assert.Positive(t, tally.hybrid)
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(theirVpn[0].Addr(), true), "the handshake should have timed out")
	assert.Empty(t, myControl.ListHostmapIndexes(true))
	assert.Empty(t, theirControl.ListHostmapIndexes(true), "the pending responder expired")

	myControl.Stop()
	theirControl.Stop()
}

// TestHybridCookieUnderLoad floods the responder with msg1 fragments from spoofed sources until it demands cookies,
// then checks a real initiator picks up the cookie and still completes the hybrid handshake.
func TestHybridCookieUnderLoad(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, _, theirUdp, r := newHybridPair(t, hybridConfig(), hybridConfig())
	defer r.RenderFlow()

	// Half of the 1024 entry table is the cookie threshold. Stopping exactly there keeps them from answering the
	// spoofed sources, which the router cannot reach.
	t.Log("Flood them with the first fragment of msg1s nobody will finish")
	for i := range 512 {
		from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 4242)
		pkt := header.Encode(make([]byte, header.Len, header.Len+2000), header.Version, header.Handshake, header.HandshakeIXHybrid, 0, 1)
		s, err := fragment.NewSender(append(pkt, make([]byte, 2000)...), uint32(i+1))
		require.NoError(t, err)
		pkts, _, err := s.Attempt(0)
		require.NoError(t, err)
		theirControl.InjectUDPPacket(&udp.Packet{From: from, To: theirUdp, Data: pkts[0]})
	}

	var cookieReplies, msg2, withCookie int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilTunnelData(t, r, theirControl, 5*time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		if h, fh := handshakeOf(p); isHybrid(h) {
			switch {
			case h.MessageCounter == 0:
				cookieReplies++
			case h.MessageCounter == 2:
				msg2++
			case fh != nil && fh.HasCookie():
				withCookie++
			}
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Positive(t, cookieReplies, "a loaded responder asks for a cookie")
	assert.Positive(t, withCookie, "the initiator resends with it")
	assert.Positive(t, msg2, "and the handshake completes")
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}
