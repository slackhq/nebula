//go:build e2e_testing

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// relayedHybridTunnel brings up a hybrid tunnel whose msg2 completes by the
// relay: every direct msg2 fragment is lost, and drop decides what else is. It
// returns the controls with the tunnel up and the first packet delivered.
func relayedHybridTunnel(t *testing.T, drop func(p *udp.Packet, receiver *nebula.Control, them netip.AddrPort, me *nebula.Control) bool) (myControl, theirControl *nebula.Control, myVpn, theirVpn []netip.Prefix, myUdp, theirUdp netip.AddrPort, r *router.R) {
	t.Helper()
	ca := newHybridCA(t)
	useRelays := pqRequire()
	useRelays["relay"] = m{"use_relays": true}
	useRelays["counters"] = m{"try_promote": 5}
	amRelay := pqRequire()
	amRelay["relay"] = m{"am_relay": true}
	var relayControl *nebula.Control
	var relayVpn []netip.Prefix
	var relayUdp netip.AddrPort
	myControl, myVpn, myUdp, _ = newSimpleServer(cert.Version3, ca.ca, ca.key, "me     ", "10.128.0.1/24", useRelays)
	relayControl, relayVpn, relayUdp, _ = newSimpleServer(cert.Version3, ca.ca, ca.key, "relay  ", "10.128.0.128/24", amRelay)
	theirControl, theirVpn, theirUdp, _ = newSimpleServer(cert.Version3, ca.ca, ca.key, "them   ", "10.128.0.2/24", useRelays)
	myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
	myControl.InjectLightHouseAddr(relayVpn[0].Addr(), relayUdp)
	myControl.InjectRelays(theirVpn[0].Addr(), []netip.Addr{relayVpn[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
	r = router.NewR(t, myControl, relayControl, theirControl)
	myControl.Start()
	relayControl.Start()
	theirControl.Start()
	t.Cleanup(func() {
		myControl.Stop()
		relayControl.Stop()
		theirControl.Stop()
	})

	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("first")))
	require.True(t, routeUntilData(t, r, theirControl, 10*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		outer := &header.H{}
		relayed := outer.Parse(p.Data) == nil && outer.Type == header.Message && outer.Subtype == header.MessageRelay
		if h, fh := handshakeOf(p); h != nil && fh != nil && h.MessageCounter == 2 && !relayed && p.From == theirUdp && receiver == myControl {
			return router.Drop
		}
		if drop(p, receiver, theirUdp, myControl) {
			return router.Drop
		}
		return router.KeepRouting
	}), "tunnel never came up")
	theirControl.GetFromTun(true)
	return
}

// exchange sends n packets each way, routing with drop, and reports how many
// arrived in each direction.
func exchange(t *testing.T, r *router.R, myControl, theirControl *nebula.Control, myVpn, theirVpn []netip.Prefix, theirUdp netip.AddrPort, n int, drop func(p *udp.Packet, receiver *nebula.Control, them netip.AddrPort, me *nebula.Control) bool) (toThem, toMe int) {
	t.Helper()
	route := func(to *nebula.Control) bool {
		return routeUntilData(t, r, to, 300*time.Millisecond, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
			if drop(p, receiver, theirUdp, myControl) {
				return router.Drop
			}
			return router.KeepRouting
		})
	}
	for range n {
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
	return
}

func noDrop(*udp.Packet, *nebula.Control, netip.AddrPort, *nebula.Control) bool { return false }

// TestHybridRelayPromotion has msg2 complete by the relay although the direct
// path works both ways, as it often does on real networks where the tunnel to
// the relay is already up and the direct path still needs a punch. Both ends
// start relayed, and the usual promotion moves them to direct.
//
// With the direct path working only toward the responder, promotion's direct
// probe makes the responder roam onto it and lose its replies, hybrid or
// classical alike: roaming on receipt assumes a path works both ways. Roam path
// validation (claude/roam-path-validation) would hold the responder on the relay.
func TestHybridRelayPromotion(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, myUdp, theirUdp, r := relayedHybridTunnel(t, noDrop)
	defer r.RenderFlow()

	theirs := theirControl.GetHostInfoByVpnAddr(myVpn[0].Addr(), false)
	require.NotNil(t, theirs)
	assert.False(t, theirs.CurrentRemote.IsValid(), "msg3 came by the relay, so the responder starts relayed")

	toThem, toMe := exchange(t, r, myControl, theirControl, myVpn, theirVpn, theirUdp, 20, noDrop)
	assert.Equal(t, 20, toThem)
	assert.Equal(t, 20, toMe)
	assert.Equal(t, theirUdp, myControl.GetHostInfoByVpnAddr(theirVpn[0].Addr(), false).CurrentRemote, "the initiator promoted to direct")
	assert.Equal(t, myUdp, theirControl.GetHostInfoByVpnAddr(myVpn[0].Addr(), false).CurrentRemote, "the responder promoted to direct")
}
