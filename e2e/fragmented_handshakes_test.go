//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"fmt"
	"net/netip"
	"strings"
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

// handshakeOf parses a handshake packet, looking inside a relayed one, and its fragment header when it travels as
// fragments. It returns nils for anything else.
func handshakeOf(p *udp.Packet) (*header.H, *fragment.Header) {
	b := p.Data
	h := &header.H{}
	if h.Parse(b) != nil {
		return nil, nil
	}
	if h.Type == header.Message && h.Subtype == header.MessageRelay {
		// Relays authenticate but do not encrypt the inner packet.
		b = b[header.Len:]
		if h.Parse(b) != nil {
			return nil, nil
		}
	}
	if h.Type != header.Handshake {
		return nil, nil
	}
	if _, fragmented := header.FragmentedPattern(h.Subtype); !fragmented || h.MessageCounter == 0 {
		return h, nil
	}
	// A relayed packet still has the relay's AEAD tag on the end.
	for _, tag := range []int{0, 16} {
		if len(b) < header.Len+tag {
			break
		}
		if fh, _, err := fragment.Parse(b[header.Len : len(b)-tag]); err == nil {
			return h, &fh
		}
	}
	return h, nil
}

// fragmentTally counts the handshake packets a test routes.
type fragmentTally struct {
	sync.Mutex
	fragments, single, cookies int
	maxFragment, maxSingle     int
}

func (ft *fragmentTally) observe(p *udp.Packet) {
	h, fh := handshakeOf(p)
	if h == nil {
		return
	}
	ft.Lock()
	defer ft.Unlock()
	switch {
	case h.MessageCounter == 0 && h.Subtype == header.HandshakeIXPSK0Fragmented:
		ft.cookies++
	case fh != nil:
		ft.fragments++
		ft.maxFragment = max(ft.maxFragment, len(p.Data))
	default:
		ft.single++
		ft.maxSingle = max(ft.maxSingle, len(p.Data))
	}
}

// isTunnelData reports whether p is tunnel data arriving at to, relayed or not.
func isTunnelData(p *udp.Packet, receiver, to *nebula.Control) bool {
	h := &header.H{}
	if receiver != to || h.Parse(p.Data) != nil || h.Type != header.Message {
		return false
	}
	if h.Subtype == header.MessageRelay {
		if h.Parse(p.Data[header.Len:]) != nil {
			return false
		}
	}
	return h.Type == header.Message && h.Subtype == header.MessageNone
}

// routeUntilData routes until tunnel data reaches to, showing every packet to fn first.
func routeUntilData(t *testing.T, r *router.R, to *nebula.Control, timeout time.Duration, fn func(p *udp.Packet)) bool {
	t.Helper()
	return r.RouteForAllExitFuncOrTimeout(timeout, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		fn(p)
		if isTunnelData(p, receiver, to) {
			return router.RouteAndExit
		}
		return router.KeepRouting
	})
}

// groupsOf returns n groups of about 40 bytes each, enough of them to make a certificate bigger than one packet.
func groupsOf(n int) []string {
	groups := make([]string, n)
	for i := range groups {
		groups[i] = fmt.Sprintf("group-%03d-%s", i, strings.Repeat("x", 30))
	}
	return groups
}

// newGroupsServer is a node whose certificate carries the given groups.
func newGroupsServer(ca cert.Certificate, caKey []byte, name, network string, groups []string, overrides m) (*nebula.Control, []netip.Prefix, netip.AddrPort) {
	now := time.Now()
	crt, _, keyPEM, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, name, now, now.Add(5*time.Minute), []netip.Prefix{netip.MustParsePrefix(network)}, nil, groups)
	control, vpn, udpAddr, _ := newServer([]cert.Certificate{ca}, []cert.Certificate{crt}, keyPEM, overrides)
	return control, vpn, udpAddr
}

func fragmentMode(mode string) m {
	return m{"handshakes": m{"fragment": mode}}
}

// newFragmentPair builds two nodes with certificates of the given groups, me initiating to them.
func newFragmentPair(t *testing.T, myGroups, theirGroups []string, mine, theirs m) (myControl, theirControl *nebula.Control, myVpn, theirVpn []netip.Prefix, r *router.R) {
	t.Helper()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	myControl, myVpn, _ = newGroupsServer(ca, caKey, "me", "10.128.0.1/24", myGroups, mine)
	theirControl, theirVpn, theirUdp := newGroupsServer(ca, caKey, "them", "10.128.0.2/24", theirGroups, theirs)
	myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
	r = router.NewR(t, myControl, theirControl)
	myControl.Start()
	theirControl.Start()
	return
}

// handshakeAndCheck sends a packet from me to them, which brings the tunnel up, and checks it arrived and that the
// tunnel carries traffic both ways.
func handshakeAndCheck(t *testing.T, myControl, theirControl *nebula.Control, myVpn, theirVpn []netip.Prefix, r *router.R) *fragmentTally {
	t.Helper()
	var tally fragmentTally
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilData(t, r, theirControl, 5*time.Second, tally.observe), "tunnel never came up")
	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)
	return &tally
}

// Certificates bigger than one packet go as fragments, every one of which fits a packet.
func TestFragmentedHandshake_BigCerts(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, r := newFragmentPair(t, groupsOf(50), groupsOf(50), nil, nil)
	defer r.RenderFlow()
	tally := handshakeAndCheck(t, myControl, theirControl, myVpn, theirVpn, r)
	assert.Positive(t, tally.fragments)
	assert.Zero(t, tally.single, "neither message fits one packet")
	assert.LessOrEqual(t, tally.maxFragment, fragment.MaxPacketLen)
	myControl.Stop()
	theirControl.Stop()
}

// Small certificates go as one packet, as before.
func TestFragmentedHandshake_SmallCertsAuto(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, r := newFragmentPair(t, nil, nil, nil, nil)
	defer r.RenderFlow()
	tally := handshakeAndCheck(t, myControl, theirControl, myVpn, theirVpn, r)
	assert.Zero(t, tally.fragments)
	assert.Positive(t, tally.single)
	myControl.Stop()
	theirControl.Stop()
}

// always fragments every message, and a responder answers a fragmented msg1 in fragments.
func TestFragmentedHandshake_Always(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, r := newFragmentPair(t, nil, nil, fragmentMode("always"), nil)
	defer r.RenderFlow()
	tally := handshakeAndCheck(t, myControl, theirControl, myVpn, theirVpn, r)
	assert.Positive(t, tally.fragments)
	assert.Zero(t, tally.single)
	myControl.Stop()
	theirControl.Stop()
}

// never sends every message as one packet, as big as it is.
func TestFragmentedHandshake_Never(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, r := newFragmentPair(t, groupsOf(50), groupsOf(50), fragmentMode("never"), fragmentMode("never"))
	defer r.RenderFlow()
	tally := handshakeAndCheck(t, myControl, theirControl, myVpn, theirVpn, r)
	assert.Zero(t, tally.fragments)
	assert.Greater(t, tally.maxSingle, fragment.MaxPacketLen)
	myControl.Stop()
	theirControl.Stop()
}

// A node that never fragments meets an auto one as an older node would: its big msg1 goes as one packet, and a msg2
// that fits one packet comes back as one.
func TestFragmentedHandshake_NeverMeetsAuto(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, r := newFragmentPair(t, groupsOf(50), nil, fragmentMode("never"), nil)
	defer r.RenderFlow()
	tally := handshakeAndCheck(t, myControl, theirControl, myVpn, theirVpn, r)
	assert.Zero(t, tally.fragments)
	assert.Greater(t, tally.maxSingle, fragment.MaxPacketLen, "msg1")
	myControl.Stop()
	theirControl.Stop()
}

// A node that never fragments does not reassemble either: an auto node's big msg1 goes to it as fragments, which it
// drops unanswered.
func TestFragmentedHandshake_NeverDropsFragments(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, r := newFragmentPair(t, groupsOf(50), nil, nil, fragmentMode("never"))
	defer r.RenderFlow()
	var tally fragmentTally
	answered := false
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	up := r.RouteForAllExitFuncOrTimeout(time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		tally.observe(p)
		answered = answered || receiver == myControl
		return router.KeepRouting
	})
	assert.False(t, up)
	assert.Positive(t, tally.fragments, "msg1")
	assert.False(t, answered)
	myControl.Stop()
	theirControl.Stop()
}

// A responder whose certificate is much bigger than the initiator's would send back more than three times what it
// received, to an address it has not seen receive anything. It asks for a cookie first; the initiator resends msg1 as
// fragments with the cookie, and gets the answer.
func TestFragmentedHandshake_CookieForBigResponse(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, r := newFragmentPair(t, nil, groupsOf(120), nil, nil)
	defer r.RenderFlow()
	tally := handshakeAndCheck(t, myControl, theirControl, myVpn, theirVpn, r)
	assert.Positive(t, tally.cookies, "the responder asked for a cookie")
	assert.Positive(t, tally.single, "the first msg1 was one packet")
	assert.Positive(t, tally.fragments, "the retry with the cookie, and msg2")
	myControl.Stop()
	theirControl.Stop()
}

// When the msg1 that needs a cookie came as fragments, the initiator's immediate resend with the cookie is answered,
// rather than held back until its next scheduled retry by the quiet period the first msg1 started.
func TestFragmentedHandshake_CookieResendAnsweredAtOnce(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, r := newFragmentPair(t, nil, groupsOf(120), fragmentMode("always"), nil)
	defer r.RenderFlow()

	cookieFragments, attempt := 0, 0
	answeredAfter := -1
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilData(t, r, theirControl, 5*time.Second, func(p *udp.Packet) {
		h, fh := handshakeOf(p)
		switch {
		case fh == nil:
		case h.MessageCounter == 1 && fh.HasCookie():
			cookieFragments++
			l, err := fh.Layout()
			require.NoError(t, err)
			attempt = l.K + fragment.DefaultRepair(l.K)
		case h.MessageCounter == 2 && answeredAfter < 0:
			answeredAfter = cookieFragments
		}
	}), "tunnel never came up")
	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)

	require.Positive(t, answeredAfter, "msg2 followed a msg1 with the cookie")
	assert.LessOrEqual(t, answeredAfter, attempt, "the first attempt with the cookie was answered")

	myControl.Stop()
	theirControl.Stop()
}

// When the first msg2 is lost, the initiator's retry is reassembled and answered with the msg2 the responder already
// sent, in fresh symbols, rather than starting a second handshake.
func TestFragmentedHandshake_LostResponse(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, r := newFragmentPair(t, groupsOf(50), groupsOf(50), nil, nil)
	defer r.RenderFlow()

	var dropped, delivered int
	fragIDs := map[uint32]bool{}
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, r.RouteForAllExitFuncOrTimeout(5*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		if isTunnelData(p, receiver, theirControl) {
			return router.RouteAndExit
		}
		h, fh := handshakeOf(p)
		if h == nil || fh == nil || h.MessageCounter != 2 {
			return router.KeepRouting
		}
		fragIDs[fh.FragID] = true
		l, err := fh.Layout()
		require.NoError(t, err)
		if int(fh.Index) < l.K+fragment.DefaultRepair(l.K) {
			// The whole first send of msg2.
			dropped++
			return router.Drop
		}
		delivered++
		return router.KeepRouting
	}), "tunnel never came up")
	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)

	assert.Positive(t, dropped)
	assert.Positive(t, delivered, "the retry was answered with fresh symbols")
	assert.Len(t, fragIDs, 1, "by the responder that answered first")

	myControl.Stop()
	theirControl.Stop()
}

// Fragments go through relays too, and each relayed fragment fits the IPv6 minimum MTU.
func TestFragmentedHandshake_Relayed(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	useRelays := m{"relay": m{"use_relays": true}}
	amRelay := m{"relay": m{"am_relay": true}}
	myControl, myVpn, _ := newGroupsServer(ca, caKey, "me     ", "10.128.0.1/24", groupsOf(50), useRelays)
	relayControl, relayVpn, relayUdp := newGroupsServer(ca, caKey, "relay  ", "10.128.0.128/24", nil, amRelay)
	theirControl, theirVpn, theirUdp := newGroupsServer(ca, caKey, "them   ", "10.128.0.2/24", groupsOf(50), useRelays)

	myControl.InjectLightHouseAddr(relayVpn[0].Addr(), relayUdp)
	myControl.InjectRelays(theirVpn[0].Addr(), []netip.Addr{relayVpn[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)

	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	var relayedFragments int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilData(t, r, theirControl, 10*time.Second, func(p *udp.Packet) {
		outer := &header.H{}
		if outer.Parse(p.Data) == nil && outer.Type == header.Message && outer.Subtype == header.MessageRelay {
			if _, fh := handshakeOf(p); fh != nil {
				assert.LessOrEqual(t, len(p.Data), fragment.MaxPacketLen+32, "a relayed fragment fits the IPv6 minimum MTU")
				relayedFragments++
			}
		}
	}), "tunnel never came up")
	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Positive(t, relayedFragments)

	myControl.Stop()
	relayControl.Stop()
	theirControl.Stop()
}
