//go:build e2e_testing

package e2e

import (
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

func pqConfig(initiate, accept, sticky bool) m {
	return m{"handshakes": m{"pq": m{
		"initiate":     initiate,
		"accept":       accept,
		"sticky":       sticky,
		"repair_delay": "0s",
	}}}
}

// handshakeOf returns the handshake header p carries, looking inside relay
// wrapping, plus the fragment header when the handshake is fragmented.
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
	if !header.IsFragmented(h.Subtype) {
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

// handshakeTally counts handshake packets by style as the router moves them.
type handshakeTally struct {
	sync.Mutex
	pq, classical int
	maxPQLen      int
}

func (ht *handshakeTally) observe(p *udp.Packet) {
	h, _ := handshakeOf(p)
	if h == nil {
		return
	}
	ht.Lock()
	defer ht.Unlock()
	if h.Subtype == header.HandshakeIXPSK2MLKEM1024 {
		ht.pq++
		ht.maxPQLen = max(ht.maxPQLen, len(p.Data))
	} else {
		ht.classical++
	}
}

// isTunnelData reports whether p is ordinary tunnel traffic headed for to,
// directly or as the last hop of a relay.
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

func newPQPair(t *testing.T, mine, theirs m) (myControl, theirControl *nebula.Control, myVpn, theirVpn []netip.Prefix, myUdp, theirUdp netip.AddrPort, r *router.R) {
	t.Helper()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpn, myUdp, _ = newSimpleServer(cert.Version2, ca, caKey, "me", "10.128.0.1/24", mine)
	theirControl, theirVpn, theirUdp, _ = newSimpleServer(cert.Version2, ca, caKey, "them", "10.128.0.2/24", theirs)
	myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
	r = router.NewR(t, myControl, theirControl)
	myControl.Start()
	theirControl.Start()
	return
}

func TestPQHandshake(t *testing.T) {
	t.Parallel()
	// They only accept, which is all a PQ initiator needs.
	myControl, theirControl, myVpn, theirVpn, myUdp, theirUdp, r := newPQPair(t, pqConfig(true, true, false), pqConfig(false, true, false))
	defer r.RenderFlow()

	var tally handshakeTally
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, r.RouteForAllExitFuncOrTimeout(5*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		tally.observe(p)
		if isTunnelData(p, receiver, theirControl) {
			return router.RouteAndExit
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Zero(t, tally.classical, "no classical handshake should be needed")
	assert.GreaterOrEqual(t, tally.pq, 4, "both messages travel as several fragments")
	assert.LessOrEqual(t, tally.maxPQLen, fragment.MaxPacketLen)

	assertHostInfoPair(t, myUdp, theirUdp, myVpn, theirVpn, myControl, theirControl)
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)
	assert.Empty(t, myControl.ListHostmapIndexes(true), "no pending index may outlive the handshake")
	assert.Empty(t, theirControl.ListHostmapIndexes(true))

	myControl.Stop()
	theirControl.Stop()
}

// TestPQHandshakeLoss drops data fragments of both messages; the repair
// fragments must carry the handshake without a retry.
func TestPQHandshakeLoss(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, _, _, r := newPQPair(t, pqConfig(true, true, false), pqConfig(false, true, false))
	defer r.RenderFlow()

	var tally handshakeTally
	dropped := 0
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, r.RouteForAllExitFuncOrTimeout(5*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		if h, fh := handshakeOf(p); fh != nil {
			// Every data fragment of msg1, and the first of msg2.
			if (h.MessageCounter == 1 && int(fh.Index) < 2) || (h.MessageCounter == 2 && fh.Index == 0) {
				dropped++
				return router.Drop
			}
		}
		tally.observe(p)
		if isTunnelData(p, receiver, theirControl) {
			return router.RouteAndExit
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Equal(t, 3, dropped)
	assert.Zero(t, tally.classical, "the first attempt should succeed from repair fragments")
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

// TestPQFallback has a peer that does not accept PQ handshakes. The initiator's
// next attempt is classical and the tunnel comes up anyway.
func TestPQFallback(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, myUdp, theirUdp, r := newPQPair(t, pqConfig(true, true, false), nil)
	defer r.RenderFlow()

	var tally handshakeTally
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, r.RouteForAllExitFuncOrTimeout(5*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		tally.observe(p)
		if isTunnelData(p, receiver, theirControl) {
			return router.RouteAndExit
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Positive(t, tally.pq, "a PQ attempt comes first")
	assert.Positive(t, tally.classical, "then a classical one")

	assertHostInfoPair(t, myUdp, theirUdp, myVpn, theirVpn, myControl, theirControl)
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)
	assert.Empty(t, myControl.ListHostmapIndexes(true), "the losing PQ attempt's index must be released")

	myControl.Stop()
	theirControl.Stop()
}

// TestPQResendFreshSymbols loses the responder's whole first msg2. The
// initiator's next PQ attempt offers fresh msg1 symbols, the responder
// recognises the repeat and resends msg2 with symbols it has not sent before.
func TestPQResendFreshSymbols(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, _, _, r := newPQPair(t, pqConfig(true, true, false), pqConfig(false, true, false))
	defer r.RenderFlow()

	var firstMsg2, freshMsg2, freshMsg1 int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, r.RouteForAllExitFuncOrTimeout(10*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		h, fh := handshakeOf(p)
		switch {
		case h != nil && fh == nil:
			// Keep the classical fallback out of the way.
			return router.Drop
		case fh != nil && h.MessageCounter == 2 && fh.Index < 4:
			firstMsg2++
			return router.Drop
		case fh != nil && h.MessageCounter == 2:
			freshMsg2++
		case fh != nil && h.MessageCounter == 1 && fh.Index >= 4:
			freshMsg1++
		}
		if isTunnelData(p, receiver, theirControl) {
			return router.RouteAndExit
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Equal(t, 4, firstMsg2, "the first msg2 is 2 data and 2 repair fragments")
	assert.Positive(t, freshMsg1, "the retry offers fresh msg1 symbols")
	assert.Positive(t, freshMsg2, "the resend offers fresh msg2 symbols")
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

// TestPQSticky checks a sticky initiator never offers a classical handshake to a
// peer it has already completed a PQ handshake with.
func TestPQSticky(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, _, _, r := newPQPair(t, pqConfig(true, true, true), pqConfig(false, true, false))
	defer r.RenderFlow()

	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, r.RouteForAllExitFuncOrTimeout(5*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		if isTunnelData(p, receiver, theirControl) {
			return router.RouteAndExit
		}
		return router.KeepRouting
	}), "tunnel never came up")
	theirControl.GetFromTun(true)

	t.Log("Rehandshake while an attacker drops every PQ packet")
	var tally handshakeTally
	myControl.ReHandshake(theirVpn[0].Addr())
	r.RouteForAllExitFuncOrTimeout(time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		tally.observe(p)
		if h, _ := handshakeOf(p); h != nil && h.Subtype == header.HandshakeIXPSK2MLKEM1024 {
			return router.Drop
		}
		return router.KeepRouting
	})
	assert.Positive(t, tally.pq, "PQ attempts keep being made")
	assert.Zero(t, tally.classical, "sticky must never fall back")

	myControl.Stop()
	theirControl.Stop()
}

func TestPQRelays(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	useRelays := pqConfig(true, true, false)
	useRelays["relay"] = m{"use_relays": true}
	amRelay := pqConfig(true, true, false)
	amRelay["relay"] = m{"am_relay": true}
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.1/24", useRelays)
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "relay  ", "10.128.0.128/24", amRelay)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24", useRelays)

	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	var tally handshakeTally
	var relayedPQ int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, r.RouteForAllExitFuncOrTimeout(10*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		tally.observe(p)
		outer := &header.H{}
		if outer.Parse(p.Data) == nil && outer.Type == header.Message && outer.Subtype == header.MessageRelay {
			if h, fh := handshakeOf(p); h != nil && fh != nil {
				relayedPQ++
				assert.LessOrEqual(t, len(p.Data), fragment.MaxPacketLen+32, "a relayed fragment fits the IPv6 minimum MTU")
			}
		}
		if isTunnelData(p, receiver, theirControl) {
			return router.RouteAndExit
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	assert.Positive(t, relayedPQ, "the end to end handshake is PQ through the relay")
	r.RenderHostmaps("Final hostmaps", myControl, relayControl, theirControl)

	myControl.Stop()
	relayControl.Stop()
	theirControl.Stop()
}

// TestPQTimeoutReleasesIndexes lets a handshake with both a PQ and a classical
// attempt pending time out, and checks neither index is left behind.
func TestPQTimeoutReleasesIndexes(t *testing.T) {
	t.Parallel()
	mine := pqConfig(true, true, false)
	mine["handshakes"].(m)["retries"] = 2
	myControl, theirControl, myVpn, theirVpn, _, _, r := newPQPair(t, mine, pqConfig(false, true, false))
	defer r.RenderFlow()

	var tally handshakeTally
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	r.RouteForAllExitFuncOrTimeout(1500*time.Millisecond, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		tally.observe(p)
		return router.Drop
	})

	assert.Positive(t, tally.pq)
	assert.Positive(t, tally.classical)
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(theirVpn[0].Addr(), true), "the handshake should have timed out")
	assert.Empty(t, myControl.ListHostmapIndexes(true))

	myControl.Stop()
	theirControl.Stop()
}

// TestPQCookieUnderLoad floods the responder with msg1 fragments from spoofed
// sources until it demands cookies, then checks a real initiator picks up the
// cookie and still completes a PQ handshake.
func TestPQCookieUnderLoad(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, _, theirUdp, r := newPQPair(t, pqConfig(true, true, false), pqConfig(false, true, false))
	defer r.RenderFlow()

	// Half of the 1024 entry table is the cookie threshold. Stopping exactly there
	// keeps them from answering the spoofed sources, which the router cannot reach.
	t.Log("Flood them with the first fragment of msg1s nobody will finish")
	for i := range 512 {
		from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 4242)
		s, err := fragment.NewSender(make([]byte, 2000), header.HandshakeIXPSK2MLKEM1024, 0, 1, uint32(i+1))
		require.NoError(t, err)
		pkts, _, err := s.Attempt(0)
		require.NoError(t, err)
		theirControl.InjectUDPPacket(&udp.Packet{From: from, To: theirUdp, Data: pkts[0]})
	}

	var tally handshakeTally
	var cookieReplies, msg2, withCookie int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, r.RouteForAllExitFuncOrTimeout(5*time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
		tally.observe(p)
		if h, fh := handshakeOf(p); h != nil && h.Subtype == header.HandshakeIXPSK2MLKEM1024 {
			switch {
			case h.MessageCounter == 0:
				cookieReplies++
			case h.MessageCounter == 2:
				msg2++
			case fh != nil && fh.HasCookie():
				withCookie++
			}
		}
		if isTunnelData(p, receiver, theirControl) {
			return router.RouteAndExit
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Positive(t, cookieReplies, "a loaded responder asks for a cookie")
	assert.Positive(t, withCookie, "the initiator resends with it")
	assert.Positive(t, msg2, "and the handshake completes post-quantum")
	assert.Zero(t, tally.classical, "the cookie round trip beats the classical fallback")
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}
