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

func pqRequire() m {
	return m{"handshakes": m{"repair_delay": "0s", "pq": m{"require": true}}}
}

func pqConfig(initiate, accept, sticky bool) m {
	return m{"handshakes": m{"repair_delay": "0s", "pq": m{
		"initiate": initiate,
		"accept":   accept,
		"sticky":   sticky,
	}}}
}

// isHybrid reports whether h is a hybrid handshake message.
func isHybrid(h *header.H) bool {
	return h.Subtype == header.HandshakeIXHybridMLKEM1024 || h.Subtype == header.HandshakeIXHybridMLKEM1024Fragmented
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
	if isHybrid(h) {
		ht.pq++
		ht.maxPQLen = max(ht.maxPQLen, len(p.Data))
	} else {
		ht.classical++
	}
}

// newPQPair builds two hosts with v3 certificates that also trust the CA's v2
// form, so a classical handshake can complete when the hybrid one does not.
func newPQPair(t *testing.T, mine, theirs m) (myControl, theirControl *nebula.Control, myVpn, theirVpn []netip.Prefix, myUdp, theirUdp netip.AddrPort, r *router.R) {
	t.Helper()
	ca := newHybridCA(t)
	ca2, _ := ca.v2()
	myControl, myVpn, myUdp, _ = newSimpleServer(cert.Version3, ca.ca, ca.key, "me", "10.128.0.1/24", withCA(mine, ca.ca, ca2))
	theirControl, theirVpn, theirUdp, _ = newSimpleServer(cert.Version3, ca.ca, ca.key, "them", "10.128.0.2/24", withCA(theirs, ca.ca, ca2))
	myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
	r = router.NewR(t, myControl, theirControl)
	myControl.Start()
	theirControl.Start()
	return
}

// TestPQHandshakeLoss drops data fragments of both messages; the repair
// fragments must carry the handshake without a retry.
func TestPQHandshakeLoss(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
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
	cert_test.SkipWithoutPQ(t)
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
	cert_test.SkipWithoutPQ(t)
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
		case fh != nil && h.MessageCounter == 2 && fh.Index < 12:
			firstMsg2++
			return router.Drop
		case fh != nil && h.MessageCounter == 2:
			freshMsg2++
		case fh != nil && h.MessageCounter == 1 && fh.Index >= 10:
			freshMsg1++
		}
		if isTunnelData(p, receiver, theirControl) {
			return router.RouteAndExit
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Equal(t, 12, firstMsg2, "the first msg2 is 9 data and 3 repair fragments")
	assert.Positive(t, freshMsg1, "the retry offers fresh msg1 symbols")
	assert.Positive(t, freshMsg2, "the resend offers fresh msg2 symbols")
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

// TestPQSticky checks a sticky initiator never offers a classical handshake to a
// peer it has already completed a PQ handshake with.
func TestPQSticky(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
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
		if h, _ := handshakeOf(p); h != nil && isHybrid(h) {
			return router.Drop
		}
		return router.KeepRouting
	})
	assert.Positive(t, tally.pq, "PQ attempts keep being made")
	assert.Zero(t, tally.classical, "sticky must never fall back")

	myControl.Stop()
	theirControl.Stop()
}

// TestPQTimeoutReleasesIndexes lets a handshake with both a PQ and a classical
// attempt pending time out, and checks neither index is left behind.
func TestPQTimeoutReleasesIndexes(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
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
	cert_test.SkipWithoutPQ(t)
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, _, theirUdp, r := newPQPair(t, pqConfig(true, true, false), pqConfig(false, true, false))
	defer r.RenderFlow()

	// Half of the 1024 entry table is the cookie threshold. Stopping exactly there
	// keeps them from answering the spoofed sources, which the router cannot reach.
	t.Log("Flood them with the first fragment of msg1s nobody will finish")
	for i := range 512 {
		from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 4242)
		pkt := header.Encode(make([]byte, header.Len, header.Len+2000), header.Version, header.Handshake, header.HandshakeIXHybridMLKEM1024, 0, 1)
		s, err := fragment.NewSender(append(pkt, make([]byte, 2000)...), uint32(i+1))
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
		if h, fh := handshakeOf(p); h != nil && isHybrid(h) {
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

// TestPQRequire checks require mode never handshakes classically, in either
// direction.
func TestPQRequire(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	t.Parallel()

	t.Run("initiator", func(t *testing.T) {
		// They neither speak PQ nor require it; we never fall back.
		myControl, theirControl, myVpn, theirVpn, _, _, r := newPQPair(t, pqRequire(), nil)
		defer r.RenderFlow()

		var tally handshakeTally
		myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
		r.RouteForAllExitFuncOrTimeout(time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
			tally.observe(p)
			return router.KeepRouting
		})
		assert.Positive(t, tally.pq)
		assert.Zero(t, tally.classical)
		assert.Nil(t, theirControl.GetHostInfoByVpnAddr(myVpn[0].Addr(), false), "no tunnel without PQ")

		myControl.Stop()
		theirControl.Stop()
	})

	t.Run("responder", func(t *testing.T) {
		// We only speak classical; they refuse it.
		myControl, theirControl, myVpn, theirVpn, _, _, r := newPQPair(t, nil, pqRequire())
		defer r.RenderFlow()

		var answers int
		myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
		r.RouteForAllExitFuncOrTimeout(time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
			if h, _ := handshakeOf(p); h != nil && h.MessageCounter == 2 {
				answers++
			}
			return router.KeepRouting
		})
		assert.Zero(t, answers, "a classical msg1 gets no answer")
		assert.Nil(t, theirControl.GetHostInfoByVpnAddr(myVpn[0].Addr(), false))

		myControl.Stop()
		theirControl.Stop()
	})

	t.Run("both", func(t *testing.T) {
		myControl, theirControl, myVpn, theirVpn, _, _, r := newPQPair(t, pqRequire(), pqRequire())
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
		assert.Zero(t, tally.classical)
		assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)

		myControl.Stop()
		theirControl.Stop()
	})
}
