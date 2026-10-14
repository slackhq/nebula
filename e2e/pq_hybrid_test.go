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

// hybridTally counts handshake packets by subtype and message.
type hybridTally struct {
	sync.Mutex
	hybrid, phase1, classical int
	msg3                      int
	maxLen                    int
}

func (ht *hybridTally) observe(p *udp.Packet) {
	h, _ := handshakeOf(p)
	if h == nil {
		return
	}
	ht.Lock()
	defer ht.Unlock()
	switch h.Subtype {
	case header.HandshakeIXHybridMLKEM1024:
		ht.hybrid++
		ht.maxLen = max(ht.maxLen, len(p.Data))
		if h.MessageCounter == 3 {
			ht.msg3++
		}
	case header.HandshakeIXPSK2MLKEM1024:
		ht.phase1++
	default:
		ht.classical++
	}
}

func isType(p *udp.Packet, t header.MessageType) bool {
	h := &header.H{}
	return h.Parse(p.Data) == nil && h.Type == t
}

type hybridCA struct {
	ca  cert.Certificate
	key []byte
}

func newHybridCA(t *testing.T) hybridCA {
	t.Helper()
	ca, _, key, _ := cert_test.NewTestCaCert(cert.Version3, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	return hybridCA{ca: ca, key: key}
}

// v2 returns the v2 form of the CA and its classical key, what a node that only has v2 certificates gets.
func (h hybridCA) v2() (cert.Certificate, []byte) {
	return cert.V2Form(h.ca), h.key[:len(h.key)-cert.MLDSA87PrivateKeySize]
}

// trust returns a pki.ca override trusting the given CAs.
func trust(cas ...cert.Certificate) string {
	var s string
	for _, c := range cas {
		b, err := c.MarshalPEM()
		if err != nil {
			panic(err)
		}
		s += string(b)
	}
	return s
}

func withCA(cfg m, cas ...cert.Certificate) m {
	if cfg == nil {
		cfg = m{}
	}
	cfg["pki"] = m{"ca": trust(cas...)}
	return cfg
}

func newHybridPair(t *testing.T, mine, theirs m) (myControl, theirControl *nebula.Control, myVpn, theirVpn []netip.Prefix, myUdp, theirUdp netip.AddrPort, r *router.R) {
	t.Helper()
	return newHybridPairWithCA(t, newHybridCA(t), mine, theirs)
}

func newHybridPairWithCA(t *testing.T, ca hybridCA, mine, theirs m) (myControl, theirControl *nebula.Control, myVpn, theirVpn []netip.Prefix, myUdp, theirUdp netip.AddrPort, r *router.R) {
	t.Helper()
	myControl, myVpn, myUdp, _ = newSimpleServer(cert.Version3, ca.ca, ca.key, "me", "10.128.0.1/24", mine)
	theirControl, theirVpn, theirUdp, _ = newSimpleServer(cert.Version3, ca.ca, ca.key, "them", "10.128.0.2/24", theirs)
	myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
	r = router.NewR(t, myControl, theirControl)
	myControl.Start()
	theirControl.Start()
	return
}

func routeUntilData(t *testing.T, r *router.R, to *nebula.Control, timeout time.Duration, fn func(p *udp.Packet, receiver *nebula.Control) router.ExitType) bool {
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

func TestHybridHandshake(t *testing.T) {
	t.Parallel()
	myControl, theirControl, myVpn, theirVpn, myUdp, theirUdp, r := newHybridPair(t, pqConfig(true, true, false), pqConfig(false, true, false))
	defer r.RenderFlow()

	var tally hybridTally
	var recvErrors int
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilData(t, r, theirControl, 5*time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		tally.observe(p)
		if isType(p, header.RecvError) {
			recvErrors++
		}
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Zero(t, tally.classical+tally.phase1, "a node with a v3 certificate speaks the hybrid handshake")
	assert.GreaterOrEqual(t, tally.hybrid, 7+9+2, "all three messages travel as several fragments")
	assert.Positive(t, tally.msg3)
	assert.LessOrEqual(t, tally.maxLen, fragment.MaxPacketLen)
	assert.Zero(t, recvErrors)

	assertHostInfoPair(t, myUdp, theirUdp, myVpn, theirVpn, myControl, theirControl)
	assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)
	for _, c := range []*nebula.Control{myControl, theirControl} {
		assert.Empty(t, c.ListHostmapIndexes(true), "no pending index may outlive the handshake")
	}
	assert.Equal(t, cert.Version3, myControl.GetHostInfoByVpnAddr(theirVpn[0].Addr(), false).Cert.Version())
	assert.Equal(t, cert.Version3, theirControl.GetHostInfoByVpnAddr(myVpn[0].Addr(), false).Cert.Version())

	myControl.Stop()
	theirControl.Stop()
}

// TestHybridConfirmationLost loses the responder's confirmation. The initiator
// keeps resending msg3, and the responder, already done, confirms again rather
// than leave the initiator to tear the tunnel down.
func TestHybridConfirmationLost(t *testing.T) {
	t.Parallel()
	// Three retries make the handshake timeout 400ms, so the wait below outlasts it.
	mine := pqConfig(true, true, false)
	mine["handshakes"].(m)["retries"] = 3
	myControl, theirControl, myVpn, theirVpn, _, _, r := newHybridPair(t, mine, pqConfig(false, true, false))
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

// TestHybridNeverConfirmed loses every msg3. The responder never completes, must
// not answer the initiator's data with RecvErrors meanwhile, and the initiator
// closes the tunnel at the handshake timeout.
func TestHybridNeverConfirmed(t *testing.T) {
	t.Parallel()
	mine := pqConfig(true, true, false)
	mine["handshakes"].(m)["retries"] = 3
	theirs := pqConfig(false, true, false)
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

// TestHybridToV2Peer has a v3 initiator meet a peer that speaks phase 1 post-quantum
// handshakes but holds only a v2 certificate. Holding v3, the initiator never
// offers phase 1, so the tunnel comes up classical on the v2 form.
func TestHybridToV2Peer(t *testing.T) {
	t.Parallel()
	ca := newHybridCA(t)
	ca2, key2 := ca.v2()
	myControl, myVpn, myUdp, _ := newSimpleServer(cert.Version3, ca.ca, ca.key, "me", "10.128.0.1/24", withCA(pqConfig(true, true, false), ca.ca, ca2))
	theirControl, theirVpn, theirUdp, _ := newSimpleServer(cert.Version2, ca2, key2, "them", "10.128.0.2/24", pqConfig(true, true, false))
	myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()
	myControl.Start()
	theirControl.Start()

	var tally hybridTally
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilData(t, r, theirControl, 5*time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		tally.observe(p)
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Positive(t, tally.hybrid, "the hybrid attempt comes first")
	assert.Zero(t, tally.phase1, "a v3 holder never initiates phase 1")
	assert.Positive(t, tally.classical)
	assertHostInfoPair(t, myUdp, theirUdp, myVpn, theirVpn, myControl, theirControl)
	assert.Equal(t, cert.Version2, theirControl.GetHostInfoByVpnAddr(myVpn[0].Addr(), false).Cert.Version())
	assert.Empty(t, myControl.ListHostmapIndexes(true))
	assert.Empty(t, theirControl.ListHostmapIndexes(true))

	myControl.Stop()
	theirControl.Stop()
}

// TestHybridDistrustedV3 has an initiator that trusts only the v2 form of the CA.
// Its hybrid attempt fails verifying the responder's v3 certificate, which must
// leave the classical attempt going rather than end the handshake.
func TestHybridDistrustedV3(t *testing.T) {
	t.Parallel()
	ca := newHybridCA(t)
	ca2, _ := ca.v2()
	myControl, theirControl, myVpn, theirVpn, _, _, r := newHybridPairWithCA(t, ca,
		withCA(pqConfig(true, true, false), ca2),
		withCA(pqConfig(false, true, false), ca.ca, ca2),
	)
	defer r.RenderFlow()

	var tally hybridTally
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
	require.True(t, routeUntilData(t, r, theirControl, 5*time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		tally.observe(p)
		return router.KeepRouting
	}), "tunnel never came up")

	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
	assert.Positive(t, tally.hybrid)
	assert.Positive(t, tally.classical)
	assert.Equal(t, cert.Version2, myControl.GetHostInfoByVpnAddr(theirVpn[0].Addr(), false).Cert.Version())
	assert.Empty(t, myControl.ListHostmapIndexes(true))

	myControl.Stop()
	theirControl.Stop()
}

// TestHybridRequire checks require with a v3 certificate means hybrid only.
func TestHybridRequire(t *testing.T) {
	t.Parallel()

	t.Run("both", func(t *testing.T) {
		myControl, theirControl, myVpn, theirVpn, _, _, r := newHybridPair(t, pqRequire(), pqRequire())
		defer r.RenderFlow()

		var tally hybridTally
		myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
		require.True(t, routeUntilData(t, r, theirControl, 5*time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
			tally.observe(p)
			return router.KeepRouting
		}), "tunnel never came up")
		assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), myVpn[0].Addr(), theirVpn[0].Addr(), 80, 80)
		assert.Zero(t, tally.classical+tally.phase1)
		assertTunnel(t, myVpn[0].Addr(), theirVpn[0].Addr(), myControl, theirControl, r)

		myControl.Stop()
		theirControl.Stop()
	})

	t.Run("responder refuses phase 1", func(t *testing.T) {
		ca := newHybridCA(t)
		ca2, key2 := ca.v2()
		myControl, myVpn, _, _ := newSimpleServer(cert.Version2, ca2, key2, "me", "10.128.0.1/24", pqRequire())
		theirControl, theirVpn, theirUdp, _ := newSimpleServer(cert.Version3, ca.ca, ca.key, "them", "10.128.0.2/24", withCA(pqRequire(), ca.ca, ca2))
		myControl.InjectLightHouseAddr(theirVpn[0].Addr(), theirUdp)
		r := router.NewR(t, myControl, theirControl)
		defer r.RenderFlow()
		myControl.Start()
		theirControl.Start()

		var tally hybridTally
		var answers int
		myControl.InjectTunPacket(BuildTunUDPPacket(theirVpn[0].Addr(), 80, myVpn[0].Addr(), 80, []byte("Hi from me")))
		r.RouteForAllExitFuncOrTimeout(time.Second, func(p *udp.Packet, receiver *nebula.Control) router.ExitType {
			tally.observe(p)
			if h, _ := handshakeOf(p); h != nil && h.MessageCounter == 2 {
				answers++
			}
			return router.KeepRouting
		})
		assert.Positive(t, tally.phase1)
		assert.Zero(t, answers, "a phase 1 msg1 gets no answer from a v3 node requiring post-quantum")
		assert.Nil(t, theirControl.GetHostInfoByVpnAddr(myVpn[0].Addr(), false))

		myControl.Stop()
		theirControl.Stop()
	})
}

func TestHybridRelays(t *testing.T) {
	t.Parallel()
	ca := newHybridCA(t)
	useRelays := pqConfig(true, true, false)
	useRelays["relay"] = m{"use_relays": true}
	amRelay := pqConfig(true, true, false)
	amRelay["relay"] = m{"am_relay": true}
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version3, ca.ca, ca.key, "me     ", "10.128.0.1/24", useRelays)
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(cert.Version3, ca.ca, ca.key, "relay  ", "10.128.0.128/24", amRelay)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version3, ca.ca, ca.key, "them   ", "10.128.0.2/24", useRelays)

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
	require.True(t, routeUntilData(t, r, theirControl, 10*time.Second, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		outer := &header.H{}
		if outer.Parse(p.Data) == nil && outer.Type == header.Message && outer.Subtype == header.MessageRelay {
			if h, fh := handshakeOf(p); h != nil && fh != nil {
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
	r.RenderHostmaps("Final hostmaps", myControl, relayControl, theirControl)

	myControl.Stop()
	relayControl.Stop()
	theirControl.Stop()
}
