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
)

// makeHandshakePacket creates a handshake packet with the given parameters.
func makeHandshakePacket(from, to netip.AddrPort, subtype header.MessageSubType, remoteIndex uint32, counter uint64) *udp.Packet {
	data := make([]byte, 200)
	header.Encode(data, header.Version, header.Handshake, subtype, remoteIndex, counter)
	for i := header.Len; i < len(data); i++ {
		data[i] = byte(i)
	}
	return &udp.Packet{To: to, From: from, Data: data}
}

func TestHandshakeRetransmitDuplicate(t *testing.T) {
	t.Parallel()
	// Verify the responder correctly handles receiving the same msg1 multiple times
	// (retransmission). The duplicate goes through CheckAndComplete -> ErrAlreadySeen
	// and the cached response is resent.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	myControl.Start()
	theirControl.Start()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	t.Log("Trigger handshake from me to them")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi")))

	t.Log("Grab my msg1")
	msg1 := myControl.GetFromUDP(true)

	t.Log("Inject msg1 into them, first time")
	theirControl.InjectUDPPacket(msg1)
	_ = theirControl.GetFromUDP(true)

	t.Log("Inject the SAME msg1 again, tests ErrAlreadySeen path")
	theirControl.InjectUDPPacket(msg1)
	resp2 := theirControl.GetFromUDP(true)
	assert.NotNil(t, resp2, "should get cached response on duplicate msg1")

	t.Log("Complete handshake with cached response")
	myControl.InjectUDPPacket(resp2)
	myControl.WaitForType(1, 0, theirControl)

	t.Log("Drain cached packet and verify tunnel works")
	cachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi"), cachedPacket, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	t.Log("Verify only one tunnel exists on each side")
	assert.Len(t, myControl.ListHostmapHosts(false), 1)
	assert.Len(t, theirControl.ListHostmapHosts(false), 1)

	myControl.Stop()
	theirControl.Stop()
}

func TestHandshakeTruncatedPacketRecovery(t *testing.T) {
	t.Parallel()
	// Verify that a truncated handshake packet is ignored and the real
	// packet can still complete the handshake.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	myControl.Start()
	theirControl.Start()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	t.Log("Trigger handshake")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi")))

	t.Log("Get msg1 and deliver to responder")
	msg1 := myControl.GetFromUDP(true)
	theirControl.InjectUDPPacket(msg1)

	t.Log("Get the real response")
	realResp := theirControl.GetFromUDP(true)

	t.Log("Truncate the response and inject, should be ignored")
	truncResp := realResp.Copy()
	truncResp.Data = truncResp.Data[:header.Len]
	myControl.InjectUDPPacket(truncResp)

	t.Log("Verify pending handshake survived the truncated packet")
	assert.NotEmpty(t, myControl.ListHostmapHosts(true), "pending handshake should still exist")

	t.Log("Inject real response, should complete handshake")
	myControl.InjectUDPPacket(realResp)
	myControl.WaitForType(1, 0, theirControl)

	t.Log("Drain and verify tunnel")
	cachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi"), cachedPacket, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

func TestHandshakeOrphanedMsg2Dropped(t *testing.T) {
	t.Parallel()
	// A msg2 arriving with no matching pending index should be silently dropped
	// with no response sent and no state changes.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	myControl.Start()
	theirControl.Start()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	t.Log("Complete a normal handshake")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi")))
	r.RouteForAllUntilTxTun(theirControl)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	t.Log("Record hostmap state")
	myIndexes := len(myControl.ListHostmapIndexes(false))

	t.Log("Inject a fake msg2 with unknown RemoteIndex")
	myControl.InjectUDPPacket(makeHandshakePacket(theirUdpAddr, myUdpAddr, header.HandshakeIXPSK0, 0xDEADBEEF, 2))

	t.Log("Verify no new indexes created")
	assert.Equal(t, myIndexes, len(myControl.ListHostmapIndexes(false)))

	t.Log("Verify no UDP response was sent")
	time.Sleep(100 * time.Millisecond)
	assert.Nil(t, myControl.GetFromUDP(false), "should not send a response to orphaned msg2")

	t.Log("Verify existing tunnel still works")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

func TestHandshakeUnknownMessageCounter(t *testing.T) {
	t.Parallel()
	// A handshake packet with an unexpected message counter should be silently
	// dropped with no side effects and no UDP response.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, _, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	myControl.Start()
	theirControl.Start()

	t.Log("Inject handshake with MessageCounter=3")
	myControl.InjectUDPPacket(makeHandshakePacket(theirUdpAddr, myUdpAddr, header.HandshakeIXPSK0, 0, 3))

	t.Log("Inject handshake with MessageCounter=99")
	myControl.InjectUDPPacket(makeHandshakePacket(theirUdpAddr, myUdpAddr, header.HandshakeIXPSK0, 0, 99))

	t.Log("Verify no tunnels or pending handshakes")
	assert.Empty(t, myControl.ListHostmapHosts(false))
	assert.Empty(t, myControl.ListHostmapHosts(true))

	t.Log("Verify no UDP response was sent")
	time.Sleep(100 * time.Millisecond)
	assert.Nil(t, myControl.GetFromUDP(false))

	myControl.Stop()
	theirControl.Stop()
}

func TestHandshakeUnknownSubtype(t *testing.T) {
	t.Parallel()
	// A handshake packet with an unknown subtype should be silently dropped.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, _, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, _, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.Start()
	theirControl.Start()

	t.Log("Inject handshake with unknown subtype 99")
	myControl.InjectUDPPacket(makeHandshakePacket(theirUdpAddr, myUdpAddr, header.MessageSubType(99), 0, 1))

	t.Log("Verify no tunnels or pending handshakes")
	assert.Empty(t, myControl.ListHostmapHosts(false))
	assert.Empty(t, myControl.ListHostmapHosts(true))

	t.Log("Verify no UDP response was sent")
	time.Sleep(100 * time.Millisecond)
	assert.Nil(t, myControl.GetFromUDP(false))

	myControl.Stop()
	theirControl.Stop()
}

func TestHandshakeLateResponse(t *testing.T) {
	t.Parallel()
	// After a handshake times out, a late response should be silently ignored
	// with no new tunnels created.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", m{
		"handshakes": m{
			"try_interval": "200ms",
			"retries":      2,
		},
	})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	myControl.Start()
	theirControl.Start()

	t.Log("Trigger handshake from me")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi")))

	t.Log("Grab msg1 but don't deliver")
	msg1 := myControl.GetFromUDP(true)

	t.Log("Wait for handshake to time out")
	for i := 0; i < 5; i++ {
		time.Sleep(300 * time.Millisecond)
		myControl.GetFromUDP(false)
	}

	t.Log("Confirm no pending handshakes remain")
	assert.Empty(t, myControl.ListHostmapHosts(true))

	t.Log("Deliver old msg1 to them, they create a tunnel")
	theirControl.InjectUDPPacket(msg1)
	resp := theirControl.GetFromUDP(true)
	assert.NotNil(t, resp)

	t.Log("Inject late response into me, should be ignored")
	myControl.InjectUDPPacket(resp)

	t.Log("No tunnel should exist on my side")
	assert.Empty(t, myControl.ListHostmapHosts(false))
	assert.Empty(t, myControl.ListHostmapHosts(true))

	myControl.Stop()
	theirControl.Stop()
}

func TestHandshakeSelfConnectionRejected(t *testing.T) {
	t.Parallel()
	// Verify that a node rejects a handshake containing its own VPN IP in the
	// peer cert. We do this by sending the initiator's own msg1 back to itself.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)

	// Need a lighthouse entry to trigger a handshake
	myControl.InjectLightHouseAddr(netip.MustParseAddr("10.128.0.2"), netip.MustParseAddrPort("10.0.0.2:4242"))

	myControl.Start()

	t.Log("Trigger handshake from me")
	myControl.InjectTunPacket(BuildTunUDPPacket(netip.MustParseAddr("10.128.0.2"), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi")))
	msg1 := myControl.GetFromUDP(true)

	t.Log("Drain any handshake retransmits before injecting")
	time.Sleep(100 * time.Millisecond)
	for myControl.GetFromUDP(false) != nil {
	}

	t.Log("Feed my own msg1 back to me as if it came from someone else")
	selfMsg := msg1.Copy()
	selfMsg.From = netip.MustParseAddrPort("10.0.0.99:4242")
	selfMsg.To = myUdpAddr
	myControl.InjectUDPPacket(selfMsg)

	t.Log("Verify no response was sent (self-connection rejected)")
	time.Sleep(100 * time.Millisecond)
	// Drain any further retransmits from the original handshake, then check
	// that none of them are a handshake response (MessageCounter=2)
	h := &header.H{}
	for {
		p := myControl.GetFromUDP(false)
		if p == nil {
			break
		}
		_ = h.Parse(p.Data)
		assert.NotEqual(t, uint64(2), h.MessageCounter,
			"should not send a stage 2 response to self-connection")
	}

	t.Log("Verify no tunnel to myself was created")
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false))

	myControl.Stop()
}

func TestHandshakeMessageCounter0Dropped(t *testing.T) {
	t.Parallel()
	// MessageCounter=0 is not a valid handshake message and should be dropped.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, _, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	_, _, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.Start()

	t.Log("Inject handshake with MessageCounter=0")
	myControl.InjectUDPPacket(makeHandshakePacket(theirUdpAddr, myUdpAddr, header.HandshakeIXPSK0, 0, 0))

	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, myControl.ListHostmapHosts(false))
	assert.Empty(t, myControl.ListHostmapHosts(true))
	assert.Nil(t, myControl.GetFromUDP(false))

	myControl.Stop()
}

func TestHandshakeRemoteAllowList(t *testing.T) {
	t.Parallel()
	// Verify that a handshake from a blocked underlay IP is dropped with no
	// response and no state changes. Then verify the same packet from an
	// allowed IP succeeds.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", m{
		"lighthouse": m{
			"remote_allow_list": m{
				"10.0.0.0/8": true,
				"0.0.0.0/0":  false,
			},
		},
	})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	myControl.Start()
	theirControl.Start()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	t.Log("Trigger handshake from them")
	theirControl.InjectTunPacket(BuildTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("Hi")))
	msg1 := theirControl.GetFromUDP(true)

	t.Log("Rewrite the source to a blocked IP and inject")
	blockedMsg := msg1.Copy()
	blockedMsg.From = netip.MustParseAddrPort("192.168.1.1:4242")
	myControl.InjectUDPPacket(blockedMsg)

	t.Log("Verify no tunnel, no pending, no response from blocked source")
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, myControl.ListHostmapHosts(false))
	assert.Empty(t, myControl.ListHostmapHosts(true))
	assert.Nil(t, myControl.GetFromUDP(false), "should not respond to blocked source")

	t.Log("Now inject the real packet from the allowed source")
	myControl.InjectUDPPacket(msg1)

	t.Log("Verify handshake completes from allowed source")
	resp := myControl.GetFromUDP(true)
	assert.NotNil(t, resp)
	theirControl.InjectUDPPacket(resp)
	theirControl.WaitForType(1, 0, myControl)

	t.Log("Drain cached packet and verify tunnel works")
	cachedPacket := myControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi"), cachedPacket, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), 80, 80)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

func TestHandshakeAlreadySeenPreferredRemote(t *testing.T) {
	t.Parallel()
	// When a duplicate msg1 arrives via ErrAlreadySeen, verify the tunnel
	// remains functional and hostmap index count is stable.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	myControl.Start()
	theirControl.Start()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	t.Log("Complete a normal handshake via the router")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi")))
	r.RouteForAllUntilTxTun(theirControl)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	t.Log("Record hostmap state")
	theirIndexes := len(theirControl.ListHostmapIndexes(false))
	hi := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
	assert.NotNil(t, hi)
	originalRemote := hi.CurrentRemote

	t.Log("Re-trigger traffic to cause a new handshake attempt (ErrAlreadySeen)")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("roam")))
	r.RouteForAllUntilTxTun(theirControl)

	t.Log("Verify tunnel still works")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	t.Log("Verify remote is still valid and index count is stable")
	hi2 := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
	assert.NotNil(t, hi2)
	assert.Equal(t, originalRemote, hi2.CurrentRemote)
	assert.Equal(t, theirIndexes, len(theirControl.ListHostmapIndexes(false)),
		"no extra indexes should be created from ErrAlreadySeen")

	myControl.Stop()
	theirControl.Stop()
}

func TestHandshakeWrongResponderPacketStore(t *testing.T) {
	t.Parallel()
	// Verify that when the wrong host responds, the cached packets are
	// transferred to the new handshake, the evil tunnel is closed, evil's
	// address is blocked, and the correct tunnel is eventually established.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.100/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.99/24", nil)
	evilControl, evilVpnIpNet, evilUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "evil", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), evilUdpAddr)

	r := router.NewR(t, myControl, theirControl, evilControl)
	defer r.RenderFlow()

	myControl.Start()
	theirControl.Start()
	evilControl.Start()

	t.Log("Send multiple packets to them (cached during handshake)")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("packet1")))
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("packet2")))

	t.Log("Route until evil tunnel is closed")
	h := &header.H{}
	r.RouteForAllExitFunc(func(p *udp.Packet, c *nebula.Control) router.ExitType {
		if err := h.Parse(p.Data); err != nil {
			panic(err)
		}
		if h.Type == header.CloseTunnel && p.To == evilUdpAddr {
			return router.RouteAndExit
		}
		return router.KeepRouting
	})

	t.Log("Verify evil's address is blocked in the new pending handshake")
	pendingHI := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), true)
	if pendingHI != nil {
		assert.NotContains(t, pendingHI.RemoteAddrs, evilUdpAddr,
			"evil's address should be blocked")
	}

	t.Log("Inject correct lighthouse addr for them")
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	t.Log("Route until cached packets arrive at the real them")
	p := r.RouteForAllUntilTxTun(theirControl)
	assert.NotNil(t, p, "a cached packet should be delivered to the correct host")

	t.Log("Verify the correct host has a tunnel")
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIpNet, theirVpnIpNet, myControl, theirControl)

	t.Log("Verify no hostinfo artifacts from evil remain")
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(evilVpnIpNet[0].Addr(), true),
		"no pending hostinfo for evil")
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(evilVpnIpNet[0].Addr(), false),
		"no main hostinfo for evil")

	myControl.Stop()
	theirControl.Stop()
	evilControl.Stop()
}

func TestHandshakeRelayComplete(t *testing.T) {
	t.Parallel()
	// Verify that a relay handshake completes correctly and relay state is
	// properly maintained on all three nodes.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "relay", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger handshake via relay")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi via relay")))

	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi via relay"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	t.Log("Verify bidirectional tunnel via relay")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	t.Log("Verify relay state on my side shows relay-to-me")
	myHI := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false)
	assert.NotNil(t, myHI)
	assert.NotEmpty(t, myHI.CurrentRelaysToMe, "should have relay-to-me for them")

	t.Log("Verify relay state on their side shows relay-to-me")
	theirHI := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
	assert.NotNil(t, theirHI)
	assert.NotEmpty(t, theirHI.CurrentRelaysToMe, "should have relay-to-me for me")

	t.Log("Verify relay node shows through-me relays")
	relayHI := relayControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
	assert.NotNil(t, relayHI)

	myControl.Stop()
	relayControl.Stop()
	theirControl.Stop()
}

// NOTE: Relay V1 cert + IPv6 rejection is not tested here because
// BuildTunUDPPacket from a V4 node to a V6 address panics in the test
// framework. The check is in handshake_manager.go handleOutbound relay
// logic (lines ~304-313): if the relay host has a V1 cert and either
// address is IPv6, the relay is skipped.

// NOTE: Relay reestablishment (Disestablished state transition) is covered
// by the existing TestReestablishRelays in handshakes_test.go.
