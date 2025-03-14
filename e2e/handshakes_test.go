//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func BenchmarkHotPath(b *testing.B) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	// Put their info in our lighthouse
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	r := router.NewR(b, myControl, theirControl)
	r.CancelFlowLogs()

	for n := 0; n < b.N; n++ {
		myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))
		_ = r.RouteForAllUntilTxTun(theirControl)
	}

	myControl.Stop()
	theirControl.Stop()
}

func TestGoodHandshake(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	// Put their info in our lighthouse
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Send a udp packet through to begin standing up the tunnel, this should come out the other side")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

	t.Log("Have them consume my stage 0 packet. They have a tunnel now")
	theirControl.InjectUDPPacket(myControl.GetFromUDP(true))

	t.Log("Get their stage 1 packet so that we can play with it")
	stage1Packet := theirControl.GetFromUDP(true)

	t.Log("I consume a garbage packet with a proper nebula header for our tunnel")
	// this should log a statement and get ignored, allowing the real handshake packet to complete the tunnel
	badPacket := stage1Packet.Copy()
	badPacket.Data = badPacket.Data[:len(badPacket.Data)-header.Len]
	myControl.InjectUDPPacket(badPacket)

	t.Log("Have me consume their real stage 1 packet. I have a tunnel now")
	myControl.InjectUDPPacket(stage1Packet)

	t.Log("Wait until we see my cached packet come through")
	myControl.WaitForType(1, 0, theirControl)

	t.Log("Make sure our host infos are correct")
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIpNet, theirVpnIpNet, myControl, theirControl)

	t.Log("Get that cached packet and make sure it looks right")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	t.Log("Do a bidirectional tunnel test")
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)
	myControl.Stop()
	theirControl.Stop()
}

func TestWrongResponderHandshake(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.100/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.99/24", nil)
	evilControl, evilVpnIp, evilUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "evil", "10.128.0.2/24", nil)

	// Put the evil udp addr in for their vpn Ip, this is a case of being lied to by the lighthouse.
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), evilUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl, evilControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()
	evilControl.Start()

	t.Log("Start the handshake process, we will route until we see the evil tunnel closed")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

	h := &header.H{}
	r.RouteForAllExitFunc(func(p *udp.Packet, c *nebula.Control) router.ExitType {
		err := h.Parse(p.Data)
		if err != nil {
			panic(err)
		}

		if h.Type == header.CloseTunnel && p.To == evilUdpAddr {
			return router.RouteAndExit
		}

		return router.KeepRouting
	})

	t.Log("Evil tunnel is closed, inject the correct udp addr for them")
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	pendingHi := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), true)
	assert.NotContains(t, pendingHi.RemoteAddrs, evilUdpAddr)

	t.Log("Route until we see the cached packet")
	r.RouteForAllExitFunc(func(p *udp.Packet, c *nebula.Control) router.ExitType {
		err := h.Parse(p.Data)
		if err != nil {
			panic(err)
		}

		if p.To == theirUdpAddr && h.Type == 1 {
			return router.RouteAndExit
		}

		return router.KeepRouting
	})

	t.Log("My cached packet should be received by them")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	t.Log("Test the tunnel with them")
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIpNet, theirVpnIpNet, myControl, theirControl)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	t.Log("Flush all packets from all controllers")
	r.FlushAll()

	t.Log("Ensure ensure I don't have any hostinfo artifacts from evil")
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(evilVpnIp[0].Addr(), true), "My pending hostmap should not contain evil")
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(evilVpnIp[0].Addr(), false), "My main hostmap should not contain evil")

	r.RenderHostmaps("Final hostmaps", myControl, theirControl, evilControl)
	t.Log("Success!")
	myControl.Stop()
	theirControl.Stop()
}

func TestWrongResponderHandshakeStaticHostMap(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.99/24", nil)
	evilControl, evilVpnIp, evilUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "evil", "10.128.0.2/24", nil)
	o := m{
		"static_host_map": m{
			theirVpnIpNet[0].Addr().String(): []string{evilUdpAddr.String()},
		},
	}
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.100/24", o)

	// Put the evil udp addr in for their vpn addr, this is a case of a remote at a static entry changing its vpn addr.
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), evilUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl, evilControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()
	evilControl.Start()

	t.Log("Start the handshake process, we will route until we see the evil tunnel closed")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

	h := &header.H{}
	r.RouteForAllExitFunc(func(p *udp.Packet, c *nebula.Control) router.ExitType {
		err := h.Parse(p.Data)
		if err != nil {
			panic(err)
		}

		if h.Type == header.CloseTunnel && p.To == evilUdpAddr {
			return router.RouteAndExit
		}

		return router.KeepRouting
	})

	t.Log("Evil tunnel is closed, inject the correct udp addr for them")
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	pendingHi := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), true)
	assert.NotContains(t, pendingHi.RemoteAddrs, evilUdpAddr)

	t.Log("Route until we see the cached packet")
	r.RouteForAllExitFunc(func(p *udp.Packet, c *nebula.Control) router.ExitType {
		err := h.Parse(p.Data)
		if err != nil {
			panic(err)
		}

		if p.To == theirUdpAddr && h.Type == 1 {
			return router.RouteAndExit
		}

		return router.KeepRouting
	})

	t.Log("My cached packet should be received by them")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	t.Log("Test the tunnel with them")
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIpNet, theirVpnIpNet, myControl, theirControl)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	t.Log("Flush all packets from all controllers")
	r.FlushAll()

	t.Log("Ensure ensure I don't have any hostinfo artifacts from evil")
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(evilVpnIp[0].Addr(), true), "My pending hostmap should not contain evil")
	assert.Nil(t, myControl.GetHostInfoByVpnAddr(evilVpnIp[0].Addr(), false), "My main hostmap should not contain evil")
	//NOTE: if evil lost the handshake race it may still have a tunnel since me would reject the handshake since the tunnel is complete

	r.RenderHostmaps("Final hostmaps", myControl, theirControl, evilControl)
	t.Log("Success!")
	myControl.Stop()
	theirControl.Stop()
}

func TestStage1Race(t *testing.T) {
	// This tests ensures that two hosts handshaking with each other at the same time will allow traffic to flow
	// But will eventually collapse down to a single tunnel

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	// Put their info in our lighthouse and vice versa
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake to start on both me and them")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))
	theirControl.InjectTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("Hi from them"))

	t.Log("Get both stage 1 handshake packets")
	myHsForThem := myControl.GetFromUDP(true)
	theirHsForMe := theirControl.GetFromUDP(true)

	r.Log("Now inject both stage 1 handshake packets")
	r.InjectUDPPacket(theirControl, myControl, theirHsForMe)
	r.InjectUDPPacket(myControl, theirControl, myHsForThem)

	r.Log("Route until they receive a message packet")
	myCachedPacket := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	r.Log("Their cached packet should be received by me")
	theirCachedPacket := r.RouteForAllUntilTxTun(myControl)
	assertUdpPacket(t, []byte("Hi from them"), theirCachedPacket, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), 80, 80)

	r.Log("Do a bidirectional tunnel test")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myHostmapHosts := myControl.ListHostmapHosts(false)
	myHostmapIndexes := myControl.ListHostmapIndexes(false)
	theirHostmapHosts := theirControl.ListHostmapHosts(false)
	theirHostmapIndexes := theirControl.ListHostmapIndexes(false)

	// We should have two tunnels on both sides
	assert.Len(t, myHostmapHosts, 1)
	assert.Len(t, theirHostmapHosts, 1)
	assert.Len(t, myHostmapIndexes, 2)
	assert.Len(t, theirHostmapIndexes, 2)

	r.RenderHostmaps("Starting hostmaps", myControl, theirControl)

	r.Log("Spin until connection manager tears down a tunnel")

	for len(myControl.GetHostmap().Indexes)+len(theirControl.GetHostmap().Indexes) > 2 {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		t.Log("Connection manager hasn't ticked yet")
		time.Sleep(time.Second)
	}

	myFinalHostmapHosts := myControl.ListHostmapHosts(false)
	myFinalHostmapIndexes := myControl.ListHostmapIndexes(false)
	theirFinalHostmapHosts := theirControl.ListHostmapHosts(false)
	theirFinalHostmapIndexes := theirControl.ListHostmapIndexes(false)

	// We should only have a single tunnel now on both sides
	assert.Len(t, myFinalHostmapHosts, 1)
	assert.Len(t, theirFinalHostmapHosts, 1)
	assert.Len(t, myFinalHostmapIndexes, 1)
	assert.Len(t, theirFinalHostmapIndexes, 1)

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)
	myControl.Stop()
	theirControl.Stop()
}

func TestUncleanShutdownRaceLoser(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	r.Log("Trigger a handshake from me to them")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	r.Log("Nuke my hostmap")
	myHostmap := myControl.GetHostmap()
	myHostmap.Hosts = map[netip.Addr]*nebula.HostInfo{}
	myHostmap.Indexes = map[uint32]*nebula.HostInfo{}
	myHostmap.RemoteIndexes = map[uint32]*nebula.HostInfo{}

	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me again"))
	p = r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me again"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	r.Log("Assert the tunnel works")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	r.Log("Wait for the dead index to go away")
	start := len(theirControl.GetHostmap().Indexes)
	for {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		if len(theirControl.GetHostmap().Indexes) < start {
			break
		}
		time.Sleep(time.Second)
	}

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)
}

func TestUncleanShutdownRaceWinner(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	r.Log("Trigger a handshake from me to them")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	r.RenderHostmaps("Final hostmaps", myControl, theirControl)

	r.Log("Nuke my hostmap")
	theirHostmap := theirControl.GetHostmap()
	theirHostmap.Hosts = map[netip.Addr]*nebula.HostInfo{}
	theirHostmap.Indexes = map[uint32]*nebula.HostInfo{}
	theirHostmap.RemoteIndexes = map[uint32]*nebula.HostInfo{}

	theirControl.InjectTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("Hi from them again"))
	p = r.RouteForAllUntilTxTun(myControl)
	assertUdpPacket(t, []byte("Hi from them again"), p, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), 80, 80)
	r.RenderHostmaps("Derp hostmaps", myControl, theirControl)

	r.Log("Assert the tunnel works")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	r.Log("Wait for the dead index to go away")
	start := len(myControl.GetHostmap().Indexes)
	for {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		if len(myControl.GetHostmap().Indexes) < start {
			break
		}
		time.Sleep(time.Second)
	}

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)
}

func TestRelays(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake from me to them via the relay")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	r.RenderHostmaps("Final hostmaps", myControl, relayControl, theirControl)
}

func TestReestablishRelays(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake from me to them via the relay")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	t.Log("Ensure packet traversal from them to me via the relay")
	theirControl.InjectTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("Hi from them"))

	p = r.RouteForAllUntilTxTun(myControl)
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from them"), p, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), 80, 80)

	// If we break the relay's connection to 'them', 'me' needs to detect and recover the connection
	r.Log("Close the tunnel")
	relayControl.CloseTunnel(theirVpnIpNet[0].Addr(), true)

	start := len(myControl.GetHostmap().Indexes)
	curIndexes := len(myControl.GetHostmap().Indexes)
	for curIndexes >= start {
		curIndexes = len(myControl.GetHostmap().Indexes)
		r.Logf("Wait for the dead index to go away:start=%v indexes, currnet=%v indexes", start, curIndexes)
		myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me should fail"))

		r.RouteForAllExitFunc(func(p *udp.Packet, c *nebula.Control) router.ExitType {
			return router.RouteAndExit
		})
		time.Sleep(2 * time.Second)
	}
	r.Log("Dead index went away. Woot!")
	r.RenderHostmaps("Me removed hostinfo", myControl, relayControl, theirControl)
	// Next packet should re-establish a relayed connection and work just great.

	t.Logf("Assert the tunnel...")
	for {
		t.Log("RouteForAllUntilTxTun")
		myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
		myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
		relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
		myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

		p = r.RouteForAllUntilTxTun(theirControl)
		r.Log("Assert the tunnel works")
		packet := gopacket.NewPacket(p, layers.LayerTypeIPv4, gopacket.Lazy)
		v4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if slices.Compare(v4.SrcIP, myVpnIpNet[0].Addr().AsSlice()) != 0 {
			t.Logf("SrcIP is unexpected...this is not the packet I'm looking for. Keep looking")
			continue
		}
		if slices.Compare(v4.DstIP, theirVpnIpNet[0].Addr().AsSlice()) != 0 {
			t.Logf("DstIP is unexpected...this is not the packet I'm looking for. Keep looking")
			continue
		}

		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if udp == nil {
			t.Log("Not a UDP packet. This is not the packet I'm looking for. Keep looking")
			continue
		}
		data := packet.ApplicationLayer()
		if data == nil {
			t.Log("No data found in packet. This is not the packet I'm looking for. Keep looking.")
			continue
		}
		if string(data.Payload()) != "Hi from me" {
			t.Logf("Unexpected payload: '%v', keep looking", string(data.Payload()))
			continue
		}
		t.Log("I found my lost packet. I am so happy.")
		break
	}
	t.Log("Assert the tunnel works the other way, too")
	for {
		t.Log("RouteForAllUntilTxTun")
		theirControl.InjectTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("Hi from them"))

		p = r.RouteForAllUntilTxTun(myControl)
		r.Log("Assert the tunnel works")
		packet := gopacket.NewPacket(p, layers.LayerTypeIPv4, gopacket.Lazy)
		v4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if slices.Compare(v4.DstIP, myVpnIpNet[0].Addr().AsSlice()) != 0 {
			t.Logf("Dst is unexpected...this is not the packet I'm looking for. Keep looking")
			continue
		}
		if slices.Compare(v4.SrcIP, theirVpnIpNet[0].Addr().AsSlice()) != 0 {
			t.Logf("SrcIP is unexpected...this is not the packet I'm looking for. Keep looking")
			continue
		}

		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if udp == nil {
			t.Log("Not a UDP packet. This is not the packet I'm looking for. Keep looking")
			continue
		}
		data := packet.ApplicationLayer()
		if data == nil {
			t.Log("No data found in packet. This is not the packet I'm looking for. Keep looking.")
			continue
		}
		if string(data.Payload()) != "Hi from them" {
			t.Logf("Unexpected payload: '%v', keep looking", string(data.Payload()))
			continue
		}
		t.Log("I found my lost packet. I am so happy.")
		break
	}
	r.RenderHostmaps("Final hostmaps", myControl, relayControl, theirControl)

}

func TestStage1RaceRelays(t *testing.T) {
	//NOTE: this is a race between me and relay resulting in a full tunnel from me to them via relay
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	theirControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)

	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	theirControl.InjectRelays(myVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})

	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	relayControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	r.Log("Get a tunnel between me and relay")
	assertTunnel(t, myVpnIpNet[0].Addr(), relayVpnIpNet[0].Addr(), myControl, relayControl, r)

	r.Log("Get a tunnel between them and relay")
	assertTunnel(t, theirVpnIpNet[0].Addr(), relayVpnIpNet[0].Addr(), theirControl, relayControl, r)

	r.Log("Trigger a handshake from both them and me via relay to them and me")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))
	theirControl.InjectTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("Hi from them"))

	r.Log("Wait for a packet from them to me")
	p := r.RouteForAllUntilTxTun(myControl)
	_ = p

	r.FlushAll()

	myControl.Stop()
	theirControl.Stop()
	relayControl.Stop()
}

func TestStage1RaceRelays2(t *testing.T) {
	//NOTE: this is a race between me and relay resulting in a full tunnel from me to them via relay
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})
	l := NewTestLogger()

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	theirControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)

	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	theirControl.InjectRelays(myVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})

	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	relayControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	r.Log("Get a tunnel between me and relay")
	l.Info("Get a tunnel between me and relay")
	assertTunnel(t, myVpnIpNet[0].Addr(), relayVpnIpNet[0].Addr(), myControl, relayControl, r)

	r.Log("Get a tunnel between them and relay")
	l.Info("Get a tunnel between them and relay")
	assertTunnel(t, theirVpnIpNet[0].Addr(), relayVpnIpNet[0].Addr(), theirControl, relayControl, r)

	r.Log("Trigger a handshake from both them and me via relay to them and me")
	l.Info("Trigger a handshake from both them and me via relay to them and me")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))
	theirControl.InjectTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("Hi from them"))

	//r.RouteUntilAfterMsgType(myControl, header.Control, header.MessageNone)
	//r.RouteUntilAfterMsgType(theirControl, header.Control, header.MessageNone)

	r.Log("Wait for a packet from them to me")
	l.Info("Wait for a packet from them to me; myControl")
	r.RouteForAllUntilTxTun(myControl)
	l.Info("Wait for a packet from them to me; theirControl")
	r.RouteForAllUntilTxTun(theirControl)

	r.Log("Assert the tunnel works")
	l.Info("Assert the tunnel works")
	assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)

	t.Log("Wait until we remove extra tunnels")
	l.Info("Wait until we remove extra tunnels")
	l.WithFields(
		logrus.Fields{
			"myControl":    len(myControl.GetHostmap().Indexes),
			"theirControl": len(theirControl.GetHostmap().Indexes),
			"relayControl": len(relayControl.GetHostmap().Indexes),
		}).Info("Waiting for hostinfos to be removed...")
	hostInfos := len(myControl.GetHostmap().Indexes) + len(theirControl.GetHostmap().Indexes) + len(relayControl.GetHostmap().Indexes)
	retries := 60
	for hostInfos > 6 && retries > 0 {
		hostInfos = len(myControl.GetHostmap().Indexes) + len(theirControl.GetHostmap().Indexes) + len(relayControl.GetHostmap().Indexes)
		l.WithFields(
			logrus.Fields{
				"myControl":    len(myControl.GetHostmap().Indexes),
				"theirControl": len(theirControl.GetHostmap().Indexes),
				"relayControl": len(relayControl.GetHostmap().Indexes),
			}).Info("Waiting for hostinfos to be removed...")
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		t.Log("Connection manager hasn't ticked yet")
		time.Sleep(time.Second)
		retries--
	}

	r.Log("Assert the tunnel works")
	l.Info("Assert the tunnel works")
	assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)

	myControl.Stop()
	theirControl.Stop()
	relayControl.Stop()
}

func TestRehandshakingRelays(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, relayConfig := newSimpleServer(cert.Version1, ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake from me to them via the relay")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	r.RenderHostmaps("working hostmaps", myControl, relayControl, theirControl)

	// When I update the certificate for the relay, both me and them will have 2 host infos for the relay,
	// and the main host infos will not have any relay state to handle the me<->relay<->them tunnel.
	r.Log("Renew relay certificate and spin until me and them sees it")
	_, _, myNextPrivKey, myNextPEM := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, "relay", time.Now(), time.Now().Add(5*time.Minute), relayVpnIpNet, nil, []string{"new group"})

	caB, err := ca.MarshalPEM()
	if err != nil {
		panic(err)
	}

	relayConfig.Settings["pki"] = m{
		"ca":   string(caB),
		"cert": string(myNextPEM),
		"key":  string(myNextPrivKey),
	}
	rc, err := yaml.Marshal(relayConfig.Settings)
	require.NoError(t, err)
	relayConfig.ReloadConfigString(string(rc))

	for {
		r.Log("Assert the tunnel works between myVpnIpNet and relayVpnIpNet")
		assertTunnel(t, myVpnIpNet[0].Addr(), relayVpnIpNet[0].Addr(), myControl, relayControl, r)
		c := myControl.GetHostInfoByVpnAddr(relayVpnIpNet[0].Addr(), false)
		if len(c.Cert.Groups()) != 0 {
			// We have a new certificate now
			r.Log("Certificate between my and relay is updated!")
			break
		}

		time.Sleep(time.Second)
	}

	for {
		r.Log("Assert the tunnel works between theirVpnIpNet and relayVpnIpNet")
		assertTunnel(t, theirVpnIpNet[0].Addr(), relayVpnIpNet[0].Addr(), theirControl, relayControl, r)
		c := theirControl.GetHostInfoByVpnAddr(relayVpnIpNet[0].Addr(), false)
		if len(c.Cert.Groups()) != 0 {
			// We have a new certificate now
			r.Log("Certificate between their and relay is updated!")
			break
		}

		time.Sleep(time.Second)
	}

	r.Log("Assert the relay tunnel still works")
	assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)
	r.RenderHostmaps("working hostmaps", myControl, relayControl, theirControl)
	// We should have two hostinfos on all sides
	for len(myControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for myControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(myControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("myControl hostinfos got cleaned up!")
	for len(theirControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for theirControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(theirControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("theirControl hostinfos got cleaned up!")
	for len(relayControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for relayControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(relayControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("relayControl hostinfos got cleaned up!")
}

func TestRehandshakingRelaysPrimary(t *testing.T) {
	// This test is the same as TestRehandshakingRelays but one of the terminal types is a primary swap winner
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.128/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, relayConfig := newSimpleServer(cert.Version1, ca, caKey, "relay  ", "10.128.0.1/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake from me to them via the relay")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	r.RenderHostmaps("working hostmaps", myControl, relayControl, theirControl)

	// When I update the certificate for the relay, both me and them will have 2 host infos for the relay,
	// and the main host infos will not have any relay state to handle the me<->relay<->them tunnel.
	r.Log("Renew relay certificate and spin until me and them sees it")
	_, _, myNextPrivKey, myNextPEM := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, "relay", time.Now(), time.Now().Add(5*time.Minute), relayVpnIpNet, nil, []string{"new group"})

	caB, err := ca.MarshalPEM()
	if err != nil {
		panic(err)
	}

	relayConfig.Settings["pki"] = m{
		"ca":   string(caB),
		"cert": string(myNextPEM),
		"key":  string(myNextPrivKey),
	}
	rc, err := yaml.Marshal(relayConfig.Settings)
	require.NoError(t, err)
	relayConfig.ReloadConfigString(string(rc))

	for {
		r.Log("Assert the tunnel works between myVpnIpNet and relayVpnIpNet")
		assertTunnel(t, myVpnIpNet[0].Addr(), relayVpnIpNet[0].Addr(), myControl, relayControl, r)
		c := myControl.GetHostInfoByVpnAddr(relayVpnIpNet[0].Addr(), false)
		if len(c.Cert.Groups()) != 0 {
			// We have a new certificate now
			r.Log("Certificate between my and relay is updated!")
			break
		}

		time.Sleep(time.Second)
	}

	for {
		r.Log("Assert the tunnel works between theirVpnIpNet and relayVpnIpNet")
		assertTunnel(t, theirVpnIpNet[0].Addr(), relayVpnIpNet[0].Addr(), theirControl, relayControl, r)
		c := theirControl.GetHostInfoByVpnAddr(relayVpnIpNet[0].Addr(), false)
		if len(c.Cert.Groups()) != 0 {
			// We have a new certificate now
			r.Log("Certificate between their and relay is updated!")
			break
		}

		time.Sleep(time.Second)
	}

	r.Log("Assert the relay tunnel still works")
	assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)
	r.RenderHostmaps("working hostmaps", myControl, relayControl, theirControl)
	// We should have two hostinfos on all sides
	for len(myControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for myControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(myControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("myControl hostinfos got cleaned up!")
	for len(theirControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for theirControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(theirControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("theirControl hostinfos got cleaned up!")
	for len(relayControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for relayControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(relayControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("relayControl hostinfos got cleaned up!")
}

func TestRehandshaking(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, myConfig := newSimpleServer(cert.Version1, ca, caKey, "me  ", "10.128.0.2/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, theirConfig := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.1/24", nil)

	// Put their info in our lighthouse and vice versa
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Stand up a tunnel between me and them")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	r.RenderHostmaps("Starting hostmaps", myControl, theirControl)

	r.Log("Renew my certificate and spin until their sees it")
	_, _, myNextPrivKey, myNextPEM := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, "me", time.Now(), time.Now().Add(5*time.Minute), myVpnIpNet, nil, []string{"new group"})

	caB, err := ca.MarshalPEM()
	if err != nil {
		panic(err)
	}

	myConfig.Settings["pki"] = m{
		"ca":   string(caB),
		"cert": string(myNextPEM),
		"key":  string(myNextPrivKey),
	}
	rc, err := yaml.Marshal(myConfig.Settings)
	require.NoError(t, err)
	myConfig.ReloadConfigString(string(rc))

	for {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		c := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
		if len(c.Cert.Groups()) != 0 {
			// We have a new certificate now
			break
		}

		time.Sleep(time.Second)
	}

	r.Log("Got the new cert")
	// Flip their firewall to only allowing the new group to catch the tunnels reverting incorrectly
	rc, err = yaml.Marshal(theirConfig.Settings)
	require.NoError(t, err)
	var theirNewConfig m
	require.NoError(t, yaml.Unmarshal(rc, &theirNewConfig))
	theirFirewall := theirNewConfig["firewall"].(map[string]any)
	theirFirewall["inbound"] = []m{{
		"proto": "any",
		"port":  "any",
		"group": "new group",
	}}
	rc, err = yaml.Marshal(theirNewConfig)
	require.NoError(t, err)
	theirConfig.ReloadConfigString(string(rc))

	r.Log("Spin until there is only 1 tunnel")
	for len(myControl.GetHostmap().Indexes)+len(theirControl.GetHostmap().Indexes) > 2 {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		t.Log("Connection manager hasn't ticked yet")
		time.Sleep(time.Second)
	}

	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
	myFinalHostmapHosts := myControl.ListHostmapHosts(false)
	myFinalHostmapIndexes := myControl.ListHostmapIndexes(false)
	theirFinalHostmapHosts := theirControl.ListHostmapHosts(false)
	theirFinalHostmapIndexes := theirControl.ListHostmapIndexes(false)

	// Make sure the correct tunnel won
	c := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
	assert.Contains(t, c.Cert.Groups(), "new group")

	// We should only have a single tunnel now on both sides
	assert.Len(t, myFinalHostmapHosts, 1)
	assert.Len(t, theirFinalHostmapHosts, 1)
	assert.Len(t, myFinalHostmapIndexes, 1)
	assert.Len(t, theirFinalHostmapIndexes, 1)

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)

	myControl.Stop()
	theirControl.Stop()
}

func TestRehandshakingLoser(t *testing.T) {
	// The purpose of this test is that the race loser renews their certificate and rehandshakes. The final tunnel
	// Should be the one with the new certificate
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, myConfig := newSimpleServer(cert.Version1, ca, caKey, "me  ", "10.128.0.2/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, theirConfig := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.1/24", nil)

	// Put their info in our lighthouse and vice versa
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Stand up a tunnel between me and them")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	r.RenderHostmaps("Starting hostmaps", myControl, theirControl)

	r.Log("Renew their certificate and spin until mine sees it")
	_, _, theirNextPrivKey, theirNextPEM := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, "them", time.Now(), time.Now().Add(5*time.Minute), theirVpnIpNet, nil, []string{"their new group"})

	caB, err := ca.MarshalPEM()
	if err != nil {
		panic(err)
	}

	theirConfig.Settings["pki"] = m{
		"ca":   string(caB),
		"cert": string(theirNextPEM),
		"key":  string(theirNextPrivKey),
	}
	rc, err := yaml.Marshal(theirConfig.Settings)
	require.NoError(t, err)
	theirConfig.ReloadConfigString(string(rc))

	for {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		theirCertInMe := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false)

		if slices.Contains(theirCertInMe.Cert.Groups(), "their new group") {
			break
		}

		time.Sleep(time.Second)
	}

	// Flip my firewall to only allowing the new group to catch the tunnels reverting incorrectly
	rc, err = yaml.Marshal(myConfig.Settings)
	require.NoError(t, err)
	var myNewConfig m
	require.NoError(t, yaml.Unmarshal(rc, &myNewConfig))
	theirFirewall := myNewConfig["firewall"].(map[string]any)
	theirFirewall["inbound"] = []m{{
		"proto": "any",
		"port":  "any",
		"group": "their new group",
	}}
	rc, err = yaml.Marshal(myNewConfig)
	require.NoError(t, err)
	myConfig.ReloadConfigString(string(rc))

	r.Log("Spin until there is only 1 tunnel")
	for len(myControl.GetHostmap().Indexes)+len(theirControl.GetHostmap().Indexes) > 2 {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		t.Log("Connection manager hasn't ticked yet")
		time.Sleep(time.Second)
	}

	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
	myFinalHostmapHosts := myControl.ListHostmapHosts(false)
	myFinalHostmapIndexes := myControl.ListHostmapIndexes(false)
	theirFinalHostmapHosts := theirControl.ListHostmapHosts(false)
	theirFinalHostmapIndexes := theirControl.ListHostmapIndexes(false)

	// Make sure the correct tunnel won
	theirCertInMe := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false)
	assert.Contains(t, theirCertInMe.Cert.Groups(), "their new group")

	// We should only have a single tunnel now on both sides
	assert.Len(t, myFinalHostmapHosts, 1)
	assert.Len(t, theirFinalHostmapHosts, 1)
	assert.Len(t, myFinalHostmapIndexes, 1)
	assert.Len(t, theirFinalHostmapIndexes, 1)

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)
	myControl.Stop()
	theirControl.Stop()
}

func TestRaceRegression(t *testing.T) {
	// This test forces stage 1, stage 2, stage 1 to be received by me from them
	// We had a bug where we were not finding the duplicate handshake and responding to the final stage 1 which
	// caused a cross-linked hostinfo
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	// Put their info in our lighthouse
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	//them rx stage:1 initiatorIndex=642843150 responderIndex=0
	//me rx   stage:1 initiatorIndex=120607833 responderIndex=0
	//them rx stage:1 initiatorIndex=642843150 responderIndex=0
	//me rx   stage:2 initiatorIndex=642843150 responderIndex=3701775874
	//me rx   stage:1 initiatorIndex=120607833 responderIndex=0
	//them rx stage:2 initiatorIndex=120607833 responderIndex=4209862089

	t.Log("Start both handshakes")
	myControl.InjectTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))
	theirControl.InjectTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("Hi from them"))

	t.Log("Get both stage 1")
	myStage1ForThem := myControl.GetFromUDP(true)
	theirStage1ForMe := theirControl.GetFromUDP(true)

	t.Log("Inject them in a special way")
	theirControl.InjectUDPPacket(myStage1ForThem)
	myControl.InjectUDPPacket(theirStage1ForMe)
	theirControl.InjectUDPPacket(myStage1ForThem)

	t.Log("Get both stage 2")
	myStage2ForThem := myControl.GetFromUDP(true)
	theirStage2ForMe := theirControl.GetFromUDP(true)

	t.Log("Inject them in a special way again")
	myControl.InjectUDPPacket(theirStage2ForMe)
	myControl.InjectUDPPacket(theirStage1ForMe)
	theirControl.InjectUDPPacket(myStage2ForThem)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	t.Log("Flush the packets")
	r.RouteForAllUntilTxTun(myControl)
	r.RouteForAllUntilTxTun(theirControl)
	r.RenderHostmaps("Starting hostmaps", myControl, theirControl)

	t.Log("Make sure the tunnel still works")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

func TestV2NonPrimaryWithLighthouse(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	lhControl, lhVpnIpNet, lhUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "lh  ", "10.128.0.1/24, ff::1/64", m{"lighthouse": m{"am_lighthouse": true}})

	o := m{
		"static_host_map": m{
			lhVpnIpNet[1].Addr().String(): []string{lhUdpAddr.String()},
		},
		"lighthouse": m{
			"hosts": []string{lhVpnIpNet[1].Addr().String()},
			"local_allow_list": m{
				// Try and block our lighthouse updates from using the actual addresses assigned to this computer
				// If we start discovering addresses the test router doesn't know about then test traffic cant flow
				"10.0.0.0/24": true,
				"::/0":        false,
			},
		},
	}
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version2, ca, caKey, "me  ", "10.128.0.2/24, ff::2/64", o)
	theirControl, theirVpnIpNet, _, _ := newSimpleServer(cert.Version2, ca, caKey, "them", "10.128.0.3/24, ff::3/64", o)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, lhControl, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	lhControl.Start()
	myControl.Start()
	theirControl.Start()

	t.Log("Stand up an ipv6 tunnel between me and them")
	assert.True(t, myVpnIpNet[1].Addr().Is6())
	assert.True(t, theirVpnIpNet[1].Addr().Is6())
	assertTunnel(t, myVpnIpNet[1].Addr(), theirVpnIpNet[1].Addr(), myControl, theirControl, r)

	lhControl.Stop()
	myControl.Stop()
	theirControl.Stop()
}
