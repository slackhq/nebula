//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func BenchmarkHotPath(b *testing.B) {
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, _, _, _ := newSimpleServer(ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", "10.128.0.2/24", nil)

	// Put their info in our lighthouse
	myControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	r := router.NewR(b, myControl, theirControl)
	r.CancelFlowLogs()

	for n := 0; n < b.N; n++ {
		myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))
		_ = r.RouteForAllUntilTxTun(theirControl)
	}

	myControl.Stop()
	theirControl.Stop()
}

func TestGoodHandshake(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", "10.128.0.2/24", nil)

	// Put their info in our lighthouse
	myControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Send a udp packet through to begin standing up the tunnel, this should come out the other side")
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))

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
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl)

	t.Log("Get that cached packet and make sure it looks right")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), 80, 80)

	t.Log("Do a bidirectional tunnel test")
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()
	assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)
	myControl.Stop()
	theirControl.Stop()
	//TODO: assert hostmaps
}

func TestWrongResponderHandshake(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	// The IPs here are chosen on purpose:
	// The current remote handling will sort by preference, public, and then lexically.
	// So we need them to have a higher address than evil (we could apply a preference though)
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me", "10.128.0.100/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", "10.128.0.99/24", nil)
	evilControl, evilVpnIp, evilUdpAddr, _ := newSimpleServer(ca, caKey, "evil", "10.128.0.2/24", nil)

	// Add their real udp addr, which should be tried after evil.
	myControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)

	// Put the evil udp addr in for their vpn Ip, this is a case of being lied to by the lighthouse.
	myControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), evilUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl, evilControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()
	evilControl.Start()

	t.Log("Start the handshake process, we will route until we see our cached packet get sent to them")
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))
	r.RouteForAllExitFunc(func(p *udp.Packet, c *nebula.Control) router.ExitType {
		h := &header.H{}
		err := h.Parse(p.Data)
		if err != nil {
			panic(err)
		}

		if p.To == theirUdpAddr && h.Type == 1 {
			return router.RouteAndExit
		}

		return router.KeepRouting
	})

	//TODO: Assert pending hostmap - I should have a correct hostinfo for them now

	t.Log("My cached packet should be received by them")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), 80, 80)

	t.Log("Test the tunnel with them")
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl)
	assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)

	t.Log("Flush all packets from all controllers")
	r.FlushAll()

	t.Log("Ensure ensure I don't have any hostinfo artifacts from evil")
	assert.Nil(t, myControl.GetHostInfoByVpnIp(evilVpnIp.Addr(), true), "My pending hostmap should not contain evil")
	assert.Nil(t, myControl.GetHostInfoByVpnIp(evilVpnIp.Addr(), false), "My main hostmap should not contain evil")
	//NOTE: if evil lost the handshake race it may still have a tunnel since me would reject the handshake since the tunnel is complete

	//TODO: assert hostmaps for everyone
	r.RenderHostmaps("Final hostmaps", myControl, theirControl, evilControl)
	t.Log("Success!")
	myControl.Stop()
	theirControl.Stop()
}

func TestStage1Race(t *testing.T) {
	// This tests ensures that two hosts handshaking with each other at the same time will allow traffic to flow
	// But will eventually collapse down to a single tunnel

	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", "10.128.0.2/24", nil)

	// Put their info in our lighthouse and vice versa
	myControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet.Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake to start on both me and them")
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))
	theirControl.InjectTunUDPPacket(myVpnIpNet.Addr(), 80, 80, []byte("Hi from them"))

	t.Log("Get both stage 1 handshake packets")
	myHsForThem := myControl.GetFromUDP(true)
	theirHsForMe := theirControl.GetFromUDP(true)

	r.Log("Now inject both stage 1 handshake packets")
	r.InjectUDPPacket(theirControl, myControl, theirHsForMe)
	r.InjectUDPPacket(myControl, theirControl, myHsForThem)

	r.Log("Route until they receive a message packet")
	myCachedPacket := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), 80, 80)

	r.Log("Their cached packet should be received by me")
	theirCachedPacket := r.RouteForAllUntilTxTun(myControl)
	assertUdpPacket(t, []byte("Hi from them"), theirCachedPacket, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), 80, 80)

	r.Log("Do a bidirectional tunnel test")
	assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)

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
		assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)
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
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", "10.128.0.2/24", nil)

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet.Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	r.Log("Trigger a handshake from me to them")
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), 80, 80)

	r.Log("Nuke my hostmap")
	myHostmap := myControl.GetHostmap()
	myHostmap.Hosts = map[netip.Addr]*nebula.HostInfo{}
	myHostmap.Indexes = map[uint32]*nebula.HostInfo{}
	myHostmap.RemoteIndexes = map[uint32]*nebula.HostInfo{}

	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me again"))
	p = r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me again"), p, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), 80, 80)

	r.Log("Assert the tunnel works")
	assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)

	r.Log("Wait for the dead index to go away")
	start := len(theirControl.GetHostmap().Indexes)
	for {
		assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)
		if len(theirControl.GetHostmap().Indexes) < start {
			break
		}
		time.Sleep(time.Second)
	}

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)
}

func TestUncleanShutdownRaceWinner(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", "10.128.0.2/24", nil)

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet.Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	r.Log("Trigger a handshake from me to them")
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), 80, 80)
	r.RenderHostmaps("Final hostmaps", myControl, theirControl)

	r.Log("Nuke my hostmap")
	theirHostmap := theirControl.GetHostmap()
	theirHostmap.Hosts = map[netip.Addr]*nebula.HostInfo{}
	theirHostmap.Indexes = map[uint32]*nebula.HostInfo{}
	theirHostmap.RemoteIndexes = map[uint32]*nebula.HostInfo{}

	theirControl.InjectTunUDPPacket(myVpnIpNet.Addr(), 80, 80, []byte("Hi from them again"))
	p = r.RouteForAllUntilTxTun(myControl)
	assertUdpPacket(t, []byte("Hi from them again"), p, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), 80, 80)
	r.RenderHostmaps("Derp hostmaps", myControl, theirControl)

	r.Log("Assert the tunnel works")
	assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)

	r.Log("Wait for the dead index to go away")
	start := len(myControl.GetHostmap().Indexes)
	for {
		assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)
		if len(myControl.GetHostmap().Indexes) < start {
			break
		}
		time.Sleep(time.Second)
	}

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)
}

func TestRelays(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet.Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet.Addr(), []netip.Addr{relayVpnIpNet.Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake from me to them via the relay")
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), 80, 80)
	r.RenderHostmaps("Final hostmaps", myControl, relayControl, theirControl)
	//TODO: assert we actually used the relay even though it should be impossible for a tunnel to have occurred without it
}

func TestStage1RaceRelays(t *testing.T) {
	//NOTE: this is a race between me and relay resulting in a full tunnel from me to them via relay
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet.Addr(), relayUdpAddr)
	theirControl.InjectLightHouseAddr(relayVpnIpNet.Addr(), relayUdpAddr)

	myControl.InjectRelays(theirVpnIpNet.Addr(), []netip.Addr{relayVpnIpNet.Addr()})
	theirControl.InjectRelays(myVpnIpNet.Addr(), []netip.Addr{relayVpnIpNet.Addr()})

	relayControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)
	relayControl.InjectLightHouseAddr(myVpnIpNet.Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	r.Log("Get a tunnel between me and relay")
	assertTunnel(t, myVpnIpNet.Addr(), relayVpnIpNet.Addr(), myControl, relayControl, r)

	r.Log("Get a tunnel between them and relay")
	assertTunnel(t, theirVpnIpNet.Addr(), relayVpnIpNet.Addr(), theirControl, relayControl, r)

	r.Log("Trigger a handshake from both them and me via relay to them and me")
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))
	theirControl.InjectTunUDPPacket(myVpnIpNet.Addr(), 80, 80, []byte("Hi from them"))

	r.Log("Wait for a packet from them to me")
	p := r.RouteForAllUntilTxTun(myControl)
	_ = p

	r.FlushAll()

	myControl.Stop()
	theirControl.Stop()
	relayControl.Stop()
	//
	////TODO: assert hostmaps
}

func TestStage1RaceRelays2(t *testing.T) {
	//NOTE: this is a race between me and relay resulting in a full tunnel from me to them via relay
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})
	l := NewTestLogger()

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet.Addr(), relayUdpAddr)
	theirControl.InjectLightHouseAddr(relayVpnIpNet.Addr(), relayUdpAddr)

	myControl.InjectRelays(theirVpnIpNet.Addr(), []netip.Addr{relayVpnIpNet.Addr()})
	theirControl.InjectRelays(myVpnIpNet.Addr(), []netip.Addr{relayVpnIpNet.Addr()})

	relayControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)
	relayControl.InjectLightHouseAddr(myVpnIpNet.Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	r.Log("Get a tunnel between me and relay")
	l.Info("Get a tunnel between me and relay")
	assertTunnel(t, myVpnIpNet.Addr(), relayVpnIpNet.Addr(), myControl, relayControl, r)

	r.Log("Get a tunnel between them and relay")
	l.Info("Get a tunnel between them and relay")
	assertTunnel(t, theirVpnIpNet.Addr(), relayVpnIpNet.Addr(), theirControl, relayControl, r)

	r.Log("Trigger a handshake from both them and me via relay to them and me")
	l.Info("Trigger a handshake from both them and me via relay to them and me")
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))
	theirControl.InjectTunUDPPacket(myVpnIpNet.Addr(), 80, 80, []byte("Hi from them"))

	//r.RouteUntilAfterMsgType(myControl, header.Control, header.MessageNone)
	//r.RouteUntilAfterMsgType(theirControl, header.Control, header.MessageNone)

	r.Log("Wait for a packet from them to me")
	l.Info("Wait for a packet from them to me; myControl")
	r.RouteForAllUntilTxTun(myControl)
	l.Info("Wait for a packet from them to me; theirControl")
	r.RouteForAllUntilTxTun(theirControl)

	r.Log("Assert the tunnel works")
	l.Info("Assert the tunnel works")
	assertTunnel(t, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), theirControl, myControl, r)

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
		assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)
		t.Log("Connection manager hasn't ticked yet")
		time.Sleep(time.Second)
		retries--
	}

	r.Log("Assert the tunnel works")
	l.Info("Assert the tunnel works")
	assertTunnel(t, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), theirControl, myControl, r)

	myControl.Stop()
	theirControl.Stop()
	relayControl.Stop()

	//
	////TODO: assert hostmaps
}

func TestRehandshakingRelays(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, relayConfig := newSimpleServer(ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet.Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet.Addr(), []netip.Addr{relayVpnIpNet.Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake from me to them via the relay")
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), 80, 80)
	r.RenderHostmaps("working hostmaps", myControl, relayControl, theirControl)

	// When I update the certificate for the relay, both me and them will have 2 host infos for the relay,
	// and the main host infos will not have any relay state to handle the me<->relay<->them tunnel.
	r.Log("Renew relay certificate and spin until me and them sees it")
	_, _, myNextPrivKey, myNextPEM := NewTestCert(ca, caKey, "relay", time.Now(), time.Now().Add(5*time.Minute), relayVpnIpNet, nil, []string{"new group"})

	caB, err := ca.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	relayConfig.Settings["pki"] = m{
		"ca":   string(caB),
		"cert": string(myNextPEM),
		"key":  string(myNextPrivKey),
	}
	rc, err := yaml.Marshal(relayConfig.Settings)
	assert.NoError(t, err)
	relayConfig.ReloadConfigString(string(rc))

	for {
		r.Log("Assert the tunnel works between myVpnIpNet and relayVpnIpNet")
		assertTunnel(t, myVpnIpNet.Addr(), relayVpnIpNet.Addr(), myControl, relayControl, r)
		c := myControl.GetHostInfoByVpnIp(relayVpnIpNet.Addr(), false)
		if len(c.Cert.Details.Groups) != 0 {
			// We have a new certificate now
			r.Log("Certificate between my and relay is updated!")
			break
		}

		time.Sleep(time.Second)
	}

	for {
		r.Log("Assert the tunnel works between theirVpnIpNet and relayVpnIpNet")
		assertTunnel(t, theirVpnIpNet.Addr(), relayVpnIpNet.Addr(), theirControl, relayControl, r)
		c := theirControl.GetHostInfoByVpnIp(relayVpnIpNet.Addr(), false)
		if len(c.Cert.Details.Groups) != 0 {
			// We have a new certificate now
			r.Log("Certificate between their and relay is updated!")
			break
		}

		time.Sleep(time.Second)
	}

	r.Log("Assert the relay tunnel still works")
	assertTunnel(t, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), theirControl, myControl, r)
	r.RenderHostmaps("working hostmaps", myControl, relayControl, theirControl)
	// We should have two hostinfos on all sides
	for len(myControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for myControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(myControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("myControl hostinfos got cleaned up!")
	for len(theirControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for theirControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(theirControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("theirControl hostinfos got cleaned up!")
	for len(relayControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for relayControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(relayControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("relayControl hostinfos got cleaned up!")
}

func TestRehandshakingRelaysPrimary(t *testing.T) {
	// This test is the same as TestRehandshakingRelays but one of the terminal types is a primary swap winner
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(ca, caKey, "me     ", "10.128.0.128/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, relayConfig := newSimpleServer(ca, caKey, "relay  ", "10.128.0.1/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet.Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet.Addr(), []netip.Addr{relayVpnIpNet.Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake from me to them via the relay")
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), 80, 80)
	r.RenderHostmaps("working hostmaps", myControl, relayControl, theirControl)

	// When I update the certificate for the relay, both me and them will have 2 host infos for the relay,
	// and the main host infos will not have any relay state to handle the me<->relay<->them tunnel.
	r.Log("Renew relay certificate and spin until me and them sees it")
	_, _, myNextPrivKey, myNextPEM := NewTestCert(ca, caKey, "relay", time.Now(), time.Now().Add(5*time.Minute), relayVpnIpNet, nil, []string{"new group"})

	caB, err := ca.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	relayConfig.Settings["pki"] = m{
		"ca":   string(caB),
		"cert": string(myNextPEM),
		"key":  string(myNextPrivKey),
	}
	rc, err := yaml.Marshal(relayConfig.Settings)
	assert.NoError(t, err)
	relayConfig.ReloadConfigString(string(rc))

	for {
		r.Log("Assert the tunnel works between myVpnIpNet and relayVpnIpNet")
		assertTunnel(t, myVpnIpNet.Addr(), relayVpnIpNet.Addr(), myControl, relayControl, r)
		c := myControl.GetHostInfoByVpnIp(relayVpnIpNet.Addr(), false)
		if len(c.Cert.Details.Groups) != 0 {
			// We have a new certificate now
			r.Log("Certificate between my and relay is updated!")
			break
		}

		time.Sleep(time.Second)
	}

	for {
		r.Log("Assert the tunnel works between theirVpnIpNet and relayVpnIpNet")
		assertTunnel(t, theirVpnIpNet.Addr(), relayVpnIpNet.Addr(), theirControl, relayControl, r)
		c := theirControl.GetHostInfoByVpnIp(relayVpnIpNet.Addr(), false)
		if len(c.Cert.Details.Groups) != 0 {
			// We have a new certificate now
			r.Log("Certificate between their and relay is updated!")
			break
		}

		time.Sleep(time.Second)
	}

	r.Log("Assert the relay tunnel still works")
	assertTunnel(t, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), theirControl, myControl, r)
	r.RenderHostmaps("working hostmaps", myControl, relayControl, theirControl)
	// We should have two hostinfos on all sides
	for len(myControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for myControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(myControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("myControl hostinfos got cleaned up!")
	for len(theirControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for theirControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(theirControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("theirControl hostinfos got cleaned up!")
	for len(relayControl.GetHostmap().Indexes) != 2 {
		t.Logf("Waiting for relayControl hostinfos (%v != 2) to get cleaned up from lack of use...", len(relayControl.GetHostmap().Indexes))
		r.Log("Assert the relay tunnel still works")
		assertTunnel(t, theirVpnIpNet.Addr(), myVpnIpNet.Addr(), theirControl, myControl, r)
		r.Log("yupitdoes")
		time.Sleep(time.Second)
	}
	t.Logf("relayControl hostinfos got cleaned up!")
}

func TestRehandshaking(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, myConfig := newSimpleServer(ca, caKey, "me  ", "10.128.0.2/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, theirConfig := newSimpleServer(ca, caKey, "them", "10.128.0.1/24", nil)

	// Put their info in our lighthouse and vice versa
	myControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet.Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Stand up a tunnel between me and them")
	assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)

	r.RenderHostmaps("Starting hostmaps", myControl, theirControl)

	r.Log("Renew my certificate and spin until their sees it")
	_, _, myNextPrivKey, myNextPEM := NewTestCert(ca, caKey, "me", time.Now(), time.Now().Add(5*time.Minute), myVpnIpNet, nil, []string{"new group"})

	caB, err := ca.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	myConfig.Settings["pki"] = m{
		"ca":   string(caB),
		"cert": string(myNextPEM),
		"key":  string(myNextPrivKey),
	}
	rc, err := yaml.Marshal(myConfig.Settings)
	assert.NoError(t, err)
	myConfig.ReloadConfigString(string(rc))

	for {
		assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)
		c := theirControl.GetHostInfoByVpnIp(myVpnIpNet.Addr(), false)
		if len(c.Cert.Details.Groups) != 0 {
			// We have a new certificate now
			break
		}

		time.Sleep(time.Second)
	}

	// Flip their firewall to only allowing the new group to catch the tunnels reverting incorrectly
	rc, err = yaml.Marshal(theirConfig.Settings)
	assert.NoError(t, err)
	var theirNewConfig m
	assert.NoError(t, yaml.Unmarshal(rc, &theirNewConfig))
	theirFirewall := theirNewConfig["firewall"].(map[interface{}]interface{})
	theirFirewall["inbound"] = []m{{
		"proto": "any",
		"port":  "any",
		"group": "new group",
	}}
	rc, err = yaml.Marshal(theirNewConfig)
	assert.NoError(t, err)
	theirConfig.ReloadConfigString(string(rc))

	r.Log("Spin until there is only 1 tunnel")
	for len(myControl.GetHostmap().Indexes)+len(theirControl.GetHostmap().Indexes) > 2 {
		assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)
		t.Log("Connection manager hasn't ticked yet")
		time.Sleep(time.Second)
	}

	assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)
	myFinalHostmapHosts := myControl.ListHostmapHosts(false)
	myFinalHostmapIndexes := myControl.ListHostmapIndexes(false)
	theirFinalHostmapHosts := theirControl.ListHostmapHosts(false)
	theirFinalHostmapIndexes := theirControl.ListHostmapIndexes(false)

	// Make sure the correct tunnel won
	c := theirControl.GetHostInfoByVpnIp(myVpnIpNet.Addr(), false)
	assert.Contains(t, c.Cert.Details.Groups, "new group")

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
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, myConfig := newSimpleServer(ca, caKey, "me  ", "10.128.0.2/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, theirConfig := newSimpleServer(ca, caKey, "them", "10.128.0.1/24", nil)

	// Put their info in our lighthouse and vice versa
	myControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet.Addr(), myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Stand up a tunnel between me and them")
	assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)

	tt1 := myControl.GetHostInfoByVpnIp(theirVpnIpNet.Addr(), false)
	tt2 := theirControl.GetHostInfoByVpnIp(myVpnIpNet.Addr(), false)
	fmt.Println(tt1.LocalIndex, tt2.LocalIndex)

	r.RenderHostmaps("Starting hostmaps", myControl, theirControl)

	r.Log("Renew their certificate and spin until mine sees it")
	_, _, theirNextPrivKey, theirNextPEM := NewTestCert(ca, caKey, "them", time.Now(), time.Now().Add(5*time.Minute), theirVpnIpNet, nil, []string{"their new group"})

	caB, err := ca.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	theirConfig.Settings["pki"] = m{
		"ca":   string(caB),
		"cert": string(theirNextPEM),
		"key":  string(theirNextPrivKey),
	}
	rc, err := yaml.Marshal(theirConfig.Settings)
	assert.NoError(t, err)
	theirConfig.ReloadConfigString(string(rc))

	for {
		assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)
		theirCertInMe := myControl.GetHostInfoByVpnIp(theirVpnIpNet.Addr(), false)

		_, theirNewGroup := theirCertInMe.Cert.Details.InvertedGroups["their new group"]
		if theirNewGroup {
			break
		}

		time.Sleep(time.Second)
	}

	// Flip my firewall to only allowing the new group to catch the tunnels reverting incorrectly
	rc, err = yaml.Marshal(myConfig.Settings)
	assert.NoError(t, err)
	var myNewConfig m
	assert.NoError(t, yaml.Unmarshal(rc, &myNewConfig))
	theirFirewall := myNewConfig["firewall"].(map[interface{}]interface{})
	theirFirewall["inbound"] = []m{{
		"proto": "any",
		"port":  "any",
		"group": "their new group",
	}}
	rc, err = yaml.Marshal(myNewConfig)
	assert.NoError(t, err)
	myConfig.ReloadConfigString(string(rc))

	r.Log("Spin until there is only 1 tunnel")
	for len(myControl.GetHostmap().Indexes)+len(theirControl.GetHostmap().Indexes) > 2 {
		assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)
		t.Log("Connection manager hasn't ticked yet")
		time.Sleep(time.Second)
	}

	assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)
	myFinalHostmapHosts := myControl.ListHostmapHosts(false)
	myFinalHostmapIndexes := myControl.ListHostmapIndexes(false)
	theirFinalHostmapHosts := theirControl.ListHostmapHosts(false)
	theirFinalHostmapIndexes := theirControl.ListHostmapIndexes(false)

	// Make sure the correct tunnel won
	theirCertInMe := myControl.GetHostInfoByVpnIp(theirVpnIpNet.Addr(), false)
	assert.Contains(t, theirCertInMe.Cert.Details.Groups, "their new group")

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
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", "10.128.0.2/24", nil)

	// Put their info in our lighthouse
	myControl.InjectLightHouseAddr(theirVpnIpNet.Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet.Addr(), myUdpAddr)

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
	myControl.InjectTunUDPPacket(theirVpnIpNet.Addr(), 80, 80, []byte("Hi from me"))
	theirControl.InjectTunUDPPacket(myVpnIpNet.Addr(), 80, 80, []byte("Hi from them"))

	t.Log("Get both stage 1")
	myStage1ForThem := myControl.GetFromUDP(true)
	theirStage1ForMe := theirControl.GetFromUDP(true)

	t.Log("Inject them in a special way")
	theirControl.InjectUDPPacket(myStage1ForThem)
	myControl.InjectUDPPacket(theirStage1ForMe)
	theirControl.InjectUDPPacket(myStage1ForThem)

	//TODO: ensure stage 2
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
	assertTunnel(t, myVpnIpNet.Addr(), theirVpnIpNet.Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

//TODO: test
// Race winner renews and handshakes
// Race loser renews and handshakes
// Does race winner repin the cert to old?
//TODO: add a test with many lies
