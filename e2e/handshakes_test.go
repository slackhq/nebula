// +build e2e_testing

package e2e

import (
	"net"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/e2e/router"
)

func TestGoodHandshake(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	myControl, myVpnIp, myUdpAddr := newSimpleServer(ca, caKey, "me", net.IP{10, 0, 0, 1})
	theirControl, theirVpnIp, theirUdpAddr := newSimpleServer(ca, caKey, "them", net.IP{10, 0, 0, 2})

	// Put their info in our lighthouse
	myControl.InjectLightHouseAddr(theirVpnIp, theirUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	// Send a udp packet through to begin standing up the tunnel, this should come out the other side
	myControl.InjectTunUDPPacket(theirVpnIp, 80, 80, []byte("Hi from me"))

	// Have them consume my stage 0 packet. They have a tunnel now
	theirControl.InjectUDPPacket(myControl.GetFromUDP(true))

	// Get their stage 1 packet so that we can play with it
	stage1Packet := theirControl.GetFromUDP(true)

	// I consume a garbage packet with a proper nebula header for our tunnel
	// this should log a statement and get ignored, allowing the real handshake packet to complete the tunnel
	badPacket := stage1Packet.Copy()
	badPacket.Data = badPacket.Data[:len(badPacket.Data)-nebula.HeaderLen]
	myControl.InjectUDPPacket(badPacket)

	// Have me consume their real stage 1 packet. I have a tunnel now
	myControl.InjectUDPPacket(stage1Packet)

	// Wait until we see my cached packet come through
	myControl.WaitForType(1, 0, theirControl)

	// Make sure our host infos are correct
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIp, theirVpnIp, myControl, theirControl)

	// Get that cached packet and make sure it looks right
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIp, theirVpnIp, 80, 80)

	// Do a bidirectional tunnel test
	assertTunnel(t, myVpnIp, theirVpnIp, myControl, theirControl, router.NewR(myControl, theirControl))

	myControl.Stop()
	theirControl.Stop()
	//TODO: assert hostmaps
}

func TestWrongResponderHandshake(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})

	myControl, myVpnIp, myUdpAddr := newSimpleServer(ca, caKey, "me", net.IP{10, 0, 0, 1})
	theirControl, theirVpnIp, theirUdpAddr := newSimpleServer(ca, caKey, "them", net.IP{10, 0, 0, 2})
	evilControl, evilVpnIp, evilUdpAddr := newSimpleServer(ca, caKey, "evil", net.IP{10, 0, 0, 99})

	// Put the evil udp addr in for their vpn Ip, this is a case of being lied to by the lighthouse
	myControl.InjectLightHouseAddr(theirVpnIp, evilUdpAddr)

	// But also add their real udp addr, which should be tried after evil
	myControl.InjectLightHouseAddr(theirVpnIp, theirUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(myControl, theirControl, evilControl)

	// Start the servers
	myControl.Start()
	theirControl.Start()
	evilControl.Start()

	t.Log("Stand up the tunnel with evil (because the lighthouse cache is lying to us about who it is)")
	myControl.InjectTunUDPPacket(theirVpnIp, 80, 80, []byte("Hi from me"))
	r.OnceFrom(myControl)
	r.OnceFrom(evilControl)

	t.Log("I should have a tunnel with evil now and there should not be a cached packet waiting for us")
	assertTunnel(t, myVpnIp, evilVpnIp, myControl, evilControl, r)
	assertHostInfoPair(t, myUdpAddr, evilUdpAddr, myVpnIp, evilVpnIp, myControl, evilControl)

	//TODO: Assert pending hostmap - I should have a correct hostinfo for them now

	t.Log("Lets let the messages fly, this time we should have a tunnel with them")
	r.OnceFrom(myControl)
	r.OnceFrom(theirControl)

	t.Log("I should now have a tunnel with them now and my original packet should get there")
	r.RouteUntilAfterMsgType(myControl, 1, 0)
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIp, theirVpnIp, 80, 80)

	t.Log("I should now have a proper tunnel with them")
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIp, theirVpnIp, myControl, theirControl)
	assertTunnel(t, myVpnIp, theirVpnIp, myControl, theirControl, r)

	t.Log("Lets make sure evil is still good")
	assertTunnel(t, myVpnIp, evilVpnIp, myControl, evilControl, r)

	//TODO: assert hostmaps for everyone
	t.Log("Success!")
	//TODO: myControl is attempting to shut down 2 tunnels but is blocked on the udp txChan after the first close message
	// what we really need here is a way to exit all the go routines loops (there are many)
	//myControl.Stop()
	//theirControl.Stop()
}

////TODO: We need to test lies both as the race winner and race loser
//func TestManyWrongResponderHandshake(t *testing.T) {
//	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
//
//	myControl, myVpnIp, myUdpAddr := newSimpleServer(ca, caKey, "me", net.IP{10, 0, 0, 99})
//	theirControl, theirVpnIp, theirUdpAddr := newSimpleServer(ca, caKey, "them", net.IP{10, 0, 0, 2})
//	evilControl, evilVpnIp, evilUdpAddr := newSimpleServer(ca, caKey, "evil", net.IP{10, 0, 0, 1})
//
//	t.Log("Build a router so we don't have to reason who gets which packet")
//	r := newRouter(myControl, theirControl, evilControl)
//
//	t.Log("Lets add more than 10 evil addresses, this exceeds the hostinfo remotes limit")
//	for i := 0; i < 10; i++ {
//		addr := net.UDPAddr{IP: evilUdpAddr.IP, Port: evilUdpAddr.Port + i}
//		myControl.InjectLightHouseAddr(theirVpnIp, &addr)
//		// We also need to tell our router about it
//		r.AddRoute(addr.IP, uint16(addr.Port), evilControl)
//	}
//
//	// Start the servers
//	myControl.Start()
//	theirControl.Start()
//	evilControl.Start()
//
//	t.Log("Stand up the tunnel with evil (because the lighthouse cache is lying to us about who it is)")
//	myControl.InjectTunUDPPacket(theirVpnIp, 80, 80, []byte("Hi from me"))
//
//	t.Log("We need to spin until we get to the right remote for them")
//	getOut := false
//	injected := false
//	for {
//		t.Log("Routing for me and evil while we work through the bad ips")
//		r.RouteExitFunc(myControl, func(packet *nebula.UdpPacket, receiver *nebula.Control) exitType {
//			// We should stop routing right after we see a packet coming from us to them
//			if *receiver == *theirControl {
//				getOut = true
//				return drainAndExit
//			}
//
//			// We need to poke our real ip in at some point, this is a well protected check looking for that moment
//			if *receiver == *evilControl {
//				hi := myControl.GetHostInfoByVpnIP(ip2int(theirVpnIp), true)
//				if !injected && len(hi.RemoteAddrs) == 1 {
//					t.Log("I am on my last ip for them, time to inject the real one into my lighthouse")
//					myControl.InjectLightHouseAddr(theirVpnIp, theirUdpAddr)
//					injected = true
//				}
//				return drainAndExit
//			}
//
//			return keepRouting
//		})
//
//		if getOut {
//			break
//		}
//
//		r.RouteForUntilAfterToAddr(evilControl, myUdpAddr, drainAndExit)
//	}
//
//	t.Log("I should have a tunnel with evil and them, evil should not have a cached packet")
//	assertTunnel(t, myVpnIp, evilVpnIp, myControl, evilControl, r)
//	evilHostInfo := myControl.GetHostInfoByVpnIP(ip2int(evilVpnIp), false)
//	realEvilUdpAddr := &net.UDPAddr{IP: evilHostInfo.CurrentRemote.IP, Port: int(evilHostInfo.CurrentRemote.Port)}
//
//	t.Log("Assert mine and evil's host pairs", evilUdpAddr, realEvilUdpAddr)
//	assertHostInfoPair(t, myUdpAddr, realEvilUdpAddr, myVpnIp, evilVpnIp, myControl, evilControl)
//
//	//t.Log("Draining everyones packets")
//	//r.Drain(theirControl)
//	//r.DrainAll(myControl, theirControl, evilControl)
//	//
//	//go func() {
//	//	for {
//	//		time.Sleep(10 * time.Millisecond)
//	//		t.Log(len(theirControl.GetUDPTxChan()))
//	//		t.Log(len(theirControl.GetTunTxChan()))
//	//		t.Log(len(myControl.GetUDPTxChan()))
//	//		t.Log(len(evilControl.GetUDPTxChan()))
//	//		t.Log("=====")
//	//	}
//	//}()
//
//	t.Log("I should have a tunnel with them now and my original packet should get there")
//	r.RouteUntilAfterMsgType(myControl, 1, 0)
//	myCachedPacket := theirControl.GetFromTun(true)
//
//	t.Log("Got the cached packet, lets test the tunnel")
//	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIp, theirVpnIp, 80, 80)
//
//	t.Log("Testing tunnels with them")
//	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIp, theirVpnIp, myControl, theirControl)
//	assertTunnel(t, myVpnIp, theirVpnIp, myControl, theirControl, r)
//
//	t.Log("Testing tunnels with evil")
//	assertTunnel(t, myVpnIp, evilVpnIp, myControl, evilControl, r)
//
//	//TODO: assert hostmaps for everyone
//}
