// +build e2e_testing

package e2e

import (
	"net"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/stretchr/testify/assert"
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

	t.Log("Send a udp packet through to begin standing up the tunnel, this should come out the other side")
	myControl.InjectTunUDPPacket(theirVpnIp, 80, 80, []byte("Hi from me"))

	t.Log("Have them consume my stage 0 packet. They have a tunnel now")
	theirControl.InjectUDPPacket(myControl.GetFromUDP(true))

	t.Log("Get their stage 1 packet so that we can play with it")
	stage1Packet := theirControl.GetFromUDP(true)

	t.Log("I consume a garbage packet with a proper nebula header for our tunnel")
	// this should log a statement and get ignored, allowing the real handshake packet to complete the tunnel
	badPacket := stage1Packet.Copy()
	badPacket.Data = badPacket.Data[:len(badPacket.Data)-nebula.HeaderLen]
	myControl.InjectUDPPacket(badPacket)

	t.Log("Have me consume their real stage 1 packet. I have a tunnel now")
	myControl.InjectUDPPacket(stage1Packet)

	t.Log("Wait until we see my cached packet come through")
	myControl.WaitForType(1, 0, theirControl)

	t.Log("Make sure our host infos are correct")
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIp, theirVpnIp, myControl, theirControl)

	t.Log("Get that cached packet and make sure it looks right")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIp, theirVpnIp, 80, 80)

	t.Log("Do a bidirectional tunnel test")
	assertTunnel(t, myVpnIp, theirVpnIp, myControl, theirControl, router.NewR(myControl, theirControl))

	myControl.Stop()
	theirControl.Stop()
	//TODO: assert hostmaps
}

func TestWrongResponderHandshake(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})

	// The IPs here are chosen on purpose:
	// The current remote handling will sort by preference, public, and then lexically.
	// So we need them to have a higher address than evil (we could apply a preference though)
	myControl, myVpnIp, myUdpAddr := newSimpleServer(ca, caKey, "me", net.IP{10, 0, 0, 100})
	theirControl, theirVpnIp, theirUdpAddr := newSimpleServer(ca, caKey, "them", net.IP{10, 0, 0, 99})
	evilControl, evilVpnIp, evilUdpAddr := newSimpleServer(ca, caKey, "evil", net.IP{10, 0, 0, 2})

	// Add their real udp addr, which should be tried after evil.
	myControl.InjectLightHouseAddr(theirVpnIp, theirUdpAddr)

	// Put the evil udp addr in for their vpn Ip, this is a case of being lied to by the lighthouse.
	myControl.InjectLightHouseAddr(theirVpnIp, evilUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(myControl, theirControl, evilControl)

	// Start the servers
	myControl.Start()
	theirControl.Start()
	evilControl.Start()

	t.Log("Start the handshake process, we will route until we see our cached packet get sent to them")
	myControl.InjectTunUDPPacket(theirVpnIp, 80, 80, []byte("Hi from me"))
	r.RouteForAllExitFunc(func(p *nebula.UdpPacket, c *nebula.Control) router.ExitType {
		h := &nebula.Header{}
		err := h.Parse(p.Data)
		if err != nil {
			panic(err)
		}

		if p.ToIp.Equal(theirUdpAddr.IP) && p.ToPort == uint16(theirUdpAddr.Port) && h.Type == 1 {
			return router.RouteAndExit
		}

		return router.KeepRouting
	})

	//TODO: Assert pending hostmap - I should have a correct hostinfo for them now

	t.Log("My cached packet should be received by them")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIp, theirVpnIp, 80, 80)

	t.Log("Test the tunnel with them")
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIp, theirVpnIp, myControl, theirControl)
	assertTunnel(t, myVpnIp, theirVpnIp, myControl, theirControl, r)

	t.Log("Flush all packets from all controllers")
	r.FlushAll()

	t.Log("Ensure ensure I don't have any hostinfo artifacts from evil")
	assert.Nil(t, myControl.GetHostInfoByVpnIP(ip2int(evilVpnIp), true), "My pending hostmap should not contain evil")
	assert.Nil(t, myControl.GetHostInfoByVpnIP(ip2int(evilVpnIp), false), "My main hostmap should not contain evil")
	//NOTE: if evil lost the handshake race it may still have a tunnel since me would reject the handshake since the tunnel is complete

	//TODO: assert hostmaps for everyone
	t.Log("Success!")
	myControl.Stop()
	theirControl.Stop()
}

func Test_Case1_Stage1Race(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	myControl, myVpnIp, myUdpAddr := newSimpleServer(ca, caKey, "me  ", net.IP{10, 0, 0, 1})
	theirControl, theirVpnIp, theirUdpAddr := newSimpleServer(ca, caKey, "them", net.IP{10, 0, 0, 2})

	// Put their info in our lighthouse and vice versa
	myControl.InjectLightHouseAddr(theirVpnIp, theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIp, myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(myControl, theirControl)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake to start on both me and them")
	myControl.InjectTunUDPPacket(theirVpnIp, 80, 80, []byte("Hi from me"))
	theirControl.InjectTunUDPPacket(myVpnIp, 80, 80, []byte("Hi from them"))

	t.Log("Get both stage 1 handshake packets")
	myHsForThem := myControl.GetFromUDP(true)
	theirHsForMe := theirControl.GetFromUDP(true)

	t.Log("Now inject both stage 1 handshake packets")
	myControl.InjectUDPPacket(theirHsForMe)
	theirControl.InjectUDPPacket(myHsForThem)
	//TODO: they should win, grab their index for me and make sure I use it in the end.

	t.Log("They should not have a stage 2 (won the race) but I should send one")
	theirControl.InjectUDPPacket(myControl.GetFromUDP(true))

	t.Log("Route for me until I send a message packet to them")
	myControl.WaitForType(1, 0, theirControl)

	t.Log("My cached packet should be received by them")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIp, theirVpnIp, 80, 80)

	t.Log("Route for them until I send a message packet to me")
	theirControl.WaitForType(1, 0, myControl)

	t.Log("Their cached packet should be received by me")
	theirCachedPacket := myControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from them"), theirCachedPacket, theirVpnIp, myVpnIp, 80, 80)

	t.Log("Do a bidirectional tunnel test")
	assertTunnel(t, myVpnIp, theirVpnIp, myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
	//TODO: assert hostmaps
}

//TODO: add a test with many lies
