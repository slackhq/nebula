// +build e2e_testing

package e2e

import (
	"net"
	"testing"
	"time"
)

func TestGoodHandshake(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	defMask := net.IPMask{0, 0, 0, 0}

	myUdpAddr := &net.UDPAddr{IP: net.IP{10, 0, 0, 1}, Port: 4242}
	myVpnIpNet := &net.IPNet{IP: net.IP{10, 128, 0, 1}, Mask: defMask}
	myControl := newSimpleServer(ca, caKey, "me", myUdpAddr, myVpnIpNet)

	theirUdpAddr := &net.UDPAddr{IP: net.IP{10, 0, 0, 2}, Port: 4242}
	theirVpnIpNet := &net.IPNet{IP: net.IP{10, 128, 0, 2}, Mask: defMask}
	theirControl := newSimpleServer(ca, caKey, "them", theirUdpAddr, theirVpnIpNet)

	// Put their info in our lighthouse
	myControl.InjectLightHouseAddr(theirVpnIpNet.IP, theirUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	// Send a udp packet through to begin standing up the tunnel, this should come out the other side
	myControl.InjectTunUDPPacket(theirVpnIpNet.IP, 80, 80, []byte("Hi from me"))

	// Have them consume my stage 0 packet. They have a tunnel now
	theirControl.InjectUDPPacket(myControl.GetFromUDP(true))

	// Have me consume their stage 1 packet. I have a tunnel now
	myControl.InjectUDPPacket(theirControl.GetFromUDP(true))

	// Wait until we see my cached packet come through
	myControl.WaitForType(1, 0, theirControl)

	// Make sure our host infos are correct
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIpNet.IP, theirVpnIpNet.IP, myControl, theirControl)

	// Get that cached packet and make sure it looks right
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet.IP, theirVpnIpNet.IP, 80, 80)

	// Send a packet from them to me
	theirControl.InjectTunUDPPacket(myVpnIpNet.IP, 80, 80, []byte("Hi from them"))
	myControl.InjectUDPPacket(theirControl.GetFromUDP(true))
	theirPacket := myControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from them"), theirPacket, theirVpnIpNet.IP, myVpnIpNet.IP, 80, 80)

	// And once more from me to them
	myControl.InjectTunUDPPacket(theirVpnIpNet.IP, 80, 80, []byte("Hello again from me"))
	theirControl.InjectUDPPacket(myControl.GetFromUDP(true))
	myPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hello again from me"), myPacket, myVpnIpNet.IP, theirVpnIpNet.IP, 80, 80)
}
