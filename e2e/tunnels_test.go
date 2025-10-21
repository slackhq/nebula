//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
)

func TestDropInactiveTunnels(t *testing.T) {
	// The goal of this test is to ensure the shortest inactivity timeout will close the tunnel on both sides
	// under ideal conditions
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", m{"tunnels": m{"drop_inactive": true, "inactivity_timeout": "5s"}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", m{"tunnels": m{"drop_inactive": true, "inactivity_timeout": "10m"}})

	// Share our underlay information
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	r := router.NewR(t, myControl, theirControl)

	r.Log("Assert the tunnel between me and them works")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	r.Log("Go inactive and wait for the tunnels to get dropped")
	waitStart := time.Now()
	for {
		myIndexes := len(myControl.GetHostmap().Indexes)
		theirIndexes := len(theirControl.GetHostmap().Indexes)
		if myIndexes == 0 && theirIndexes == 0 {
			break
		}

		since := time.Since(waitStart)
		r.Logf("my tunnels: %v; their tunnels: %v; duration: %v", myIndexes, theirIndexes, since)
		if since > time.Second*30 {
			t.Fatal("Tunnel should have been declared inactive after 5 seconds and before 30 seconds")
		}

		time.Sleep(1 * time.Second)
		r.FlushAll()
	}

	r.Logf("Inactive tunnels were dropped within %v", time.Since(waitStart))
	myControl.Stop()
	theirControl.Stop()
}

func TestCrossStackRelaysWork(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version2, ca, caKey, "me     ", "10.128.0.1/24,fc00::1/64", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "relay  ", "10.128.0.128/24,fc00::128/64", m{"relay": m{"am_relay": true}})
	theirUdp := netip.MustParseAddrPort("10.0.0.2:4242")
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithUdp(cert.Version2, ca, caKey, "them   ", "fc00::2/64", theirUdp, m{"relay": m{"use_relays": true}})

	//myVpnV4 := myVpnIpNet[0]
	myVpnV6 := myVpnIpNet[1]
	relayVpnV4 := relayVpnIpNet[0]
	relayVpnV6 := relayVpnIpNet[1]
	theirVpnV6 := theirVpnIpNet[0]

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnV4.Addr(), relayUdpAddr)
	myControl.InjectLightHouseAddr(relayVpnV6.Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnV6.Addr(), []netip.Addr{relayVpnV6.Addr()})
	relayControl.InjectLightHouseAddr(theirVpnV6.Addr(), theirUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake from me to them via the relay")
	myControl.InjectTunUDPPacket(theirVpnV6.Addr(), 80, myVpnV6.Addr(), 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnV6.Addr(), theirVpnV6.Addr(), 80, 80)

	t.Log("reply?")
	theirControl.InjectTunUDPPacket(myVpnV6.Addr(), 80, theirVpnV6.Addr(), 80, []byte("Hi from them"))
	p = r.RouteForAllUntilTxTun(myControl)
	assertUdpPacket(t, []byte("Hi from them"), p, theirVpnV6.Addr(), myVpnV6.Addr(), 80, 80)

	r.RenderHostmaps("Final hostmaps", myControl, relayControl, theirControl)
	//t.Log("finish up")
	//myControl.Stop()
	//theirControl.Stop()
	//relayControl.Stop()
}
