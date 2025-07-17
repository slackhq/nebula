//go:build e2e_testing
// +build e2e_testing

package e2e

import (
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
