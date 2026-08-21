//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/udp"
)

// TestRecoveryTiming measures how long a tunnel takes to come back after the peer stops accepting our traffic,
// which is what a laptop waking on a new network looks like from the peer's side: its NAT has no state for where
// we are now, so everything we send disappears.
//
// It is a measurement, not a pass/fail assertion. Recovery is timed to the moment the peer punches back at us,
// since that is when its NAT opens and the tunnel is usable again.
//
//	go test -tags e2e_testing -v -run TestRecoveryTiming ./e2e/
func TestRecoveryTiming(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rebind bool
	}{
		{"no trigger", false},
		{"rebind counter", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, lost := measureRecovery(t, tc.rebind)
			t.Logf("RESULT %-16s recovered in %-9v (%d packets lost)", tc.name, d.Round(time.Millisecond), lost)
		})
	}
}

// measureRecovery returns how long until the peer punched back, and how many of our packets died meanwhile. When
// rebind is true we call RebindUDPServer once the tunnel goes dark, which is what the darwin network change
// monitor does and what iOS has always done. When false, nothing tells nebula anything is wrong.
func measureRecovery(t *testing.T, rebind bool) (time.Duration, int) {
	t.Helper()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	lhControl, lhVpnIpNet, lhUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "lh", "10.128.0.1/24", m{
		"lighthouse": m{"am_lighthouse": true},
	})

	peerCfg := m{
		"lighthouse": m{
			"hosts":    []any{lhVpnIpNet[0].Addr().String()},
			"interval": 600,
			"local_allow_list": m{
				"10.0.0.0/24": true,
				"::/0":        false,
			},
		},
		"static_host_map": m{
			lhVpnIpNet[0].Addr().String(): []any{lhUdpAddr.String()},
		},
	}

	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "me", "10.128.0.2/24", peerCfg)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "them", "10.128.0.3/24", peerCfg)

	r := router.NewR(t, lhControl, myControl, theirControl)
	defer r.RenderFlow()
	defer func() {
		lhControl.Stop()
		myControl.Stop()
		theirControl.Stop()
	}()

	lhControl.Start()
	myControl.Start()
	theirControl.Start()
	r.RouteFor(time.Millisecond * 500)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("establish")))
	r.RouteFor(time.Second)
	if myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false) == nil {
		t.Fatal("failed to establish the tunnel we are measuring")
	}
	r.RouteFor(time.Millisecond * 500)

	// From here the peer's NAT has no state for us, everything we send it disappears
	start := time.Now()
	blackholed := 0
	var recovered time.Duration

	if rebind {
		myControl.RebindUDPServer()
	}

	// Keep the tun busy the way someone retrying a stalled connection would
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(time.Millisecond * 200)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				myControl.InjectTunPacket(BuildTunUDPPacket(
					theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("retry")))
			}
		}
	}()

	r.RouteForAllExitFuncOrTimeout(time.Second*30, func(p *udp.Packet, c *nebula.Control) router.ExitType {
		if c == theirControl && p.From == myControl.GetUDPAddr() {
			blackholed++
			return router.Drop
		}

		// The peer reaching us directly is the moment its NAT opened, whether that is a punch or a handshake
		if c == myControl && p.From == theirUdpAddr {
			recovered = time.Since(start)
			return router.RouteAndExit
		}

		return router.KeepRouting
	})

	if recovered == 0 {
		t.Fatalf("no recovery within 30s (%d packets blackholed)", blackholed)
	}
	return recovered, blackholed
}
