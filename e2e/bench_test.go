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

// BenchmarkHandshake measures end-to-end tunnel establishment time. The two
// nodes and the router are constructed once before the loop so the timed window
// is just the handshake itself: trigger packet -> handshake1 -> handshake2 ->
// cached packet replay -> arrival on the remote TUN. Between iterations we
// tear down both sides locally (no CloseTunnel notification on the wire) and
// re-inject the lighthouse address that closeTunnel cleared, so the next
// iteration runs through a fresh handshake against the same harness.
func BenchmarkHandshake(b *testing.B) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	// Default try_interval is 100ms. The handshake manager schedules handshake1
	// on its OutboundHandshakeTimer rather than firing immediately on trigger
	// (the trigger channel only fast-paths static hosts), so a 100ms default
	// drowns the actual handshake cost. Drop it to 1ms so the bench reflects
	// the computation, not the wheel cadence.
	bovr := m{"handshakes": m{"try_interval": "1ms"}}
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "me", "10.128.0.1/24", bovr)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "them", "10.128.0.2/24", bovr)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	myControl.Start()
	theirControl.Start()
	defer myControl.Stop()
	defer theirControl.Stop()

	r := router.NewR(b, myControl, theirControl)
	r.CancelFlowLogs()
	r.EnableFanIn()

	trigger := BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me"))

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		myControl.InjectTunPacket(trigger)
		// RouteForAllUntilTxTun returns the moment the cached packet arrives at
		// the remote TUN, which is also when both sides are fully established.
		_ = r.RouteForAllUntilTxTun(theirControl)

		b.StopTimer()
		// Local-only close removes hostmap state on both sides without putting a
		// CloseTunnel packet on the wire that we'd then have to drain. The
		// closeTunnel path also clears learned lighthouse state for the peer
		// when the last hostinfo for that addr goes away, so we re-inject.
		myControl.CloseTunnel(theirVpnIpNet[0].Addr(), true)
		theirControl.CloseTunnel(myVpnIpNet[0].Addr(), true)
		myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
		theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)
		b.StartTimer()
	}
}
