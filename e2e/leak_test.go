//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"go.uber.org/goleak"
)

// TestNoGoroutineLeaks brings up two nebula instances, completes a tunnel,
// stops both, and asserts no goroutines leak past the shutdown. goleak's
// retry mechanism gives the wg.Wait()-driven goroutines a moment to drain
// before failing the assertion.
//
// IgnoreCurrent is necessary in the parallelized suite: other tests can
// leave goroutines mid-shutdown when this one runs (Stop is async, the
// wg.Wait() drain is not blocking on test return). We're checking that
// *this* test's setup tears down cleanly, not that the whole suite is
// idle at this moment. Intentionally NOT t.Parallel()'d for the same
// reason — concurrent test goroutines would always show up.
func TestNoGoroutineLeaks(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	myControl.Start()
	theirControl.Start()

	r := router.NewR(t, myControl, theirControl)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
	r.RenderFlow()

	// Settle period: Stop() is non-blocking; the wg-driven goroutines need
	// a moment to drain. goleak retries internally too, but a short explicit
	// settle reduces flakes when the suite is busy.
	time.Sleep(50 * time.Millisecond)
}
