//go:build e2e_testing

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOrphanedRelayRecoversImmediately covers a relayed tunnel whose tunnel to the relay was replaced while the
// relayed tunnel sat idle, which is what a laptop sees after it sleeps or changes networks: the lighthouse/relay
// tunnel goes dead and gets handshaked again. An idle relay is not migrated to the replacement relay hostinfo, so the
// relayed tunnel has nothing to send through. The next packet has to rebuild the tunnel and arrive within a handshake,
// not after connection_alive_interval + pending_deletion_interval of dead tunnel detection.
func TestOrphanedRelayRecoversImmediately(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	myVpnIp := myVpnIpNet[0].Addr()
	relayVpnIp := relayVpnIpNet[0].Addr()
	theirVpnIp := theirVpnIpNet[0].Addr()

	// Teach me how to get to the relay and that they can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIp, relayUdpAddr)
	myControl.InjectRelays(theirVpnIp, []netip.Addr{relayVpnIp})
	relayControl.InjectLightHouseAddr(theirVpnIp, theirUdpAddr)

	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	r.Log("Build the relayed tunnel from me to them")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIp, 80, myVpnIp, 80, []byte("Hi from me")))
	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIp, theirVpnIp, 80, 80)
	orphan := myControl.GetHostInfoByVpnAddr(theirVpnIp, false)
	require.NotNil(t, orphan)

	r.Log("Replace my tunnel to the relay while the relayed tunnel is idle")
	require.True(t, myControl.CloseTunnel(relayVpnIp, true))
	// Closing forgets the relay's underlay address, which a real lighthouse/relay keeps in static_host_map
	myControl.InjectLightHouseAddr(relayVpnIp, relayUdpAddr)
	// I initiate, like a laptop coming back: the relay still holds the old tunnel and would send into the void.
	myControl.InjectTunPacket(BuildTunUDPPacket(relayVpnIp, 80, myVpnIp, 80, []byte("Hi relay")))
	p = r.RouteForAllUntilTxTun(relayControl)
	assertUdpPacket(t, []byte("Hi relay"), p, myVpnIp, relayVpnIp, 80, 80)
	assertTunnel(t, myVpnIp, relayVpnIp, myControl, relayControl, r)
	stale := myControl.GetHostInfoByVpnAddr(theirVpnIp, false)
	require.NotNil(t, stale, "the relayed tunnel should still be in my hostmap")
	require.Equal(t, orphan.LocalIndex, stale.LocalIndex, "the relayed tunnel should not have been touched yet")
	r.RenderHostmaps("relayed tunnel lost its relay", myControl, relayControl, theirControl)

	r.Log("Send to them again, it must arrive without waiting for dead tunnel detection")
	start := time.Now()
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIp, 80, myVpnIp, 80, []byte("Hi again")))

	delivered := make(chan []byte, 1)
	go func() { delivered <- r.RouteForAllUntilTxTun(theirControl) }()

	select {
	case p = <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("packet over the orphaned relayed tunnel was not delivered")
	}
	elapsed := time.Since(start)
	assertUdpPacket(t, []byte("Hi again"), p, myVpnIp, theirVpnIp, 80, 80)
	assert.Less(t, elapsed, time.Second, "recovery should take one handshake")
	t.Logf("recovered in %v", elapsed)

	replacement := myControl.GetHostInfoByVpnAddr(theirVpnIp, false)
	require.NotNil(t, replacement)
	assert.NotEqual(t, orphan.LocalIndex, replacement.LocalIndex, "the orphaned tunnel should have been replaced")

	r.Log("Assert the replacement tunnel works both ways")
	assertTunnel(t, myVpnIp, theirVpnIp, myControl, theirControl, r)
	r.RenderHostmaps("final hostmaps", myControl, relayControl, theirControl)

	myControl.Stop()
	relayControl.Stop()
	theirControl.Stop()
}
