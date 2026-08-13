//go:build e2e_testing
// +build e2e_testing

// Reproducer for: CloseTunnel tunnel teardown bypasses firewall policy, and
// tunnel establishment itself ignores firewall rules.
//
// A (server, 10.128.0.1/24) configures its firewall to DROP ALL INBOUND traffic
// (empty inbound rules), only allowing outbound. B (10.128.0.2/24) sends data
// first to force a handshake.
//
// Evidence:
//  1. The handshake completes successfully even though the inbound firewall
//     would drop every data packet from B (outside.go:150 HandleRequest /
//     handshake_manager.go HandleIncoming never consult the firewall;
//     firewall.Drop() is only called from handleOutsideMessagePacket at
//     outside.go:502).
//  2. After completion, B sends a CloseTunnel message over the shared
//     session. A processes it in closeTunnel() (outside.go:164-166 / 251-257)
//     WITHOUT any firewall evaluation, tearing down the tunnel.
//  3. The tunnel is gone: A deleted the HostInfo and re-initiates a handshake
//     when B probes again.
package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloseTunnelBypassesFirewall(t *testing.T) {
	t.Parallel()
	done := deadline(t, 30)
	defer done()

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	// A: inbound rules = empty (deny all inbound data). Outbound allowed.
	a, aVpn, aUdp, _ := newSimpleServer(cert.Version1, ca, caKey, "server", "10.128.0.1/24", m{
		"firewall": m{
			"outbound": []m{{"proto": "any", "port": "any", "host": "any"}},
			"inbound":  []m{}, // deny everything inbound
		},
	})

	// B: normal permissive rules (irrelevant for the finding).
	b, bVpn, bUdp, _ := newSimpleServer(cert.Version1, ca, caKey, "client", "10.128.0.2/24", nil)

	// Lighthouse-free topology: each node points at the other statically.
	a.InjectLightHouseAddr(bVpn[0].Addr(), bUdp)
	b.InjectLightHouseAddr(aVpn[0].Addr(), aUdp)

	a.Start()
	b.Start()
	defer a.Stop()
	defer b.Stop()

	t.Log("B injects a data packet toward A; B becomes the initiator and emits stage-0")
	b.InjectTunPacket(BuildTunUDPPacket(aVpn[0].Addr(), 80, bVpn[0].Addr(), 90, []byte("hello")))

	stage0 := b.GetFromUDP(true)
	t.Log("Inject B's stage-0 into A (the server whose inbound firewall denies all data)")
	a.InjectUDPPacket(stage0)

	// A, as IX responder, completes the handshake on the stage-0 alone and
	// emits a completion message. This demonstrates the tunnel forming on A
	// without any inbound firewall evaluation.
	t.Log("A replies with the handshake completion")
	stage1 := a.GetFromUDP(true)
	b.InjectUDPPacket(stage1)

	// The tunnel is live once A's cached (or fresh) data reaches B.
	t.Log("Waiting for the tunnel to complete and the cached packet to cross")
	b.WaitForType(header.Message, 0, a)

	// Confirm the tunnel is live bidirectionally (our own payload).
	r := router.NewR(t, a, b)
	defer r.RenderFlow()
	a.InjectTunPacket(BuildTunUDPPacket(bVpn[0].Addr(), 80, aVpn[0].Addr(), 90, []byte("hi from A")))
	aPacket := r.RouteForAllUntilTxTun(b)
	udpA := gopacket.NewPacket(aPacket, layers.LayerTypeIPv4, gopacket.Lazy)
	require.Equal(t, []byte("hi from A"), udpA.ApplicationLayer().Payload(), "tunnel B->A check")
	b.InjectTunPacket(BuildTunUDPPacket(aVpn[0].Addr(), 80, bVpn[0].Addr(), 90, []byte("hi from B")))
	// The first packet B emits is the original cached "hello" crossing at
	// handshake completion; drain it, then the probe.
	bCached := r.RouteForAllUntilTxTun(a)
	udpCached := gopacket.NewPacket(bCached, layers.LayerTypeIPv4, gopacket.Lazy)
	if !assert.Equal(t, []byte("hello"), udpCached.ApplicationLayer().Payload(), "expected cached hello to cross first") {
		return
	}
	bPacket := r.RouteForAllUntilTxTun(a)
	udpB := gopacket.NewPacket(bPacket, layers.LayerTypeIPv4, gopacket.Lazy)
	require.Equal(t, []byte("hi from B"), udpB.ApplicationLayer().Payload(), "tunnel A->B check")

	// ---------------- Finding 1: tunnel establishment bypassed the firewall --
	t.Log("Tunnel is live even though A's inbound firewall has zero allow rules")
	assertHostInfoPair(t, aUdp, bUdp, aVpn, bVpn, a, b)

	// ---------------- Finding 2: send CloseTunnel from B ---------------------
	t.Log("B tears down the tunnel with its local CloseTunnel admin action")
	ok := b.CloseTunnel(aVpn[0].Addr(), false)
	require.True(t, ok, "expected CloseTunnel to succeed")

	t.Log("Observe the CloseTunnel message on the wire")
	closeMsg := b.GetFromUDP(true)
	require.NotNil(t, closeMsg, "expected CloseTunnel on the wire")
	var h header.H
	require.NoError(t, h.Parse(closeMsg.Data))
	assert.Equal(t, header.CloseTunnel, h.Type, "expected a CloseTunnel message")

	// The close message originates from B's UDP port 4242; A's firewall has NO
	// inbound rule, so any legitimate DATA packet from B is dropped by the
	// firewall match stage before processing. Yet the CloseTunnel path
	// (outside.go:164) never invokes Drop().
	a.InjectUDPPacket(closeMsg)
	time.Sleep(100 * time.Millisecond)

	// ---------------- Finding 3: verify the tunnel is gone --------------------
	t.Log("A's main hostmap no longer holds the completed tunnel with B")
	hi := a.GetHostInfoByVpnAddr(bVpn[0].Addr(), false)
	assert.Nil(t, hi, "tunnel to B should be torn down after CloseTunnel processing")

	t.Log("B probes A again; B re-initiates a handshake because its tunnel was torn down")
	// Re-enter the lighthouse mapping the close cleared on A, then probe via the router.
	b.InjectLightHouseAddr(aVpn[0].Addr(), aUdp)
	a.InjectLightHouseAddr(bVpn[0].Addr(), bUdp)
	b.InjectTunPacket(BuildTunUDPPacket(aVpn[0].Addr(), 80, bVpn[0].Addr(), 90, []byte("after close")))

	// Route until the probe reaches A's tun: A's fresh handshake must complete
	// and deliver the cached "after close" packet. This proves both sides tore
	// down and rebuilt the tunnel after the close.
	afterPacket := r.RouteForAllUntilTxTun(a)
	afterUdp := gopacket.NewPacket(afterPacket, layers.LayerTypeIPv4, gopacket.Lazy)
	require.Equal(t, []byte("after close"), afterUdp.ApplicationLayer().Payload(), "tunnel re-formed after CloseTunnel")
}

// TestCloseTunnelRawCrafted proves a CloseTunnel is accepted regardless of the
// UDP source address that delivered it: processing only requires a valid
// decryption match (RemoteIndex lookup), with no source validation anywhere
// on the CloseTunnel path (outside.go:164-166, 244-257).
func TestCloseTunnelRawCrafted(t *testing.T) {
	t.Parallel()
	done := deadline(t, 30)
	defer done()

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	a, aVpn, aUdp, _ := newSimpleServer(cert.Version1, ca, caKey, "server", "10.128.0.1/24", nil)
	b, bVpn, bUdp, _ := newSimpleServer(cert.Version1, ca, caKey, "client", "10.128.0.2/24", nil)

	a.InjectLightHouseAddr(bVpn[0].Addr(), bUdp)
	b.InjectLightHouseAddr(aVpn[0].Addr(), aUdp)

	a.Start()
	b.Start()
	defer a.Stop()
	defer b.Stop()

	// Stand up the tunnel using the proven TestGoodHandshake pattern.
	r := router.NewR(t, a, b)
	defer r.RenderFlow()
	b.InjectTunPacket(BuildTunUDPPacket(aVpn[0].Addr(), 80, bVpn[0].Addr(), 90, []byte("hello")))
	bCached := r.RouteForAllUntilTxTun(a)
	require.Equal(t, []byte("hello"), gopacket.NewPacket(bCached, layers.LayerTypeIPv4, gopacket.Lazy).ApplicationLayer().Payload())
	assertHostInfoPair(t, aUdp, bUdp, aVpn, bVpn, a, b)

	// Forge a CloseTunnel over the session and deliver it to A from a totally
	// unrelated, spoofed underlay address.
	b.CloseTunnel(aVpn[0].Addr(), false)
	closeMsg := b.GetFromUDP(true)
	require.NotNil(t, closeMsg)

	var h header.H
	require.NoError(t, h.Parse(closeMsg.Data))
	assert.Equal(t, header.CloseTunnel, h.Type)

	// Spoof the underlay source to an unrelated address: A must still tear
	// down the tunnel because CloseTunnel processing never validates the
	// source UDP address — only the decrypted header's RemoteIndex.
	spoofed := closeMsg.Copy()
	spoofed.From = netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), 12345)
	a.InjectUDPPacket(spoofed)
	time.Sleep(150 * time.Millisecond)

	// The tunnel should be gone even though the only packet ever received on
	// the teardown path came from an address B never used.
	hi := a.GetHostInfoByVpnAddr(bVpn[0].Addr(), false)
	assert.Nil(t, hi, "tunnel to B should be torn down after a spoofed-source CloseTunnel")

	// Tunnel re-formation also confirms teardown: B re-initiates and the
	// fresh handshake completes.
	b.InjectLightHouseAddr(aVpn[0].Addr(), aUdp)
	a.InjectLightHouseAddr(bVpn[0].Addr(), bUdp)
	b.InjectTunPacket(BuildTunUDPPacket(aVpn[0].Addr(), 80, bVpn[0].Addr(), 90, []byte("reprobe")))
	afterPacket := r.RouteForAllUntilTxTun(a)
	require.Equal(t, []byte("reprobe"), gopacket.NewPacket(afterPacket, layers.LayerTypeIPv4, gopacket.Lazy).ApplicationLayer().Payload(), "tunnel re-formed after spoofed-source CloseTunnel")
}

// TestNoOverlapTunnelEstablishmentRaw proves validatePeerCert never requires
// the peer's certificate networks to overlap ours (handshake_manager.go:1025
// only *logs* the absence of common networks); a tunnel still fully forms.
func TestNoOverlapTunnelEstablishmentRaw(t *testing.T) {
	t.Parallel()
	done := deadline(t, 30)
	defer done()

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	a, aVpn, _, _ := newSimpleServer(cert.Version2, ca, caKey, "me", "10.128.0.1/24", nil)
	b, bVpn, _, _ := newSimpleServer(cert.Version2, ca, caKey, "them", "2001::69/24", nil) // disjoint networks

	a.InjectLightHouseAddr(bVpn[0].Addr(), b.GetUDPAddr())
	b.InjectLightHouseAddr(aVpn[0].Addr(), a.GetUDPAddr())

	a.Start()
	b.Start()
	defer a.Stop()
	defer b.Stop()

	a.GetF().SendMessageToVpnAddr(header.Test, header.MessageNone, bVpn[0].Addr(), []byte{}, []byte{}, []byte{})
	b.InjectUDPPacket(a.GetFromUDP(true))
	a.InjectUDPPacket(b.GetFromUDP(true))
	a.WaitForType(header.Test, 0, b)

	// The tunnel is fully established with disjoint networks.
	assert.NotNil(t, a.GetHostInfoByVpnAddr(bVpn[0].Addr(), false), "tunnel established with disjoint cert networks")
	assert.NotNil(t, b.GetHostInfoByVpnAddr(aVpn[0].Addr(), false), "tunnel established with disjoint cert networks")
}
