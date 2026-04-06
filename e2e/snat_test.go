//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseIPv4UDPPacket extracts source/dest IPs, ports, and payload from an IPv4 UDP packet.
func parseIPv4UDPPacket(t testing.TB, pkt []byte) (srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) {
	t.Helper()
	require.True(t, len(pkt) >= 28, "packet too short for IPv4+UDP header")
	require.Equal(t, byte(0x45), pkt[0]&0xF0|pkt[0]&0x0F, "not a simple IPv4 packet (IHL!=5)")

	srcIP, _ = netip.AddrFromSlice(pkt[12:16])
	dstIP, _ = netip.AddrFromSlice(pkt[16:20])

	ihl := int(pkt[0]&0x0F) * 4
	require.True(t, len(pkt) >= ihl+8, "packet too short for UDP header")
	srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	udpLen := binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6])
	payload = pkt[ihl+8 : ihl+int(udpLen)]
	return
}

func TestSNAT_IPv6OnlyPeer_IPv4UnsafeTraffic(t *testing.T) {
	// Scenario: Two IPv6-only VPN nodes. The "router" node has unsafe networks
	// (192.168.0.0/16) in its cert and a configured SNAT address. The "sender"
	// node has an unsafe route for 192.168.0.0/16 via the router.
	//
	// When sender injects an IPv4 packet destined for the unsafe network, it
	// gets tunneled to the router. The router's firewall detects this is IPv4
	// from an IPv6-only peer and applies SNAT, rewriting the source IP to the
	// SNAT address before delivering it to TUN.
	//
	// When a reply comes back from TUN addressed to the SNAT address, the
	// router un-SNATs it (restoring the original destination) and tunnels it
	// back to the sender.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	unsafePrefix := "192.168.0.0/16"
	snatAddr := netip.MustParseAddr("169.254.42.42")

	// Router: IPv6-only with unsafe networks and a manual SNAT address.
	// Override inbound firewall with local_cidr: "any" so both IPv4 (unsafe)
	// and IPv6 (VPN) traffic is accepted.
	routerControl, routerVpnIpNet, routerUdpAddr, _ := newSimpleServerWithUdpAndUnsafeNetworks(
		cert.Version2, ca, caKey, "router", "ff::1/64",
		netip.MustParseAddrPort("[beef::1]:4242"),
		unsafePrefix,
		m{
			"firewall": m{
				"inbound": []m{{
					"proto":      "any",
					"port":       "any",
					"host":       "any",
					"local_cidr": "any",
				}},
			},
			"tun": m{
				"snat_address_for_4over6": snatAddr.String(),
			},
		},
	)

	// Sender: IPv6-only with an unsafe route via the router
	senderControl, _, _, _ := newSimpleServerWithUdp(
		cert.Version2, ca, caKey, "sender", "ff::2/64",
		netip.MustParseAddrPort("[beef::2]:4242"),
		m{
			"tun": m{
				"unsafe_routes": []m{
					{"route": unsafePrefix, "via": routerVpnIpNet[0].Addr().String()},
				},
			},
		},
	)

	// Tell sender where the router lives
	senderControl.InjectLightHouseAddr(routerVpnIpNet[0].Addr(), routerUdpAddr)

	// Build the router and start both nodes
	r := router.NewR(t, routerControl, senderControl)
	defer r.RenderFlow()

	routerControl.Start()
	senderControl.Start()

	// --- Outbound: sender -> IPv4 unsafe dest (via router with SNAT) ---

	origSrcIP := netip.MustParseAddr("10.0.0.1")
	unsafeDest := netip.MustParseAddr("192.168.1.1")
	var origSrcPort uint16 = 12345
	var dstPort uint16 = 80

	t.Log("Sender injects an IPv4 packet to the unsafe network")
	senderControl.InjectTunUDPPacket(unsafeDest, dstPort, origSrcIP, origSrcPort, []byte("snat me"))

	t.Log("Route packets (handshake + data) until the router gets the packet on TUN")
	snatPkt := r.RouteForAllUntilTxTun(routerControl)

	t.Log("Verify the packet was SNATted")
	gotSrcIP, gotDstIP, gotSrcPort, gotDstPort, gotPayload := parseIPv4UDPPacket(t, snatPkt)
	assert.Equal(t, snatAddr, gotSrcIP, "source IP should be rewritten to the SNAT address")
	assert.Equal(t, unsafeDest, gotDstIP, "destination IP should be unchanged")
	assert.Equal(t, dstPort, gotDstPort, "destination port should be unchanged")
	assert.Equal(t, []byte("snat me"), gotPayload, "payload should be unchanged")

	// Capture the SNAT port (may differ from original if port was remapped)
	snatPort := gotSrcPort
	t.Logf("SNAT port: %d (original: %d)", snatPort, origSrcPort)

	// --- Return: reply from unsafe dest -> un-SNATted back to sender ---

	t.Log("Router injects a reply packet from the unsafe dest to the SNAT address")
	routerControl.InjectTunUDPPacket(snatAddr, snatPort, unsafeDest, dstPort, []byte("reply from unsafe"))

	t.Log("Route until sender gets the reply on TUN")
	replyPkt := r.RouteForAllUntilTxTun(senderControl)

	t.Log("Verify the reply was un-SNATted")
	replySrcIP, replyDstIP, replySrcPort, replyDstPort, replyPayload := parseIPv4UDPPacket(t, replyPkt)
	assert.Equal(t, unsafeDest, replySrcIP, "reply source should be the unsafe dest")
	assert.Equal(t, origSrcIP, replyDstIP, "reply dest should be the original source IP (un-SNATted)")
	assert.Equal(t, dstPort, replySrcPort, "reply source port should be the unsafe dest port")
	assert.Equal(t, origSrcPort, replyDstPort, "reply dest port should be the original source port (un-SNATted)")
	assert.Equal(t, []byte("reply from unsafe"), replyPayload, "payload should be unchanged")

	r.RenderHostmaps("Final hostmaps", routerControl, senderControl)

	// Also verify normal IPv6 VPN traffic still works between the nodes
	t.Log("Verify normal IPv6 VPN tunnel still works")
	assertTunnel(t, routerVpnIpNet[0].Addr(), senderControl.GetVpnAddrs()[0], routerControl, senderControl, r)

	routerControl.Stop()
	senderControl.Stop()
}

func TestSNAT_MultipleFlows(t *testing.T) {
	// Test that multiple distinct IPv4 flows from the same IPv6-only peer
	// are tracked independently through SNAT.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	unsafePrefix := "192.168.0.0/16"
	snatAddr := netip.MustParseAddr("169.254.42.42")

	routerControl, routerVpnIpNet, routerUdpAddr, _ := newSimpleServerWithUdpAndUnsafeNetworks(
		cert.Version2, ca, caKey, "router", "ff::1/64",
		netip.MustParseAddrPort("[beef::1]:4242"),
		unsafePrefix,
		m{
			"firewall": m{
				"inbound": []m{{
					"proto":      "any",
					"port":       "any",
					"host":       "any",
					"local_cidr": "any",
				}},
			},
			"tun": m{
				"snat_address_for_4over6": snatAddr.String(),
			},
		},
	)

	senderControl, _, _, _ := newSimpleServerWithUdp(
		cert.Version2, ca, caKey, "sender", "ff::2/64",
		netip.MustParseAddrPort("[beef::2]:4242"),
		m{
			"tun": m{
				"unsafe_routes": []m{
					{"route": unsafePrefix, "via": routerVpnIpNet[0].Addr().String()},
				},
			},
		},
	)

	senderControl.InjectLightHouseAddr(routerVpnIpNet[0].Addr(), routerUdpAddr)

	r := router.NewR(t, routerControl, senderControl)
	defer r.RenderFlow()
	r.CancelFlowLogs()

	routerControl.Start()
	senderControl.Start()

	unsafeDest := netip.MustParseAddr("192.168.1.1")

	// Send first flow
	senderControl.InjectTunUDPPacket(unsafeDest, 80, netip.MustParseAddr("10.0.0.1"), 1111, []byte("flow1"))
	pkt1 := r.RouteForAllUntilTxTun(routerControl)
	srcIP1, _, srcPort1, _, payload1 := parseIPv4UDPPacket(t, pkt1)
	assert.Equal(t, snatAddr, srcIP1)
	assert.Equal(t, []byte("flow1"), payload1)

	// Send second flow (different source port)
	senderControl.InjectTunUDPPacket(unsafeDest, 80, netip.MustParseAddr("10.0.0.1"), 2222, []byte("flow2"))
	pkt2 := r.RouteForAllUntilTxTun(routerControl)
	srcIP2, _, srcPort2, _, payload2 := parseIPv4UDPPacket(t, pkt2)
	assert.Equal(t, snatAddr, srcIP2)
	assert.Equal(t, []byte("flow2"), payload2)

	// The two flows should have different SNAT ports (since they're different conntracks)
	t.Logf("Flow 1 SNAT port: %d, Flow 2 SNAT port: %d", srcPort1, srcPort2)

	// Reply to flow 2 first (out of order)
	routerControl.InjectTunUDPPacket(snatAddr, srcPort2, unsafeDest, 80, []byte("reply2"))
	reply2 := r.RouteForAllUntilTxTun(senderControl)
	_, replyDst2, _, replyDstPort2, replyPayload2 := parseIPv4UDPPacket(t, reply2)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), replyDst2)
	assert.Equal(t, uint16(2222), replyDstPort2, "reply to flow 2 should restore original port 2222")
	assert.Equal(t, []byte("reply2"), replyPayload2)

	// Reply to flow 1
	routerControl.InjectTunUDPPacket(snatAddr, srcPort1, unsafeDest, 80, []byte("reply1"))
	reply1 := r.RouteForAllUntilTxTun(senderControl)
	_, replyDst1, _, replyDstPort1, replyPayload1 := parseIPv4UDPPacket(t, reply1)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), replyDst1)
	assert.Equal(t, uint16(1111), replyDstPort1, "reply to flow 1 should restore original port 1111")
	assert.Equal(t, []byte("reply1"), replyPayload1)

	routerControl.Stop()
	senderControl.Stop()
}

// --- Adversarial SNAT E2E Tests ---

func TestSNAT_UnsolicitedReplyDropped(t *testing.T) {
	// Without any outbound SNAT traffic, inject a packet from the router's TUN
	// addressed to the SNAT address. The sender must never receive it because
	// there's no conntrack entry to un-SNAT through.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	unsafePrefix := "192.168.0.0/16"
	snatAddr := netip.MustParseAddr("169.254.42.42")

	routerControl, routerVpnIpNet, routerUdpAddr, _ := newSimpleServerWithUdpAndUnsafeNetworks(
		cert.Version2, ca, caKey, "router", "ff::1/64",
		netip.MustParseAddrPort("[beef::1]:4242"),
		unsafePrefix,
		m{
			"firewall": m{
				"inbound": []m{{
					"proto":      "any",
					"port":       "any",
					"host":       "any",
					"local_cidr": "any",
				}},
			},
			"tun": m{
				"snat_address_for_4over6": snatAddr.String(),
			},
		},
	)

	senderControl, _, _, _ := newSimpleServerWithUdp(
		cert.Version2, ca, caKey, "sender", "ff::2/64",
		netip.MustParseAddrPort("[beef::2]:4242"),
		m{
			"tun": m{
				"unsafe_routes": []m{
					{"route": unsafePrefix, "via": routerVpnIpNet[0].Addr().String()},
				},
			},
		},
	)

	senderControl.InjectLightHouseAddr(routerVpnIpNet[0].Addr(), routerUdpAddr)

	r := router.NewR(t, routerControl, senderControl)
	defer r.RenderFlow()
	r.CancelFlowLogs()

	routerControl.Start()
	senderControl.Start()

	// First establish the tunnel with normal IPv6 traffic so handshake completes
	assertTunnel(t, routerVpnIpNet[0].Addr(), senderControl.GetVpnAddrs()[0], routerControl, senderControl, r)

	// Inject the unsolicited reply from router's TUN to the SNAT address.
	// There is NO prior outbound SNAT flow, so no conntrack entry exists.
	// The router should silently drop this because unSnat finds no matching conntrack.
	routerControl.InjectTunUDPPacket(snatAddr, 55555, netip.MustParseAddr("192.168.1.1"), 80, []byte("unsolicited"))

	// Send a canary IPv6 VPN packet after the bad one. Since the router processes
	// TUN packets sequentially, the canary arriving proves the bad packet was processed first.
	senderVpnAddr := senderControl.GetVpnAddrs()[0]
	routerControl.InjectTunUDPPacket(senderVpnAddr, 90, routerVpnIpNet[0].Addr(), 80, []byte("canary"))
	canaryPkt := r.RouteForAllUntilTxTun(senderControl)
	assertUdpPacket(t, []byte("canary"), canaryPkt, routerVpnIpNet[0].Addr(), senderVpnAddr, 80, 90)

	// The unsolicited packet should have been dropped — nothing else on sender's TUN
	got := senderControl.GetFromTun(false)
	assert.Nil(t, got, "sender should not receive unsolicited packet to SNAT address with no conntrack entry")

	routerControl.Stop()
	senderControl.Stop()
}

func TestSNAT_NonUnsafeDestDropped(t *testing.T) {
	// An IPv6-only sender sends IPv4 traffic to a destination outside the router's
	// unsafe networks (172.16.0.1 when unsafe is 192.168.0.0/16). The router should
	// reject this because the local address is not routable. This verifies that
	// willingToHandleLocalAddr enforces boundaries on what SNAT traffic can reach.

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	unsafePrefix := "192.168.0.0/16"
	snatAddr := netip.MustParseAddr("169.254.42.42")

	routerControl, routerVpnIpNet, routerUdpAddr, _ := newSimpleServerWithUdpAndUnsafeNetworks(
		cert.Version2, ca, caKey, "router", "ff::1/64",
		netip.MustParseAddrPort("[beef::1]:4242"),
		unsafePrefix,
		m{
			"firewall": m{
				"inbound": []m{{
					"proto":      "any",
					"port":       "any",
					"host":       "any",
					"local_cidr": "any",
				}},
			},
			"tun": m{
				"snat_address_for_4over6": snatAddr.String(),
			},
		},
	)

	// Sender has unsafe routes for BOTH 192.168.0.0/16 AND 172.16.0.0/12 via router.
	// This means the sender will route 172.16.0.1 through the tunnel to the router.
	// But the router should reject it because 172.16.0.0/12 is NOT in its unsafe networks.
	senderControl, _, _, _ := newSimpleServerWithUdp(
		cert.Version2, ca, caKey, "sender", "ff::2/64",
		netip.MustParseAddrPort("[beef::2]:4242"),
		m{
			"tun": m{
				"unsafe_routes": []m{
					{"route": unsafePrefix, "via": routerVpnIpNet[0].Addr().String()},
					{"route": "172.16.0.0/12", "via": routerVpnIpNet[0].Addr().String()},
				},
			},
		},
	)

	senderControl.InjectLightHouseAddr(routerVpnIpNet[0].Addr(), routerUdpAddr)

	r := router.NewR(t, routerControl, senderControl)
	defer r.RenderFlow()
	r.CancelFlowLogs()

	routerControl.Start()
	senderControl.Start()

	// Establish the tunnel first
	assertTunnel(t, routerVpnIpNet[0].Addr(), senderControl.GetVpnAddrs()[0], routerControl, senderControl, r)

	// Send to 172.16.0.1 (NOT in router's unsafe networks 192.168.0.0/16).
	// The router should reject this at willingToHandleLocalAddr.
	senderControl.InjectTunUDPPacket(
		netip.MustParseAddr("172.16.0.1"), 80,
		netip.MustParseAddr("10.0.0.1"), 12345,
		[]byte("wrong dest"),
	)

	// Send a canary to a valid unsafe destination to prove the bad packet was processed
	senderControl.InjectTunUDPPacket(
		netip.MustParseAddr("192.168.1.1"), 80,
		netip.MustParseAddr("10.0.0.1"), 33333,
		[]byte("canary"),
	)

	// Route until the canary arrives — the 172.16.0.1 packet should have been
	// processed and dropped before the canary gets through
	canaryPkt := r.RouteForAllUntilTxTun(routerControl)
	_, canaryDst, _, _, canaryPayload := parseIPv4UDPPacket(t, canaryPkt)
	assert.Equal(t, netip.MustParseAddr("192.168.1.1"), canaryDst, "canary should arrive at the valid unsafe dest")
	assert.Equal(t, []byte("canary"), canaryPayload)

	// No more packets — the 172.16.0.1 packet was dropped
	got := routerControl.GetFromTun(false)
	assert.Nil(t, got, "packet to non-unsafe destination 172.16.0.1 should be dropped by the router")

	routerControl.Stop()
	senderControl.Stop()
}
