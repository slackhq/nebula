//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDropInactiveTunnels(t *testing.T) {
	t.Parallel()
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
		myIndexes := myControl.GetHostmapIndexCount()
		theirIndexes := theirControl.GetHostmapIndexCount()
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

func TestCertUpgrade(t *testing.T) {
	t.Parallel()
	// The goal of this test is to ensure the shortest inactivity timeout will close the tunnel on both sides
	// under ideal conditions
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	caB, err := ca.MarshalPEM()
	if err != nil {
		panic(err)
	}
	ca2, _, caKey2, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	ca2B, err := ca2.MarshalPEM()
	if err != nil {
		panic(err)
	}
	caStr := fmt.Sprintf("%s\n%s", caB, ca2B)

	myCert, _, myPrivKey, _ := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, "me", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{netip.MustParsePrefix("10.128.0.1/24")}, nil, []string{})
	_, myCert2Pem := cert_test.NewTestCertDifferentVersion(myCert, cert.Version2, ca2, caKey2)

	theirCert, _, theirPrivKey, _ := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, "them", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{netip.MustParsePrefix("10.128.0.2/24")}, nil, []string{})
	theirCert2, _ := cert_test.NewTestCertDifferentVersion(theirCert, cert.Version2, ca2, caKey2)

	myControl, myVpnIpNet, myUdpAddr, myC := newServer([]cert.Certificate{ca, ca2}, []cert.Certificate{myCert}, myPrivKey, m{})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newServer([]cert.Certificate{ca, ca2}, []cert.Certificate{theirCert, theirCert2}, theirPrivKey, m{})

	// Share our underlay information
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	r.Log("Assert the tunnel between me and them works")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
	r.Log("yay")
	//todo ???
	time.Sleep(1 * time.Second)
	r.FlushAll()

	mc := m{
		"pki": m{
			"ca":   caStr,
			"cert": string(myCert2Pem),
			"key":  string(myPrivKey),
		},
		//"tun": m{"disabled": true},
		"firewall": myC.Settings["firewall"],
		//"handshakes": m{
		//	"try_interval": "1s",
		//},
		"listen":  myC.Settings["listen"],
		"logging": myC.Settings["logging"],
		"timers":  myC.Settings["timers"],
	}

	cb, err := yaml.Marshal(mc)
	if err != nil {
		panic(err)
	}

	r.Logf("reload new v2-only config")
	err = myC.ReloadConfigString(string(cb))
	assert.NoError(t, err)
	r.Log("yay, spin until their sees it")
	waitStart := time.Now()
	for {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		c := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
		if c == nil {
			r.Log("nil")
		} else {
			version := c.Cert.Version()
			r.Logf("version %d", version)
			if version == cert.Version2 {
				break
			}
		}
		since := time.Since(waitStart)
		if since > time.Second*10 {
			t.Fatal("Cert should be new by now")
		}
		time.Sleep(time.Second)
	}

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)

	myControl.Stop()
	theirControl.Stop()
}

func TestCertDowngrade(t *testing.T) {
	t.Parallel()
	// The goal of this test is to ensure the shortest inactivity timeout will close the tunnel on both sides
	// under ideal conditions
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	caB, err := ca.MarshalPEM()
	if err != nil {
		panic(err)
	}
	ca2, _, caKey2, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	ca2B, err := ca2.MarshalPEM()
	if err != nil {
		panic(err)
	}
	caStr := fmt.Sprintf("%s\n%s", caB, ca2B)

	myCert, _, myPrivKey, myCertPem := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, "me", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{netip.MustParsePrefix("10.128.0.1/24")}, nil, []string{})
	myCert2, _ := cert_test.NewTestCertDifferentVersion(myCert, cert.Version2, ca2, caKey2)

	theirCert, _, theirPrivKey, _ := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, "them", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{netip.MustParsePrefix("10.128.0.2/24")}, nil, []string{})
	theirCert2, _ := cert_test.NewTestCertDifferentVersion(theirCert, cert.Version2, ca2, caKey2)

	myControl, myVpnIpNet, myUdpAddr, myC := newServer([]cert.Certificate{ca, ca2}, []cert.Certificate{myCert2}, myPrivKey, m{})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newServer([]cert.Certificate{ca, ca2}, []cert.Certificate{theirCert, theirCert2}, theirPrivKey, m{})

	// Share our underlay information
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	r.Log("Assert the tunnel between me and them works")
	//assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)
	//r.Log("yay")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
	r.Log("yay")
	//todo ???
	time.Sleep(1 * time.Second)
	r.FlushAll()

	mc := m{
		"pki": m{
			"ca":   caStr,
			"cert": string(myCertPem),
			"key":  string(myPrivKey),
		},
		"firewall": myC.Settings["firewall"],
		"listen":   myC.Settings["listen"],
		"logging":  myC.Settings["logging"],
		"timers":   myC.Settings["timers"],
	}

	cb, err := yaml.Marshal(mc)
	if err != nil {
		panic(err)
	}

	r.Logf("reload new v1-only config")
	err = myC.ReloadConfigString(string(cb))
	assert.NoError(t, err)
	r.Log("yay, spin until their sees it")
	waitStart := time.Now()
	for {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		c := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
		c2 := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false)
		if c == nil || c2 == nil {
			r.Log("nil")
		} else {
			version := c.Cert.Version()
			theirVersion := c2.Cert.Version()
			r.Logf("version %d,%d", version, theirVersion)
			if version == cert.Version1 {
				break
			}
		}
		since := time.Since(waitStart)
		if since > time.Second*5 {
			r.Log("it is unusual that the cert is not new yet, but not a failure yet")
		}
		if since > time.Second*10 {
			r.Log("wtf")
			t.Fatal("Cert should be new by now")
		}
		time.Sleep(time.Second)
	}

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)

	myControl.Stop()
	theirControl.Stop()
}

func TestCertMismatchCorrection(t *testing.T) {
	t.Parallel()
	// The goal of this test is to ensure the shortest inactivity timeout will close the tunnel on both sides
	// under ideal conditions
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	ca2, _, caKey2, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	myCert, _, myPrivKey, _ := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, "me", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{netip.MustParsePrefix("10.128.0.1/24")}, nil, []string{})
	myCert2, _ := cert_test.NewTestCertDifferentVersion(myCert, cert.Version2, ca2, caKey2)

	theirCert, _, theirPrivKey, _ := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca, caKey, "them", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{netip.MustParsePrefix("10.128.0.2/24")}, nil, []string{})
	theirCert2, _ := cert_test.NewTestCertDifferentVersion(theirCert, cert.Version2, ca2, caKey2)

	myControl, myVpnIpNet, myUdpAddr, _ := newServer([]cert.Certificate{ca, ca2}, []cert.Certificate{myCert2}, myPrivKey, m{})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newServer([]cert.Certificate{ca, ca2}, []cert.Certificate{theirCert, theirCert2}, theirPrivKey, m{})

	// Share our underlay information
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	r.Log("Assert the tunnel between me and them works")
	//assertTunnel(t, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), theirControl, myControl, r)
	//r.Log("yay")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
	r.Log("yay")
	//todo ???
	time.Sleep(1 * time.Second)
	r.FlushAll()

	waitStart := time.Now()
	for {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		c := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
		c2 := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false)
		if c == nil || c2 == nil {
			r.Log("nil")
		} else {
			version := c.Cert.Version()
			theirVersion := c2.Cert.Version()
			r.Logf("version %d,%d", version, theirVersion)
			if version == theirVersion {
				break
			}
		}
		since := time.Since(waitStart)
		if since > time.Second*5 {
			r.Log("wtf")
		}
		if since > time.Second*10 {
			r.Log("wtf")
			t.Fatal("Cert should be new by now")
		}
		time.Sleep(time.Second)
	}

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)

	myControl.Stop()
	theirControl.Stop()
}

func TestCrossStackRelaysWork(t *testing.T) {
	t.Parallel()
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
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnV6.Addr(), 80, myVpnV6.Addr(), 80, []byte("Hi from me")))

	p := r.RouteForAllUntilTxTun(theirControl)
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnV6.Addr(), theirVpnV6.Addr(), 80, 80)

	t.Log("reply?")
	theirControl.InjectTunPacket(BuildTunUDPPacket(myVpnV6.Addr(), 80, theirVpnV6.Addr(), 80, []byte("Hi from them")))
	p = r.RouteForAllUntilTxTun(myControl)
	assertUdpPacket(t, []byte("Hi from them"), p, theirVpnV6.Addr(), myVpnV6.Addr(), 80, 80)

	r.RenderHostmaps("Final hostmaps", myControl, relayControl, theirControl)
	//t.Log("finish up")
	//myControl.Stop()
	//theirControl.Stop()
	//relayControl.Stop()
}

// TestRelayReplayProtection asserts that a relay (forwarding-type) node rejects
// replayed relay frames. A captured relay frame, re-injected with the same
// message counter, must be dropped by the replay window rather than re-forwarded
// to the relay target. Before the fix, handleOutsideRelayPacket authenticated the
// frame but never advanced the replay window, so every replay was re-forwarded.
func TestRelayReplayProtection(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version2, ca, caKey, "me     ", "10.128.0.1/24,fc00::1/64", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "relay  ", "10.128.0.128/24,fc00::128/64", m{"relay": m{"am_relay": true}})
	theirUdp := netip.MustParseAddrPort("10.0.0.2:4242")
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithUdp(cert.Version2, ca, caKey, "them   ", "fc00::2/64", theirUdp, m{"relay": m{"use_relays": true}})

	myVpnV6 := myVpnIpNet[1]
	relayVpnV4 := relayVpnIpNet[0]
	relayVpnV6 := relayVpnIpNet[1]
	theirVpnV6 := theirVpnIpNet[0]

	// Teach me how to reach the relay and that them is reachable via the relay
	myControl.InjectLightHouseAddr(relayVpnV4.Addr(), relayUdpAddr)
	myControl.InjectLightHouseAddr(relayVpnV6.Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnV6.Addr(), []netip.Addr{relayVpnV6.Addr()})
	relayControl.InjectLightHouseAddr(theirVpnV6.Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	// Establish the relayed tunnel in both directions so all handshakes complete.
	t.Log("Establish the relayed tunnel")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnV6.Addr(), 80, myVpnV6.Addr(), 80, []byte("Hi from me")))
	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnV6.Addr(), theirVpnV6.Addr(), 80, 80)
	theirControl.InjectTunPacket(BuildTunUDPPacket(myVpnV6.Addr(), 80, theirVpnV6.Addr(), 80, []byte("Hi from them")))
	p = r.RouteForAllUntilTxTun(myControl)
	assertUdpPacket(t, []byte("Hi from them"), p, theirVpnV6.Addr(), myVpnV6.Addr(), 80, 80)

	// Drain anything still queued on me's UDP tx so the next packet we pull is the
	// relay frame we are about to generate.
	for myControl.GetFromUDP(false) != nil {
	}

	// Capture a single legitimate relay frame that me transmits toward the relay.
	t.Log("Capture a relay frame from me -> relay")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnV6.Addr(), 80, myVpnV6.Addr(), 80, []byte("replay me")))
	relayFrame := myControl.GetFromUDP(true)
	require.Equal(t, relayUdpAddr, relayFrame.To, "captured frame should be addressed to the relay")
	var fh header.H
	require.NoError(t, fh.Parse(relayFrame.Data))
	require.Equal(t, header.Message, fh.Type)
	require.Equal(t, header.MessageRelay, fh.Subtype)

	// drainForwards counts relay frames the relay forwards toward them within the
	// settle window. We match on destination + (Message, MessageRelay) so the
	// relay's own direct traffic to them can't be miscounted.
	drainForwards := func(settle time.Duration) int {
		ch := relayControl.GetUDPTxChan()
		count := 0
		for {
			select {
			case pkt := <-ch:
				var ph header.H
				if pkt.To == theirUdpAddr && ph.Parse(pkt.Data) == nil &&
					ph.Type == header.Message && ph.Subtype == header.MessageRelay {
					count++
				}
				pkt.Release()
			case <-time.After(settle):
				return count
			}
		}
	}

	// First delivery of the captured frame: the relay should forward it once.
	t.Log("Deliver the captured frame once; relay forwards it to them")
	relayControl.InjectUDPPacket(relayFrame)
	require.Equal(t, 1, drainForwards(200*time.Millisecond), "relay should forward the first, legitimate copy")

	// Replay the exact same frame several times. A correct replay window rejects
	// these duplicates so the relay forwards none of them.
	t.Log("Replay the captured frame; relay must drop the duplicates")
	const replays = 3
	for i := 0; i < replays; i++ {
		relayControl.InjectUDPPacket(relayFrame)
	}
	forwarded := drainForwards(200 * time.Millisecond)
	assert.Equal(t, 0, forwarded, "relay re-forwarded %d/%d replayed relay frames; replay protection is ineffective on relay tunnels", forwarded, replays)

	r.RenderHostmaps("Final hostmaps", myControl, relayControl, theirControl)
}

func TestCloseTunnelAuthenticated(t *testing.T) {
	t.Parallel()
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

	r.Log("Close the tunnel")
	myControl.CloseTunnel(theirVpnIpNet[0].Addr(), false)
	r.FlushAll()

	waitStart := time.Now()
	for {
		myIndexes := myControl.GetHostmapIndexCount()
		theirIndexes := theirControl.GetHostmapIndexCount()
		if myIndexes == 0 && theirIndexes == 0 {
			break
		}

		since := time.Since(waitStart)
		r.Logf("my tunnels: %v; their tunnels: %v; duration: %v", myIndexes, theirIndexes, since)
		if since > time.Second*6 {
			t.Fatal("Tunnel should have been declared inactive after 2 seconds and before 6 seconds")
		}

		time.Sleep(1 * time.Second)
		//r.FlushAll()
	}

	r.Logf("Happy path success, tunnels were dropped within %v", time.Since(waitStart))

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)
	r.Log("Assert another tunnel between me and them works")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
	hi := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false)
	if hi == nil {
		t.Fatal("There is no hostinfo for this tunnel")
	}
	myHi := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
	if myHi == nil {
		t.Fatal("There is no hostinfo for my tunnel")
	}
	r.Log("It does")

	buf := make([]byte, 1024)
	hdr := header.H{
		Version:        1,
		Type:           header.CloseTunnel,
		Subtype:        0,
		Reserved:       0,
		RemoteIndex:    hi.RemoteIndex,
		MessageCounter: 5,
	}
	out, err := hdr.Encode(buf)
	if err != nil {
		t.Fatal(err)
	}

	pkt := &udp.Packet{
		To:   hi.CurrentRemote,
		From: myHi.CurrentRemote,
		Data: out,
	}
	r.InjectUDPPacket(myControl, theirControl, pkt)
	r.Log("Injected bogus close tunnel. Let's see!")
	waitStart = time.Now()
	for {
		myIndexes := myControl.GetHostmapIndexCount()
		theirIndexes := theirControl.GetHostmapIndexCount()
		if myIndexes == 0 {
			t.Fatal("myIndexes should not be 0")
		}
		if theirIndexes == 0 {
			t.Fatal("theirIndexes should not be 0, they should have rejected this bogus packet")
		}

		since := time.Since(waitStart)
		r.Logf("my tunnels: %v; their tunnels: %v; duration: %v", myIndexes, theirIndexes, since)
		if since > time.Second*4 {
			t.Log("The tunnel would have been gone by now")
			break
		}

		time.Sleep(1 * time.Second)
		r.FlushAll()
	}

	myControl.Stop()
	theirControl.Stop()
}
