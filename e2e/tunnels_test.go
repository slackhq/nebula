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
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
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

func TestCertUpgrade(t *testing.T) {
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
