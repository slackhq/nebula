//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"dario.cat/mergo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

type m = map[string]any

// newSimpleServer creates a nebula instance with many assumptions
func newSimpleServer(v cert.Version, caCrt cert.Certificate, caKey []byte, name string, sVpnNetworks string, overrides m) (*nebula.Control, []netip.Prefix, netip.AddrPort, *config.C) {
	var vpnNetworks []netip.Prefix
	for _, sn := range strings.Split(sVpnNetworks, ",") {
		vpnIpNet, err := netip.ParsePrefix(strings.TrimSpace(sn))
		if err != nil {
			panic(err)
		}
		vpnNetworks = append(vpnNetworks, vpnIpNet)
	}

	if len(vpnNetworks) == 0 {
		panic("no vpn networks")
	}

	var udpAddr netip.AddrPort
	if vpnNetworks[0].Addr().Is4() {
		budpIp := vpnNetworks[0].Addr().As4()
		budpIp[1] -= 128
		udpAddr = netip.AddrPortFrom(netip.AddrFrom4(budpIp), 4242)
	} else {
		budpIp := vpnNetworks[0].Addr().As16()
		// beef for funsies
		budpIp[2] = 190
		budpIp[3] = 239
		udpAddr = netip.AddrPortFrom(netip.AddrFrom16(budpIp), 4242)
	}
	return newSimpleServerWithUdp(v, caCrt, caKey, name, sVpnNetworks, udpAddr, overrides)
}

func newSimpleServerWithUdp(v cert.Version, caCrt cert.Certificate, caKey []byte, name string, sVpnNetworks string, udpAddr netip.AddrPort, overrides m) (*nebula.Control, []netip.Prefix, netip.AddrPort, *config.C) {
	return newSimpleServerWithUdpAndUnsafeNetworks(v, caCrt, caKey, name, sVpnNetworks, udpAddr, "", overrides)
}

func newSimpleServerWithUdpAndUnsafeNetworks(v cert.Version, caCrt cert.Certificate, caKey []byte, name string, sVpnNetworks string, udpAddr netip.AddrPort, sUnsafeNetworks string, overrides m) (*nebula.Control, []netip.Prefix, netip.AddrPort, *config.C) {
	l := NewTestLogger()

	var vpnNetworks []netip.Prefix
	for _, sn := range strings.Split(sVpnNetworks, ",") {
		vpnIpNet, err := netip.ParsePrefix(strings.TrimSpace(sn))
		if err != nil {
			panic(err)
		}
		vpnNetworks = append(vpnNetworks, vpnIpNet)
	}

	if len(vpnNetworks) == 0 {
		panic("no vpn networks")
	}

	firewallInbound := []m{{
		"proto": "any",
		"port":  "any",
		"host":  "any",
	}}

	var unsafeNetworks []netip.Prefix
	if sUnsafeNetworks != "" {
		firewallInbound = []m{{
			"proto":      "any",
			"port":       "any",
			"host":       "any",
			"local_cidr": "0.0.0.0/0",
		}}

		for _, sn := range strings.Split(sUnsafeNetworks, ",") {
			x, err := netip.ParsePrefix(strings.TrimSpace(sn))
			if err != nil {
				panic(err)
			}
			unsafeNetworks = append(unsafeNetworks, x)
		}
	}

	_, _, myPrivKey, myPEM := cert_test.NewTestCert(v, cert.Curve_CURVE25519, caCrt, caKey, name, time.Now(), time.Now().Add(5*time.Minute), vpnNetworks, unsafeNetworks, []string{})

	caB, err := caCrt.MarshalPEM()
	if err != nil {
		panic(err)
	}

	mc := m{
		"pki": m{
			"ca":   string(caB),
			"cert": string(myPEM),
			"key":  string(myPrivKey),
		},
		//"tun": m{"disabled": true},
		"firewall": m{
			"outbound": []m{{
				"proto": "any",
				"port":  "any",
				"host":  "any",
			}},
			"inbound": firewallInbound,
		},
		//"handshakes": m{
		//	"try_interval": "1s",
		//},
		"listen": m{
			"host": udpAddr.Addr().String(),
			"port": udpAddr.Port(),
		},
		"logging": m{
			"timestamp_format": fmt.Sprintf("%v 15:04:05.000000", name),
			"level":            l.Level.String(),
		},
		"timers": m{
			"pending_deletion_interval": 2,
			"connection_alive_interval": 2,
		},
	}

	if overrides != nil {
		final := m{}
		err = mergo.Merge(&final, overrides, mergo.WithAppendSlice)
		if err != nil {
			panic(err)
		}
		err = mergo.Merge(&final, mc, mergo.WithAppendSlice)
		if err != nil {
			panic(err)
		}
		mc = final
	}

	cb, err := yaml.Marshal(mc)
	if err != nil {
		panic(err)
	}

	c := config.NewC(l)
	c.LoadString(string(cb))

	control, err := nebula.Main(c, false, "e2e-test", l, nil)

	if err != nil {
		panic(err)
	}

	return control, vpnNetworks, udpAddr, c
}

// newServer creates a nebula instance with fewer assumptions
func newServer(caCrt []cert.Certificate, certs []cert.Certificate, key []byte, overrides m) (*nebula.Control, []netip.Prefix, netip.AddrPort, *config.C) {
	l := NewTestLogger()

	vpnNetworks := certs[len(certs)-1].Networks()

	var udpAddr netip.AddrPort
	if vpnNetworks[0].Addr().Is4() {
		budpIp := vpnNetworks[0].Addr().As4()
		budpIp[1] -= 128
		udpAddr = netip.AddrPortFrom(netip.AddrFrom4(budpIp), 4242)
	} else {
		budpIp := vpnNetworks[0].Addr().As16()
		// beef for funsies
		budpIp[2] = 190
		budpIp[3] = 239
		udpAddr = netip.AddrPortFrom(netip.AddrFrom16(budpIp), 4242)
	}

	caStr := ""
	for _, ca := range caCrt {
		x, err := ca.MarshalPEM()
		if err != nil {
			panic(err)
		}
		caStr += string(x)
	}
	certStr := ""
	for _, c := range certs {
		x, err := c.MarshalPEM()
		if err != nil {
			panic(err)
		}
		certStr += string(x)
	}

	mc := m{
		"pki": m{
			"ca":   caStr,
			"cert": certStr,
			"key":  string(key),
		},
		//"tun": m{"disabled": true},
		"firewall": m{
			"outbound": []m{{
				"proto": "any",
				"port":  "any",
				"host":  "any",
			}},
			"inbound": []m{{
				"proto": "any",
				"port":  "any",
				"host":  "any",
			}},
		},
		//"handshakes": m{
		//	"try_interval": "1s",
		//},
		"listen": m{
			"host": udpAddr.Addr().String(),
			"port": udpAddr.Port(),
		},
		"logging": m{
			"timestamp_format": fmt.Sprintf("%v 15:04:05.000000", certs[0].Name()),
			"level":            l.Level.String(),
		},
		"timers": m{
			"pending_deletion_interval": 2,
			"connection_alive_interval": 2,
		},
	}

	if overrides != nil {
		final := m{}
		err := mergo.Merge(&final, overrides, mergo.WithAppendSlice)
		if err != nil {
			panic(err)
		}
		err = mergo.Merge(&final, mc, mergo.WithAppendSlice)
		if err != nil {
			panic(err)
		}
		mc = final
	}

	cb, err := yaml.Marshal(mc)
	if err != nil {
		panic(err)
	}

	c := config.NewC(l)
	cStr := string(cb)
	c.LoadString(cStr)

	control, err := nebula.Main(c, false, "e2e-test", l, nil)

	if err != nil {
		panic(err)
	}

	return control, vpnNetworks, udpAddr, c
}

type doneCb func()

func deadline(t *testing.T, seconds time.Duration) doneCb {
	timeout := time.After(seconds * time.Second)
	done := make(chan bool)
	go func() {
		select {
		case <-timeout:
			t.Fatal("Test did not finish in time")
		case <-done:
		}
	}()

	return func() {
		done <- true
	}
}

func assertTunnel(t testing.TB, vpnIpA, vpnIpB netip.Addr, controlA, controlB *nebula.Control, r *router.R) {
	// Send a packet from them to me
	controlB.InjectTunUDPPacket(vpnIpA, 80, vpnIpB, 90, []byte("Hi from B"))
	bPacket := r.RouteForAllUntilTxTun(controlA)
	assertUdpPacket(t, []byte("Hi from B"), bPacket, vpnIpB, vpnIpA, 90, 80)

	// And once more from me to them
	controlA.InjectTunUDPPacket(vpnIpB, 80, vpnIpA, 90, []byte("Hello from A"))
	aPacket := r.RouteForAllUntilTxTun(controlB)
	assertUdpPacket(t, []byte("Hello from A"), aPacket, vpnIpA, vpnIpB, 90, 80)
}

func assertHostInfoPair(t testing.TB, addrA, addrB netip.AddrPort, vpnNetsA, vpnNetsB []netip.Prefix, controlA, controlB *nebula.Control) {
	// Get both host infos
	//TODO: CERT-V2 we may want to loop over each vpnAddr and assert all the things
	hBinA := controlA.GetHostInfoByVpnAddr(vpnNetsB[0].Addr(), false)
	require.NotNil(t, hBinA, "Host B was not found by vpnAddr in controlA")

	hAinB := controlB.GetHostInfoByVpnAddr(vpnNetsA[0].Addr(), false)
	require.NotNil(t, hAinB, "Host A was not found by vpnAddr in controlB")

	// Check that both vpn and real addr are correct
	assert.EqualValues(t, getAddrs(vpnNetsB), hBinA.VpnAddrs, "Host B VpnIp is wrong in control A")
	assert.EqualValues(t, getAddrs(vpnNetsA), hAinB.VpnAddrs, "Host A VpnIp is wrong in control B")

	assert.Equal(t, addrB, hBinA.CurrentRemote, "Host B remote is wrong in control A")
	assert.Equal(t, addrA, hAinB.CurrentRemote, "Host A remote is wrong in control B")

	// Check that our indexes match
	assert.Equal(t, hBinA.LocalIndex, hAinB.RemoteIndex, "Host B local index does not match host A remote index")
	assert.Equal(t, hBinA.RemoteIndex, hAinB.LocalIndex, "Host B remote index does not match host A local index")
}

func assertUdpPacket(t testing.TB, expected, b []byte, fromIp, toIp netip.Addr, fromPort, toPort uint16) {
	if toIp.Is6() {
		assertUdpPacket6(t, expected, b, fromIp, toIp, fromPort, toPort)
	} else {
		assertUdpPacket4(t, expected, b, fromIp, toIp, fromPort, toPort)
	}
}

func assertUdpPacket6(t testing.TB, expected, b []byte, fromIp, toIp netip.Addr, fromPort, toPort uint16) {
	packet := gopacket.NewPacket(b, layers.LayerTypeIPv6, gopacket.Lazy)
	v6 := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	assert.NotNil(t, v6, "No ipv6 data found")

	assert.Equal(t, fromIp.AsSlice(), []byte(v6.SrcIP), "Source ip was incorrect")
	assert.Equal(t, toIp.AsSlice(), []byte(v6.DstIP), "Dest ip was incorrect")

	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	assert.NotNil(t, udp, "No udp data found")

	assert.Equal(t, fromPort, uint16(udp.SrcPort), "Source port was incorrect")
	assert.Equal(t, toPort, uint16(udp.DstPort), "Dest port was incorrect")

	data := packet.ApplicationLayer()
	assert.NotNil(t, data)
	assert.Equal(t, expected, data.Payload(), "Data was incorrect")
}

func assertUdpPacket4(t testing.TB, expected, b []byte, fromIp, toIp netip.Addr, fromPort, toPort uint16) {
	packet := gopacket.NewPacket(b, layers.LayerTypeIPv4, gopacket.Lazy)
	v4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	assert.NotNil(t, v4, "No ipv4 data found")

	assert.Equal(t, fromIp.AsSlice(), []byte(v4.SrcIP), "Source ip was incorrect")
	assert.Equal(t, toIp.AsSlice(), []byte(v4.DstIP), "Dest ip was incorrect")

	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	assert.NotNil(t, udp, "No udp data found")

	assert.Equal(t, fromPort, uint16(udp.SrcPort), "Source port was incorrect")
	assert.Equal(t, toPort, uint16(udp.DstPort), "Dest port was incorrect")

	data := packet.ApplicationLayer()
	assert.NotNil(t, data)
	assert.Equal(t, expected, data.Payload(), "Data was incorrect")
}

func getAddrs(ns []netip.Prefix) []netip.Addr {
	var a []netip.Addr
	for _, n := range ns {
		a = append(a, n.Addr())
	}
	return a
}

func NewTestLogger() *logrus.Logger {
	l := logrus.New()

	v := os.Getenv("TEST_LOGS")
	if v == "" {
		l.SetOutput(io.Discard)
		l.SetLevel(logrus.PanicLevel)
		return l
	}

	switch v {
	case "2":
		l.SetLevel(logrus.DebugLevel)
	case "3":
		l.SetLevel(logrus.TraceLevel)
	default:
		l.SetLevel(logrus.InfoLevel)
	}

	return l
}
