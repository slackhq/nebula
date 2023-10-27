//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"dario.cat/mergo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/iputil"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/yaml.v2"
)

type m map[string]interface{}

// newSimpleServer creates a nebula instance with many assumptions
func newSimpleServer(caCrt *cert.NebulaCertificate, caKey []byte, name string, udpIp net.IP, overrides m) (*nebula.Control, *net.IPNet, *net.UDPAddr, *config.C) {
	l := NewTestLogger()

	vpnIpNet := &net.IPNet{IP: make([]byte, len(udpIp)), Mask: net.IPMask{255, 255, 255, 0}}
	copy(vpnIpNet.IP, udpIp)
	vpnIpNet.IP[1] += 128
	udpAddr := net.UDPAddr{
		IP:   udpIp,
		Port: 4242,
	}
	_, _, myPrivKey, myPEM := newTestCert(caCrt, caKey, name, time.Now(), time.Now().Add(5*time.Minute), vpnIpNet, nil, []string{})

	caB, err := caCrt.MarshalToPEM()
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
			"host": udpAddr.IP.String(),
			"port": udpAddr.Port,
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
		err = mergo.Merge(&overrides, mc, mergo.WithAppendSlice)
		if err != nil {
			panic(err)
		}
		mc = overrides
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

	return control, vpnIpNet, &udpAddr, c
}

// newTestCaCert will generate a CA cert
func newTestCaCert(before, after time.Time, ips, subnets []*net.IPNet, groups []string) (*cert.NebulaCertificate, []byte, []byte, []byte) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           "test ca",
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           true,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	if len(ips) > 0 {
		nc.Details.Ips = ips
	}

	if len(subnets) > 0 {
		nc.Details.Subnets = subnets
	}

	if len(groups) > 0 {
		nc.Details.Groups = groups
	}

	err = nc.Sign(cert.Curve_CURVE25519, priv)
	if err != nil {
		panic(err)
	}

	pem, err := nc.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	return nc, pub, priv, pem
}

// newTestCert will generate a signed certificate with the provided details.
// Expiry times are defaulted if you do not pass them in
func newTestCert(ca *cert.NebulaCertificate, key []byte, name string, before, after time.Time, ip *net.IPNet, subnets []*net.IPNet, groups []string) (*cert.NebulaCertificate, []byte, []byte, []byte) {
	issuer, err := ca.Sha256Sum()
	if err != nil {
		panic(err)
	}

	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}

	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	pub, rawPriv := x25519Keypair()

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           name,
			Ips:            []*net.IPNet{ip},
			Subnets:        subnets,
			Groups:         groups,
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           false,
			Issuer:         issuer,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	err = nc.Sign(ca.Details.Curve, key)
	if err != nil {
		panic(err)
	}

	pem, err := nc.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	return nc, pub, cert.MarshalX25519PrivateKey(rawPriv), pem
}

func x25519Keypair() ([]byte, []byte) {
	privkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		panic(err)
	}

	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	return pubkey, privkey
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

func assertTunnel(t *testing.T, vpnIpA, vpnIpB net.IP, controlA, controlB *nebula.Control, r *router.R) {
	// Send a packet from them to me
	controlB.InjectTunUDPPacket(vpnIpA, 80, 90, []byte("Hi from B"))
	bPacket := r.RouteForAllUntilTxTun(controlA)
	assertUdpPacket(t, []byte("Hi from B"), bPacket, vpnIpB, vpnIpA, 90, 80)

	// And once more from me to them
	controlA.InjectTunUDPPacket(vpnIpB, 80, 90, []byte("Hello from A"))
	aPacket := r.RouteForAllUntilTxTun(controlB)
	assertUdpPacket(t, []byte("Hello from A"), aPacket, vpnIpA, vpnIpB, 90, 80)
}

func assertHostInfoPair(t *testing.T, addrA, addrB *net.UDPAddr, vpnIpA, vpnIpB net.IP, controlA, controlB *nebula.Control) {
	// Get both host infos
	hBinA := controlA.GetHostInfoByVpnIp(iputil.Ip2VpnIp(vpnIpB), false)
	assert.NotNil(t, hBinA, "Host B was not found by vpnIp in controlA")

	hAinB := controlB.GetHostInfoByVpnIp(iputil.Ip2VpnIp(vpnIpA), false)
	assert.NotNil(t, hAinB, "Host A was not found by vpnIp in controlB")

	// Check that both vpn and real addr are correct
	assert.Equal(t, vpnIpB, hBinA.VpnIp, "Host B VpnIp is wrong in control A")
	assert.Equal(t, vpnIpA, hAinB.VpnIp, "Host A VpnIp is wrong in control B")

	assert.Equal(t, addrB.IP.To16(), hBinA.CurrentRemote.IP.To16(), "Host B remote ip is wrong in control A")
	assert.Equal(t, addrA.IP.To16(), hAinB.CurrentRemote.IP.To16(), "Host A remote ip is wrong in control B")

	assert.Equal(t, addrB.Port, int(hBinA.CurrentRemote.Port), "Host B remote port is wrong in control A")
	assert.Equal(t, addrA.Port, int(hAinB.CurrentRemote.Port), "Host A remote port is wrong in control B")

	// Check that our indexes match
	assert.Equal(t, hBinA.LocalIndex, hAinB.RemoteIndex, "Host B local index does not match host A remote index")
	assert.Equal(t, hBinA.RemoteIndex, hAinB.LocalIndex, "Host B remote index does not match host A local index")

	//TODO: Would be nice to assert this memory
	//checkIndexes := func(name string, hm *HostMap, hi *HostInfo) {
	//	hBbyIndex := hmA.Indexes[hBinA.localIndexId]
	//	assert.NotNil(t, hBbyIndex, "Could not host info by local index in %s", name)
	//	assert.Equal(t, &hBbyIndex, &hBinA, "%s Indexes map did not point to the right host info", name)
	//
	//	//TODO: remote indexes are susceptible to collision
	//	hBbyRemoteIndex := hmA.RemoteIndexes[hBinA.remoteIndexId]
	//	assert.NotNil(t, hBbyIndex, "Could not host info by remote index in %s", name)
	//	assert.Equal(t, &hBbyRemoteIndex, &hBinA, "%s RemoteIndexes did not point to the right host info", name)
	//}
	//
	//// Check hostmap indexes too
	//checkIndexes("hmA", hmA, hBinA)
	//checkIndexes("hmB", hmB, hAinB)
}

func assertUdpPacket(t *testing.T, expected, b []byte, fromIp, toIp net.IP, fromPort, toPort uint16) {
	packet := gopacket.NewPacket(b, layers.LayerTypeIPv4, gopacket.Lazy)
	v4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	assert.NotNil(t, v4, "No ipv4 data found")

	assert.Equal(t, fromIp, v4.SrcIP, "Source ip was incorrect")
	assert.Equal(t, toIp, v4.DstIP, "Dest ip was incorrect")

	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	assert.NotNil(t, udp, "No udp data found")

	assert.Equal(t, fromPort, uint16(udp.SrcPort), "Source port was incorrect")
	assert.Equal(t, toPort, uint16(udp.DstPort), "Dest port was incorrect")

	data := packet.ApplicationLayer()
	assert.NotNil(t, data)
	assert.Equal(t, expected, data.Payload(), "Data was incorrect")
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
