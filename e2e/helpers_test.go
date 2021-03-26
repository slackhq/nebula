// +build e2e_testing

package e2e

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/yaml.v2"
)

type m map[string]interface{}

// newSimpleServer creates a nebula instance with many assumptions
func newSimpleServer(caCrt *cert.NebulaCertificate, caKey []byte, name string, listenAddr *net.UDPAddr, vpnIp *net.IPNet) *nebula.Control {
	l := logrus.New()
	_, _, myPrivKey, myPEM := newTestCert(caCrt, caKey, name, time.Now(), time.Now().Add(5*time.Minute), vpnIp, nil, []string{})

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
		"listen": m{
			"host": listenAddr.IP.String(),
			"port": listenAddr.Port,
		},
		"logging": m{
			"timestamp_format": fmt.Sprintf("%v 15:04:05.000000", name),
			"level":            "info",
		},
	}
	cb, err := yaml.Marshal(mc)
	if err != nil {
		panic(err)
	}

	config := nebula.NewConfig(l)
	config.LoadString(string(cb))

	control, err := nebula.Main(config, false, "e2e-test", l, nil)

	if err != nil {
		panic(err)
	}

	return control
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

	err = nc.Sign(priv)
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

	err = nc.Sign(key)
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
	var pubkey, privkey [32]byte
	if _, err := io.ReadFull(rand.Reader, privkey[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return pubkey[:], privkey[:]
}

func ip2int(ip []byte) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func assertHostInfoPair(t *testing.T, addrA, addrB *net.UDPAddr, vpnIpA, vpnIpB net.IP, controlA, controlB *nebula.Control) {
	// Get both host infos
	hBinA := controlA.GetHostInfoByVpnIP(ip2int(vpnIpB), false)
	assert.NotNil(t, hBinA, "Host B was not found by vpnIP in controlA")

	hAinB := controlB.GetHostInfoByVpnIP(ip2int(vpnIpA), false)
	assert.NotNil(t, hAinB, "Host A was not found by vpnIP in controlB")

	// Check that both vpn and real addr are correct
	assert.Equal(t, vpnIpB, hBinA.VpnIP, "HostA VpnIp is wrong in controlB")
	assert.Equal(t, vpnIpA, hAinB.VpnIP, "HostB VpnIp is wrong in controlA")

	assert.Equal(t, addrB.IP.To16(), hBinA.CurrentRemote.IP.To16(), "HostA remote ip is wrong in controlB")
	assert.Equal(t, addrA.IP.To16(), hAinB.CurrentRemote.IP.To16(), "HostB remote ip is wrong in controlA")

	assert.Equal(t, uint16(addrA.Port), hBinA.CurrentRemote.Port, "HostA remote ip is wrong in controlB")
	assert.Equal(t, uint16(addrB.Port), hAinB.CurrentRemote.Port, "HostB remote ip is wrong in controlA")

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
