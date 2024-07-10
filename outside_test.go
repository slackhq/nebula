package nebula

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"dario.cat/mergo"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/net/ipv4"
	"gopkg.in/yaml.v2"
)

func Test_newPacket(t *testing.T) {
	p := &firewall.Packet{}

	// length fail
	err := newPacket([]byte{0, 1}, true, p)
	assert.EqualError(t, err, "packet is less than 20 bytes")

	// length fail with ip options
	h := ipv4.Header{
		Version: 1,
		Len:     100,
		Src:     net.IPv4(10, 0, 0, 1),
		Dst:     net.IPv4(10, 0, 0, 2),
		Options: []byte{0, 1, 0, 2},
	}

	b, _ := h.Marshal()
	err = newPacket(b, true, p)

	assert.EqualError(t, err, "packet is less than 28 bytes, ip header len: 24")

	// not an ipv4 packet
	err = newPacket([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true, p)
	assert.EqualError(t, err, "packet is not ipv4, type: 0")

	// invalid ihl
	err = newPacket([]byte{4<<4 | (8 >> 2 & 0x0f), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true, p)
	assert.EqualError(t, err, "packet had an invalid header length: 8")

	// account for variable ip header length - incoming
	h = ipv4.Header{
		Version:  1,
		Len:      100,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Options:  []byte{0, 1, 0, 2},
		Protocol: firewall.ProtoTCP,
	}

	b, _ = h.Marshal()
	b = append(b, []byte{0, 3, 0, 4}...)
	err = newPacket(b, true, p)

	assert.Nil(t, err)
	assert.Equal(t, p.Protocol, uint8(firewall.ProtoTCP))
	assert.Equal(t, p.LocalIP, netip.MustParseAddr("10.0.0.2"))
	assert.Equal(t, p.RemoteIP, netip.MustParseAddr("10.0.0.1"))
	assert.Equal(t, p.RemotePort, uint16(3))
	assert.Equal(t, p.LocalPort, uint16(4))

	// account for variable ip header length - outgoing
	h = ipv4.Header{
		Version:  1,
		Protocol: 2,
		Len:      100,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Options:  []byte{0, 1, 0, 2},
	}

	b, _ = h.Marshal()
	b = append(b, []byte{0, 5, 0, 6}...)
	err = newPacket(b, false, p)

	assert.Nil(t, err)
	assert.Equal(t, p.Protocol, uint8(2))
	assert.Equal(t, p.LocalIP, netip.MustParseAddr("10.0.0.1"))
	assert.Equal(t, p.RemoteIP, netip.MustParseAddr("10.0.0.2"))
	assert.Equal(t, p.RemotePort, uint16(6))
	assert.Equal(t, p.LocalPort, uint16(5))
}

func TestTemp(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), netip.Prefix{}, nil, []string{})

	lhControl, _, _ := newSimpleServer(ca, caKey, "lh", "fdee::1/64", m{"listen": m{"port": 10000}})
	//myControl, _, _ := newSimpleServer(ca, caKey, "me  ", "fdee::2/64", m{"listen": m{"port": 10001}})
	//theirControl, _, _ := newSimpleServer(ca, caKey, "them", "fdee::3/64", m{"listen": m{"port": 10002}})

	lhControl.Start()
	//myControl.Start()
	//theirControl.Start()

	time.Sleep(time.Hour)
}

func newSimpleServer(caCrt *cert.NebulaCertificate, caKey []byte, name string, sVpnIpNet string, overrides m) (*Control, netip.Prefix, *config.C) {
	l := logrus.New()
	vpnIpNet, err := netip.ParsePrefix(sVpnIpNet)
	if err != nil {
		panic(err)
	}

	_, _, myPrivKey, myPEM := NewTestCert(caCrt, caKey, name, time.Now(), time.Now().Add(5*time.Minute), vpnIpNet, nil, []string{})

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
			"host": "::",
			"port": "0",
		},
		"logging": m{
			"timestamp_format": fmt.Sprintf("%v 15:04:05.000000", name),
			"level":            "debug",
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

	control, err := Main(c, false, "e2e-test", l, nil)

	if err != nil {
		panic(err)
	}

	return control, vpnIpNet, c
}

func NewTestCaCert(before, after time.Time, ip netip.Prefix, subnets []netip.Prefix, groups []string) (*cert.NebulaCertificate, []byte, []byte, []byte) {
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
			Ip:             ip,
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           true,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	if len(subnets) > 0 {
		nc.Details.Subnets = make([]netip.Prefix, len(subnets))
		for i, ip := range subnets {
			nc.Details.Subnets[i] = ip
		}
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

// NewTestCert will generate a signed certificate with the provided details.
// Expiry times are defaulted if you do not pass them in
func NewTestCert(ca *cert.NebulaCertificate, key []byte, name string, before, after time.Time, ip netip.Prefix, subnets []netip.Prefix, groups []string) (*cert.NebulaCertificate, []byte, []byte, []byte) {
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
			Name: name,
			Ip:   ip,
			//Subnets:        subnets,
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
