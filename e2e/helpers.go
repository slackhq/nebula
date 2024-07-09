package e2e

import (
	"crypto/rand"
	"io"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

// NewTestCaCert will generate a CA cert
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
