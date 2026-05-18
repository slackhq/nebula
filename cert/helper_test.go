package cert

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/netip"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

// testCertNow is the reference "now" used to derive default before/after times
// in NewTestCaCert and NewTestCert. Holding it fixed for the lifetime of the
// test binary keeps CA and leaf defaults aligned at the same second, so a leaf
// signed with default times can never expire after its CA on a rounding race.
var testCertNow = time.Now().Round(time.Second)

// NewTestCaCert will create a new ca certificate
func NewTestCaCert(version Version, curve Curve, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (Certificate, []byte, []byte, []byte) {
	var err error
	var pub, priv []byte

	switch curve {
	case Curve_CURVE25519:
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
	case Curve_P256:
		privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		pub = elliptic.Marshal(elliptic.P256(), privk.PublicKey.X, privk.PublicKey.Y)
		priv = privk.D.FillBytes(make([]byte, 32))
	default:
		// There is no default to allow the underlying lib to respond with an error
	}

	if before.IsZero() {
		before = testCertNow.Add(time.Second * -60)
	}
	if after.IsZero() {
		after = testCertNow.Add(time.Second * 60)
	}

	t := &TBSCertificate{
		Curve:          curve,
		Version:        version,
		Name:           "test ca",
		NotBefore:      time.Unix(before.Unix(), 0),
		NotAfter:       time.Unix(after.Unix(), 0),
		PublicKey:      pub,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		IsCA:           true,
	}

	c, err := t.Sign(nil, curve, priv)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
	}

	return c, pub, priv, pem
}

// NewTestCert will generate a signed certificate with the provided details.
// Expiry times are defaulted if you do not pass them in
func NewTestCert(v Version, curve Curve, ca Certificate, key []byte, name string, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (Certificate, []byte, []byte, []byte) {
	if before.IsZero() {
		before = testCertNow.Add(time.Second * -60)
	}

	if after.IsZero() {
		after = testCertNow.Add(time.Second * 60)
	}

	if len(networks) == 0 {
		networks = []netip.Prefix{netip.MustParsePrefix("10.0.0.123/8")}
	}

	var pub, priv []byte
	switch curve {
	case Curve_CURVE25519:
		pub, priv = X25519Keypair()
	case Curve_P256:
		pub, priv = P256Keypair()
	default:
		panic("unknown curve")
	}

	nc := &TBSCertificate{
		Version:        v,
		Curve:          curve,
		Name:           name,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		NotBefore:      time.Unix(before.Unix(), 0),
		NotAfter:       time.Unix(after.Unix(), 0),
		PublicKey:      pub,
		IsCA:           false,
	}

	c, err := nc.Sign(ca, ca.Curve(), key)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
	}

	return c, pub, MarshalPrivateKeyToPEM(curve, priv), pem
}

func X25519Keypair() ([]byte, []byte) {
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

func P256Keypair() ([]byte, []byte) {
	privkey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey := privkey.PublicKey()
	return pubkey.Bytes(), privkey.Bytes()
}
