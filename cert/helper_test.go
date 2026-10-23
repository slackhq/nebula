package cert

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/netip"
	"testing"
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

	if version == Version3 {
		pub, priv = appendPQSigningKey(pub, priv)
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
	if version == Version3 {
		t.PQSuite = DefaultPQSuite
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

	if v == Version3 {
		pub, priv = appendPQKey(ca, pub, priv)
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
		PQSuite:        PQSuiteOf(ca),
		// A v3 host certificate has a v2 form when its CA does.
		OmitV2Form: v == Version3 && V2Form(ca) == nil,
	}

	c, err := nc.Sign(ca, ca.Curve(), key)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
	}

	if v == Version3 {
		return c, pub, MarshalPQPrivateKeyToPEM(curve, PQSuiteOf(ca), priv), pem
	}
	return c, pub, MarshalPrivateKeyToPEM(curve, priv), pem
}

// appendPQSigningKey makes a classical CA keypair into a version 3 composite one with a fresh key of the default suite.
func appendPQSigningKey(pub, priv []byte) ([]byte, []byte) {
	pqPub, pqPriv, err := DefaultPQSuite.GenerateKey(true)
	if err != nil {
		panic(err)
	}
	return append(pub, pqPub...), append(priv, pqPriv...)
}

// appendPQKey makes a classical host keypair into a version 3 composite one with a fresh key of the CA's suite.
func appendPQKey(ca Certificate, pub, priv []byte) ([]byte, []byte) {
	pqPub, pqPriv, err := PQSuiteOf(ca).GenerateKey(false)
	if err != nil {
		panic(err)
	}
	return append(pub, pqPub...), append(priv, pqPriv...)
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

// skipWithoutPQ skips a test that needs the default post-quantum suite when this build can not run it, as under the
// FIPS 140-3 Go Cryptographic Module v1.0.0, which has no ML-DSA.
func skipWithoutPQ(t testing.TB) {
	t.Helper()
	if err := DefaultPQSuite.Available(); err != nil {
		t.Skip(err)
	}
}
