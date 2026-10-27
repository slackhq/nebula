package cert_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

// testCertNow is the reference "now" used to derive default before/after times
// in NewTestCaCert and NewTestCert. Holding it fixed for the lifetime of the
// test binary keeps CA and leaf defaults aligned at the same second, so a leaf
// signed with default times can never expire after its CA on a rounding race.
var testCertNow = time.Now().Round(time.Second)

// NewTestCaCert will create a new ca certificate
func NewTestCaCert(version cert.Version, curve cert.Curve, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (cert.Certificate, []byte, []byte, []byte) {
	return newTestCaCert(version, curve, before, after, networks, unsafeNetworks, groups, false)
}

// NewTestV3CaCertWithoutV2Form is NewTestCaCert for a version 3 CA without a v2 form, whose host certificates
// NewTestCert then makes without one too.
func NewTestV3CaCertWithoutV2Form(curve cert.Curve, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (cert.Certificate, []byte, []byte, []byte) {
	return newTestCaCert(cert.Version3, curve, before, after, networks, unsafeNetworks, groups, true)
}

func newTestCaCert(version cert.Version, curve cert.Curve, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string, omitV2Form bool) (cert.Certificate, []byte, []byte, []byte) {
	var err error
	var pub, priv []byte

	switch curve {
	case cert.Curve_CURVE25519:
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
	case cert.Curve_P256:
		privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		pub = elliptic.Marshal(elliptic.P256(), privk.PublicKey.X, privk.PublicKey.Y)
		priv = privk.D.FillBytes(make([]byte, 32))
	default:
		// There is no default to allow the underlying lib to respond with an error
	}

	if version == cert.Version3 {
		pub, priv = appendPQSigningKey(pub, priv)
	}

	if before.IsZero() {
		before = testCertNow.Add(time.Second * -60)
	}
	if after.IsZero() {
		after = testCertNow.Add(time.Second * 60)
	}

	t := &cert.TBSCertificate{
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
		OmitV2Form:     omitV2Form,
	}
	if version == cert.Version3 {
		t.PQSuite = cert.DefaultPQSuite
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
func NewTestCert(v cert.Version, curve cert.Curve, ca cert.Certificate, key []byte, name string, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (cert.Certificate, []byte, []byte, []byte) {
	if before.IsZero() {
		before = testCertNow.Add(time.Second * -60)
	}

	if after.IsZero() {
		after = testCertNow.Add(time.Second * 60)
	}

	var pub, priv []byte
	switch curve {
	case cert.Curve_CURVE25519:
		pub, priv = X25519Keypair()
	case cert.Curve_P256:
		pub, priv = P256Keypair()
	default:
		panic("unknown curve")
	}

	if v == cert.Version3 {
		pub, priv = appendPQKey(ca, pub, priv)
	}

	nc := &cert.TBSCertificate{
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
		PQSuite:        cert.PQSuiteOf(ca),
		// A v3 host certificate has a v2 form when its CA does.
		OmitV2Form: v == cert.Version3 && cert.V2Form(ca) == nil,
	}

	c, err := nc.Sign(ca, ca.Curve(), key)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
	}

	if v == cert.Version3 {
		return c, pub, cert.MarshalPQPrivateKeyToPEM(curve, cert.PQSuiteOf(ca), priv), pem
	}
	return c, pub, cert.MarshalPrivateKeyToPEM(curve, priv), pem
}

func NewTestCertDifferentVersion(c cert.Certificate, v cert.Version, ca cert.Certificate, key []byte) (cert.Certificate, []byte) {
	nc := &cert.TBSCertificate{
		Version:        v,
		Curve:          c.Curve(),
		Name:           c.Name(),
		Networks:       c.Networks(),
		UnsafeNetworks: c.UnsafeNetworks(),
		Groups:         c.Groups(),
		NotBefore:      time.Unix(c.NotBefore().Unix(), 0),
		NotAfter:       time.Unix(c.NotAfter().Unix(), 0),
		PublicKey:      c.PublicKey(),
		IsCA:           false,
		PQSuite:        cert.PQSuiteOf(ca),
		// A v3 host certificate has a v2 form when its CA does.
		OmitV2Form: v == cert.Version3 && cert.V2Form(ca) == nil,
	}

	c, err := nc.Sign(ca, ca.Curve(), key)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
	}

	return c, pem
}

// appendPQSigningKey makes a classical CA keypair into a version 3 composite one with a fresh key of the default suite.
func appendPQSigningKey(pub, priv []byte) ([]byte, []byte) {
	pqPub, pqPriv, err := cert.DefaultPQSuite.GenerateKey(true)
	if err != nil {
		panic(err)
	}
	return append(pub, pqPub...), append(priv, pqPriv...)
}

// appendPQKey makes a classical host keypair into a version 3 composite one with a fresh key of the CA's suite.
func appendPQKey(ca cert.Certificate, pub, priv []byte) ([]byte, []byte) {
	pqPub, pqPriv, err := cert.PQSuiteOf(ca).GenerateKey(false)
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

// DummyCert is a minimal cert.Certificate implementation for testing error paths.
type DummyCert struct {
	Version_        cert.Version
	Curve_          cert.Curve
	Groups_         []string
	IsCA_           bool
	Issuer_         string
	Name_           string
	Networks_       []netip.Prefix
	NotAfter_       time.Time
	NotBefore_      time.Time
	PublicKey_      []byte
	Signature_      []byte
	UnsafeNetworks_ []netip.Prefix
}

func (d *DummyCert) Version() cert.Version                         { return d.Version_ }
func (d *DummyCert) Curve() cert.Curve                             { return d.Curve_ }
func (d *DummyCert) Groups() []string                              { return d.Groups_ }
func (d *DummyCert) IsCA() bool                                    { return d.IsCA_ }
func (d *DummyCert) Issuer() string                                { return d.Issuer_ }
func (d *DummyCert) Name() string                                  { return d.Name_ }
func (d *DummyCert) Networks() []netip.Prefix                      { return d.Networks_ }
func (d *DummyCert) NotAfter() time.Time                           { return d.NotAfter_ }
func (d *DummyCert) NotBefore() time.Time                          { return d.NotBefore_ }
func (d *DummyCert) PublicKey() []byte                             { return d.PublicKey_ }
func (d *DummyCert) Signature() cert.Signatures                    { return cert.Signatures{Classical: d.Signature_} }
func (d *DummyCert) UnsafeNetworks() []netip.Prefix                { return d.UnsafeNetworks_ }
func (d *DummyCert) Fingerprint() (string, error)                  { return "", nil }
func (d *DummyCert) CheckSignature(key []byte) bool                { return false }
func (d *DummyCert) MarshalForHandshakes() ([]byte, error)         { return nil, nil }
func (d *DummyCert) MarshalPEM() ([]byte, error)                   { return nil, nil }
func (d *DummyCert) MarshalJSON() ([]byte, error)                  { return nil, nil }
func (d *DummyCert) Marshal() ([]byte, error)                      { return nil, nil }
func (d *DummyCert) String() string                                { return "dummy" }
func (d *DummyCert) Copy() cert.Certificate                        { return d }
func (d *DummyCert) VerifyPrivateKey(c cert.Curve, k []byte) error { return nil }
func (d *DummyCert) Expired(time.Time) bool                        { return false }
func (d *DummyCert) MarshalPublicKeyPEM() []byte                   { return nil }
func (d *DummyCert) PublicKeyPEM() []byte                          { return nil }

// NewTestCAPool creates a CAPool from the given CA certificates, panicking on error.
func NewTestCAPool(cas ...cert.Certificate) *cert.CAPool {
	pool := cert.NewCAPool()
	for _, ca := range cas {
		if err := pool.AddCA(ca); err != nil {
			panic(err)
		}
	}
	return pool
}

// SkipWithoutPQ skips a test that needs the default post-quantum suite when this build can not run it, as under the
// FIPS 140-3 Go Cryptographic Module v1.0.0, which has no ML-DSA.
func SkipWithoutPQ(t testing.TB) {
	t.Helper()
	if err := cert.DefaultPQSuite.Available(); err != nil {
		t.Skip(err)
	}
}

// WithCurve re-encodes a curve25519 v2 certificate PEM as one carrying curve, the way a certificate for a curve a newer
// nebula added would look. Its signature no longer verifies.
func WithCurve(certPEM []byte, curve cert.Curve) []byte {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		panic("not a PEM block")
	}

	in := cryptobyte.String(block.Bytes)
	var body, details, publicKey, signature cryptobyte.String
	if !in.ReadASN1(&body, asn1.SEQUENCE) ||
		!body.ReadASN1Element(&details, asn1.Tag(0).Constructed().ContextSpecific()) ||
		!body.ReadASN1Element(&publicKey, asn1.Tag(2).ContextSpecific()) ||
		!body.ReadASN1Element(&signature, asn1.Tag(3).ContextSpecific()) {
		panic("not a curve25519 v2 certificate")
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(details)
		b.AddASN1(asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddUint8(uint8(curve))
		})
		b.AddBytes(publicKey)
		b.AddBytes(signature)
	})
	return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: b.BytesOrPanic()})
}
