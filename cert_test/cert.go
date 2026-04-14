package cert_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

// NewTestCaCert will create a new ca certificate
func NewTestCaCert(version cert.Version, curve cert.Curve, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (cert.Certificate, []byte, []byte, []byte) {
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

	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
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
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}

	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
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
	}

	c, err := nc.Sign(ca, ca.Curve(), key)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
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
func (d *DummyCert) Signature() []byte                             { return d.Signature_ }
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
