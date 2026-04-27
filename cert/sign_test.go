package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert/p256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateV1_Sign(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	tbs := TBSCertificate{
		Version: Version1,
		Name:    "testing",
		Networks: []netip.Prefix{
			mustParsePrefixUnmapped("10.1.1.1/24"),
			mustParsePrefixUnmapped("10.1.1.2/16"),
		},
		UnsafeNetworks: []netip.Prefix{
			mustParsePrefixUnmapped("9.1.1.2/24"),
			mustParsePrefixUnmapped("9.1.1.3/24"),
		},
		Groups:    []string{"test-group1", "test-group2", "test-group3"},
		NotBefore: before,
		NotAfter:  after,
		PublicKey: pubKey,
		IsCA:      false,
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	c, err := tbs.Sign(&certificateV1{details: detailsV1{notBefore: before, notAfter: after}}, Curve_CURVE25519, priv)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.True(t, c.CheckSignature(pub))

	b, err := c.Marshal()
	require.NoError(t, err)
	uc, err := unmarshalCertificateV1(b, nil)
	require.NoError(t, err)
	assert.NotNil(t, uc)
}

func TestCertificateV1_SignP256(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("01234567890abcedfghij1234567890ab1234567890abcedfghij1234567890ab")

	tbs := TBSCertificate{
		Version: Version1,
		Name:    "testing",
		Networks: []netip.Prefix{
			mustParsePrefixUnmapped("10.1.1.1/24"),
			mustParsePrefixUnmapped("10.1.1.2/16"),
		},
		UnsafeNetworks: []netip.Prefix{
			mustParsePrefixUnmapped("9.1.1.2/24"),
			mustParsePrefixUnmapped("9.1.1.3/16"),
		},
		Groups:    []string{"test-group1", "test-group2", "test-group3"},
		NotBefore: before,
		NotAfter:  after,
		PublicKey: pubKey,
		IsCA:      false,
		Curve:     Curve_P256,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	rawPriv := priv.D.FillBytes(make([]byte, 32))

	c, err := tbs.Sign(&certificateV1{details: detailsV1{notBefore: before, notAfter: after}}, Curve_P256, rawPriv)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.True(t, c.CheckSignature(pub))

	b, err := c.Marshal()
	require.NoError(t, err)
	uc, err := unmarshalCertificateV1(b, nil)
	require.NoError(t, err)
	assert.NotNil(t, uc)
}

func TestCertificate_SignP256_AlwaysNormalized(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("01234567890abcedfghij1234567890ab1234567890abcedfghij1234567890ab")

	tbs := TBSCertificate{
		Version: Version1,
		Name:    "testing",
		Networks: []netip.Prefix{
			mustParsePrefixUnmapped("10.1.1.1/24"),
			mustParsePrefixUnmapped("10.1.1.2/16"),
		},
		UnsafeNetworks: []netip.Prefix{
			mustParsePrefixUnmapped("9.1.1.2/24"),
			mustParsePrefixUnmapped("9.1.1.3/16"),
		},
		Groups:    []string{"test-group1", "test-group2", "test-group3"},
		NotBefore: before,
		NotAfter:  after,
		PublicKey: pubKey,
		IsCA:      true,
		Curve:     Curve_P256,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	rawPriv := priv.D.FillBytes(make([]byte, 32))

	for i := 0; i < 1000; i++ {
		if i&1 == 1 {
			tbs.Version = Version1
		} else {
			tbs.Version = Version2
		}
		c, err := tbs.Sign(nil, Curve_P256, rawPriv)
		require.NoError(t, err)
		assert.NotNil(t, c)
		assert.True(t, c.CheckSignature(pub))
		normie, err := p256.IsNormalized(c.Signature())
		require.NoError(t, err)
		assert.True(t, normie)
	}
}
