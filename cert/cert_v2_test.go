package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateV2_Marshal(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	nc := certificateV2{
		details: detailsV2{
			name: "testing",
			networks: []netip.Prefix{
				mustParsePrefixUnmapped("10.1.1.2/16"),
				mustParsePrefixUnmapped("10.1.1.1/24"),
			},
			unsafeNetworks: []netip.Prefix{
				mustParsePrefixUnmapped("9.1.1.3/16"),
				mustParsePrefixUnmapped("9.1.1.2/24"),
			},
			groups:    []string{"test-group1", "test-group2", "test-group3"},
			notBefore: before,
			notAfter:  after,
			isCA:      false,
			issuer:    "1234567890abcdef1234567890abcdef",
		},
		signature: []byte("1234567890abcdef1234567890abcdef"),
		publicKey: pubKey,
	}

	db, err := nc.details.Marshal()
	require.NoError(t, err)
	nc.rawDetails = db

	b, err := nc.Marshal()
	require.Nil(t, err)
	//t.Log("Cert size:", len(b))

	nc2, err := unmarshalCertificateV2(b, nil, Curve_CURVE25519)
	assert.Nil(t, err)

	assert.Equal(t, nc.Version(), Version2)
	assert.Equal(t, nc.Curve(), Curve_CURVE25519)
	assert.Equal(t, nc.Signature(), nc2.Signature())
	assert.Equal(t, nc.Name(), nc2.Name())
	assert.Equal(t, nc.NotBefore(), nc2.NotBefore())
	assert.Equal(t, nc.NotAfter(), nc2.NotAfter())
	assert.Equal(t, nc.PublicKey(), nc2.PublicKey())
	assert.Equal(t, nc.IsCA(), nc2.IsCA())
	assert.Equal(t, nc.Issuer(), nc2.Issuer())

	// unmarshalling will sort networks and unsafeNetworks, we need to do the same
	// but first make sure it fails
	assert.NotEqual(t, nc.Networks(), nc2.Networks())
	assert.NotEqual(t, nc.UnsafeNetworks(), nc2.UnsafeNetworks())

	slices.SortFunc(nc.details.networks, comparePrefix)
	slices.SortFunc(nc.details.unsafeNetworks, comparePrefix)

	assert.Equal(t, nc.Networks(), nc2.Networks())
	assert.Equal(t, nc.UnsafeNetworks(), nc2.UnsafeNetworks())

	assert.Equal(t, nc.Groups(), nc2.Groups())
}

func TestCertificateV2_Expired(t *testing.T) {
	nc := certificateV2{
		details: detailsV2{
			notBefore: time.Now().Add(time.Second * -60).Round(time.Second),
			notAfter:  time.Now().Add(time.Second * 60).Round(time.Second),
		},
	}

	assert.True(t, nc.Expired(time.Now().Add(time.Hour)))
	assert.True(t, nc.Expired(time.Now().Add(-time.Hour)))
	assert.False(t, nc.Expired(time.Now()))
}

func TestCertificateV2_MarshalJSON(t *testing.T) {
	time.Local = time.UTC
	pubKey := []byte("1234567890abcedf1234567890abcedf")

	nc := certificateV2{
		details: detailsV2{
			name: "testing",
			networks: []netip.Prefix{
				mustParsePrefixUnmapped("10.1.1.1/24"),
				mustParsePrefixUnmapped("10.1.1.2/16"),
			},
			unsafeNetworks: []netip.Prefix{
				mustParsePrefixUnmapped("9.1.1.2/24"),
				mustParsePrefixUnmapped("9.1.1.3/16"),
			},
			groups:    []string{"test-group1", "test-group2", "test-group3"},
			notBefore: time.Date(1, 0, 0, 1, 0, 0, 0, time.UTC),
			notAfter:  time.Date(1, 0, 0, 2, 0, 0, 0, time.UTC),
			isCA:      false,
			issuer:    "1234567890abcedf1234567890abcedf",
		},
		publicKey: pubKey,
		signature: []byte("1234567890abcedf1234567890abcedf1234567890abcedf1234567890abcedf"),
	}

	b, err := nc.MarshalJSON()
	assert.ErrorIs(t, err, ErrMissingDetails)

	rd, err := nc.details.Marshal()
	assert.NoError(t, err)

	nc.rawDetails = rd
	b, err = nc.MarshalJSON()
	assert.Nil(t, err)
	assert.Equal(
		t,
		"{\"curve\":\"CURVE25519\",\"details\":{\"groups\":[\"test-group1\",\"test-group2\",\"test-group3\"],\"isCa\":false,\"issuer\":\"1234567890abcedf1234567890abcedf\",\"name\":\"testing\",\"networks\":[\"10.1.1.1/24\",\"10.1.1.2/16\"],\"notAfter\":\"0000-11-30T02:00:00Z\",\"notBefore\":\"0000-11-30T01:00:00Z\",\"unsafeNetworks\":[\"9.1.1.2/24\",\"9.1.1.3/16\"]},\"fingerprint\":\"152d9a7400c1e001cb76cffd035215ebb351f69eeb797f7f847dd086e15e56dd\",\"publicKey\":\"3132333435363738393061626365646631323334353637383930616263656466\",\"signature\":\"31323334353637383930616263656466313233343536373839306162636564663132333435363738393061626365646631323334353637383930616263656466\",\"version\":2}",
		string(b),
	)
}

func TestCertificateV2_VerifyPrivateKey(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	err := ca.VerifyPrivateKey(Curve_CURVE25519, caKey)
	assert.Nil(t, err)

	err = ca.VerifyPrivateKey(Curve_CURVE25519, caKey[:16])
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)

	_, caKey2, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	err = ca.VerifyPrivateKey(Curve_CURVE25519, caKey2)
	assert.ErrorIs(t, err, ErrPublicPrivateKeyMismatch)

	c, _, priv, _ := NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	rawPriv, b, curve, err := UnmarshalPrivateKeyFromPEM(priv)
	assert.NoError(t, err)
	assert.Empty(t, b)
	assert.Equal(t, Curve_CURVE25519, curve)
	err = c.VerifyPrivateKey(Curve_CURVE25519, rawPriv)
	assert.Nil(t, err)

	_, priv2 := X25519Keypair()
	err = c.VerifyPrivateKey(Curve_P256, priv2)
	assert.ErrorIs(t, err, ErrPublicPrivateCurveMismatch)

	err = c.VerifyPrivateKey(Curve_CURVE25519, priv2)
	assert.ErrorIs(t, err, ErrPublicPrivateKeyMismatch)

	err = c.VerifyPrivateKey(Curve_CURVE25519, priv2[:16])
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)

	ac, ok := c.(*certificateV2)
	require.True(t, ok)
	ac.curve = Curve(99)
	err = c.VerifyPrivateKey(Curve(99), priv2)
	assert.EqualError(t, err, "invalid curve: 99")

	ca2, _, caKey2, _ := NewTestCaCert(Version2, Curve_P256, time.Time{}, time.Time{}, nil, nil, nil)
	err = ca.VerifyPrivateKey(Curve_CURVE25519, caKey)
	assert.Nil(t, err)

	err = ca2.VerifyPrivateKey(Curve_P256, caKey2[:16])
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)

	c, _, priv, _ = NewTestCert(Version2, Curve_P256, ca2, caKey2, "test", time.Time{}, time.Time{}, nil, nil, nil)
	rawPriv, b, curve, err = UnmarshalPrivateKeyFromPEM(priv)

	err = c.VerifyPrivateKey(Curve_P256, priv[:16])
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)

	err = c.VerifyPrivateKey(Curve_P256, priv)
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)

	aCa, ok := ca2.(*certificateV2)
	require.True(t, ok)
	aCa.curve = Curve(99)
	err = aCa.VerifyPrivateKey(Curve(99), priv2)
	assert.EqualError(t, err, "invalid curve: 99")

}

func TestCertificateV2_VerifyPrivateKeyP256(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_P256, time.Time{}, time.Time{}, nil, nil, nil)
	err := ca.VerifyPrivateKey(Curve_P256, caKey)
	assert.Nil(t, err)

	_, _, caKey2, _ := NewTestCaCert(Version2, Curve_P256, time.Time{}, time.Time{}, nil, nil, nil)
	assert.Nil(t, err)
	err = ca.VerifyPrivateKey(Curve_P256, caKey2)
	assert.NotNil(t, err)

	c, _, priv, _ := NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	rawPriv, b, curve, err := UnmarshalPrivateKeyFromPEM(priv)
	assert.NoError(t, err)
	assert.Empty(t, b)
	assert.Equal(t, Curve_P256, curve)
	err = c.VerifyPrivateKey(Curve_P256, rawPriv)
	assert.Nil(t, err)

	_, priv2 := P256Keypair()
	err = c.VerifyPrivateKey(Curve_P256, priv2)
	assert.NotNil(t, err)
}

func TestCertificateV2_Copy(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)
	cc := c.Copy()
	test.AssertDeepCopyEqual(t, c, cc)
}

func TestUnmarshalCertificateV2(t *testing.T) {
	data := []byte("\x98\x00\x00")
	_, err := unmarshalCertificateV2(data, nil, Curve_CURVE25519)
	assert.EqualError(t, err, "bad wire format")
}
