package cert

import (
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
	pubKey := []byte("1234567890abcedfghij1234567890ab")

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
			issuer:    "1234567890abcedfghij1234567890ab",
		},
		publicKey: pubKey,
		signature: []byte("1234567890abcedfghij1234567890ab"),
	}

	b, err := nc.MarshalJSON()
	assert.Nil(t, err)
	assert.Equal(
		t,
		"{\"curve\":\"CURVE25519\",\"details\":{\"groups\":[\"test-group1\",\"test-group2\",\"test-group3\"],\"isCa\":false,\"issuer\":\"1234567890abcedfghij1234567890ab\",\"name\":\"testing\",\"networks\":[\"10.1.1.1/24\",\"10.1.1.2/16\"],\"notAfter\":\"0000-11-30T02:00:00Z\",\"notBefore\":\"0000-11-30T01:00:00Z\",\"unsafeNetworks\":[\"9.1.1.2/24\",\"9.1.1.3/16\"]},\"fingerprint\":\"a9e2984aad14d49821f86993e1c3ec9f1d51251baa7636fbca96aebb72439ade\",\"publicKey\":\"313233343536373839306162636564666768696a313233343536373839306162\",\"signature\":\"313233343536373839306162636564666768696a313233343536373839306162\",\"version\":2}",
		string(b),
	)
}

func TestCertificateV2_VerifyPrivateKey(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	err := ca.VerifyPrivateKey(Curve_CURVE25519, caKey)
	assert.Nil(t, err)

	_, _, caKey2, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	assert.Nil(t, err)
	err = ca.VerifyPrivateKey(Curve_CURVE25519, caKey2)
	assert.NotNil(t, err)

	c, _, priv, _ := NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	rawPriv, b, curve, err := UnmarshalPrivateKeyFromPEM(priv)
	assert.NoError(t, err)
	assert.Empty(t, b)
	assert.Equal(t, Curve_CURVE25519, curve)
	err = c.VerifyPrivateKey(Curve_CURVE25519, rawPriv)
	assert.Nil(t, err)

	_, priv2 := X25519Keypair()
	err = c.VerifyPrivateKey(Curve_CURVE25519, priv2)
	assert.NotNil(t, err)
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
