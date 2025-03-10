package cert

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCertificateV1_Marshal(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	nc := certificateV1{
		details: detailsV1{
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
			notBefore: before,
			notAfter:  after,
			publicKey: pubKey,
			isCA:      false,
			issuer:    "1234567890abcedfghij1234567890ab",
		},
		signature: []byte("1234567890abcedfghij1234567890ab"),
	}

	b, err := nc.Marshal()
	require.NoError(t, err)
	//t.Log("Cert size:", len(b))

	nc2, err := unmarshalCertificateV1(b, nil)
	require.NoError(t, err)

	assert.Equal(t, Version1, nc.Version())
	assert.Equal(t, Curve_CURVE25519, nc.Curve())
	assert.Equal(t, nc.Signature(), nc2.Signature())
	assert.Equal(t, nc.Name(), nc2.Name())
	assert.Equal(t, nc.NotBefore(), nc2.NotBefore())
	assert.Equal(t, nc.NotAfter(), nc2.NotAfter())
	assert.Equal(t, nc.PublicKey(), nc2.PublicKey())
	assert.Equal(t, nc.IsCA(), nc2.IsCA())

	assert.Equal(t, nc.Networks(), nc2.Networks())
	assert.Equal(t, nc.UnsafeNetworks(), nc2.UnsafeNetworks())

	assert.Equal(t, nc.Groups(), nc2.Groups())
}

func TestCertificateV1_Expired(t *testing.T) {
	nc := certificateV1{
		details: detailsV1{
			notBefore: time.Now().Add(time.Second * -60).Round(time.Second),
			notAfter:  time.Now().Add(time.Second * 60).Round(time.Second),
		},
	}

	assert.True(t, nc.Expired(time.Now().Add(time.Hour)))
	assert.True(t, nc.Expired(time.Now().Add(-time.Hour)))
	assert.False(t, nc.Expired(time.Now()))
}

func TestCertificateV1_MarshalJSON(t *testing.T) {
	time.Local = time.UTC
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	nc := certificateV1{
		details: detailsV1{
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
			publicKey: pubKey,
			isCA:      false,
			issuer:    "1234567890abcedfghij1234567890ab",
		},
		signature: []byte("1234567890abcedfghij1234567890ab"),
	}

	b, err := nc.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(
		t,
		"{\"details\":{\"curve\":\"CURVE25519\",\"groups\":[\"test-group1\",\"test-group2\",\"test-group3\"],\"isCa\":false,\"issuer\":\"1234567890abcedfghij1234567890ab\",\"name\":\"testing\",\"networks\":[\"10.1.1.1/24\",\"10.1.1.2/16\"],\"notAfter\":\"0000-11-30T02:00:00Z\",\"notBefore\":\"0000-11-30T01:00:00Z\",\"publicKey\":\"313233343536373839306162636564666768696a313233343536373839306162\",\"unsafeNetworks\":[\"9.1.1.2/24\",\"9.1.1.3/16\"]},\"fingerprint\":\"3944c53d4267a229295b56cb2d27d459164c010ac97d655063ba421e0670f4ba\",\"signature\":\"313233343536373839306162636564666768696a313233343536373839306162\",\"version\":1}",
		string(b),
	)
}

func TestCertificateV1_VerifyPrivateKey(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	err := ca.VerifyPrivateKey(Curve_CURVE25519, caKey)
	require.NoError(t, err)

	_, _, caKey2, _ := NewTestCaCert(Version1, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	require.NoError(t, err)
	err = ca.VerifyPrivateKey(Curve_CURVE25519, caKey2)
	require.Error(t, err)

	c, _, priv, _ := NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	rawPriv, b, curve, err := UnmarshalPrivateKeyFromPEM(priv)
	require.NoError(t, err)
	assert.Empty(t, b)
	assert.Equal(t, Curve_CURVE25519, curve)
	err = c.VerifyPrivateKey(Curve_CURVE25519, rawPriv)
	require.NoError(t, err)

	_, priv2 := X25519Keypair()
	err = c.VerifyPrivateKey(Curve_CURVE25519, priv2)
	require.Error(t, err)
}

func TestCertificateV1_VerifyPrivateKeyP256(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_P256, time.Time{}, time.Time{}, nil, nil, nil)
	err := ca.VerifyPrivateKey(Curve_P256, caKey)
	require.NoError(t, err)

	_, _, caKey2, _ := NewTestCaCert(Version1, Curve_P256, time.Time{}, time.Time{}, nil, nil, nil)
	require.NoError(t, err)
	err = ca.VerifyPrivateKey(Curve_P256, caKey2)
	require.Error(t, err)

	c, _, priv, _ := NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	rawPriv, b, curve, err := UnmarshalPrivateKeyFromPEM(priv)
	require.NoError(t, err)
	assert.Empty(t, b)
	assert.Equal(t, Curve_P256, curve)
	err = c.VerifyPrivateKey(Curve_P256, rawPriv)
	require.NoError(t, err)

	_, priv2 := P256Keypair()
	err = c.VerifyPrivateKey(Curve_P256, priv2)
	require.Error(t, err)
}

// Ensure that upgrading the protobuf library does not change how certificates
// are marshalled, since this would break signature verification
func TestMarshalingCertificateV1Consistency(t *testing.T) {
	before := time.Date(1970, time.January, 1, 1, 1, 1, 1, time.UTC)
	after := time.Date(9999, time.January, 1, 1, 1, 1, 1, time.UTC)
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	nc := certificateV1{
		details: detailsV1{
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
			publicKey: pubKey,
			isCA:      false,
			issuer:    "1234567890abcedfghij1234567890ab",
		},
		signature: []byte("1234567890abcedfghij1234567890ab"),
	}

	b, err := nc.Marshal()
	require.NoError(t, err)
	assert.Equal(t, "0a8e010a0774657374696e671212828284508080fcff0f8182845080feffff0f1a12838284488080fcff0f8282844880feffff0f220b746573742d67726f757031220b746573742d67726f757032220b746573742d67726f75703328cd1c30cdb8ccf0af073a20313233343536373839306162636564666768696a3132333435363738393061624a081234567890abcedf1220313233343536373839306162636564666768696a313233343536373839306162", fmt.Sprintf("%x", b))

	b, err = proto.Marshal(nc.getRawDetails())
	require.NoError(t, err)
	assert.Equal(t, "0a0774657374696e671212828284508080fcff0f8182845080feffff0f1a12838284488080fcff0f8282844880feffff0f220b746573742d67726f757031220b746573742d67726f757032220b746573742d67726f75703328cd1c30cdb8ccf0af073a20313233343536373839306162636564666768696a3132333435363738393061624a081234567890abcedf", fmt.Sprintf("%x", b))
}

func TestCertificateV1_Copy(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)
	cc := c.Copy()
	test.AssertDeepCopyEqual(t, c, cc)
}

func TestUnmarshalCertificateV1(t *testing.T) {
	// Test that we don't panic with an invalid certificate (#332)
	data := []byte("\x98\x00\x00")
	_, err := unmarshalCertificateV1(data, nil)
	require.EqualError(t, err, "encoded Details was nil")
}

func appendByteSlices(b ...[]byte) []byte {
	retSlice := []byte{}
	for _, v := range b {
		retSlice = append(retSlice, v...)
	}
	return retSlice
}

func mustParsePrefixUnmapped(s string) netip.Prefix {
	prefix := netip.MustParsePrefix(s)
	return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits())
}
