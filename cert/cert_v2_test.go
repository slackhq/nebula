package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateV2_Marshal(t *testing.T) {
	t.Parallel()
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
	require.NoError(t, err)
	//t.Log("Cert size:", len(b))

	nc2, err := unmarshalCertificateV2(b, nil, Curve_CURVE25519)
	require.NoError(t, err)

	assert.Equal(t, Version2, nc.Version())
	assert.Equal(t, Curve_CURVE25519, nc.Curve())
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

func TestCertificateV2_Unmarshal(t *testing.T) {
	t.Parallel()
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

	certWithPubkey, err := nc.Marshal()
	require.NoError(t, err)
	//t.Log("Cert size:", len(b))
	certWithoutPubkey, err := nc.MarshalForHandshakes()
	require.NoError(t, err)

	// Cert must not have a pubkey if one is passed in as an argument
	_, err = unmarshalCertificateV2(certWithPubkey, pubKey, Curve_CURVE25519)
	require.ErrorIs(t, err, ErrCertPubkeyPresent)

	// Certs must have pubkeys
	_, err = unmarshalCertificateV2(certWithoutPubkey, nil, Curve_CURVE25519)
	require.ErrorIs(t, err, ErrBadFormat)

	// Ensure proper unmarshal if a pubkey is passed in
	nc2, err := unmarshalCertificateV2(certWithoutPubkey, pubKey, Curve_CURVE25519)
	require.NoError(t, err)

	assert.Equal(t, nc.PublicKey(), nc2.PublicKey())
}

func TestCertificateV2_PublicKeyPem(t *testing.T) {
	t.Parallel()
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := ed25519.PublicKey("1234567890abcedfghij1234567890ab")

	nc := certificateV2{
		details: detailsV2{
			name:           "testing",
			networks:       []netip.Prefix{},
			unsafeNetworks: []netip.Prefix{},
			groups:         []string{"test-group1", "test-group2", "test-group3"},
			notBefore:      before,
			notAfter:       after,
			isCA:           false,
			issuer:         "1234567890abcedfghij1234567890ab",
		},
		publicKey: pubKey,
		signature: []byte("1234567890abcedfghij1234567890ab"),
	}

	assert.Equal(t, Version2, nc.Version())
	assert.Equal(t, Curve_CURVE25519, nc.Curve())
	pubPem := "-----BEGIN NEBULA X25519 PUBLIC KEY-----\nMTIzNDU2Nzg5MGFiY2VkZmdoaWoxMjM0NTY3ODkwYWI=\n-----END NEBULA X25519 PUBLIC KEY-----\n"
	assert.Equal(t, string(nc.MarshalPublicKeyPEM()), pubPem)
	assert.False(t, nc.IsCA())

	nc.details.isCA = true
	assert.Equal(t, Curve_CURVE25519, nc.Curve())
	pubPem = "-----BEGIN NEBULA ED25519 PUBLIC KEY-----\nMTIzNDU2Nzg5MGFiY2VkZmdoaWoxMjM0NTY3ODkwYWI=\n-----END NEBULA ED25519 PUBLIC KEY-----\n"
	assert.Equal(t, string(nc.MarshalPublicKeyPEM()), pubPem)
	assert.True(t, nc.IsCA())

	pubP256KeyPem := []byte(`-----BEGIN NEBULA P256 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA P256 PUBLIC KEY-----
`)

	pubP256KeyPemCA := []byte(`-----BEGIN NEBULA ECDSA P256 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA ECDSA P256 PUBLIC KEY-----
`)

	pubP256Key, _, _, err := UnmarshalPublicKeyFromPEM(pubP256KeyPem)
	require.NoError(t, err)
	nc.curve = Curve_P256
	nc.publicKey = pubP256Key
	assert.Equal(t, Curve_P256, nc.Curve())
	assert.Equal(t, string(nc.MarshalPublicKeyPEM()), string(pubP256KeyPemCA))
	assert.True(t, nc.IsCA())

	nc.details.isCA = false
	assert.Equal(t, Curve_P256, nc.Curve())
	assert.Equal(t, string(nc.MarshalPublicKeyPEM()), string(pubP256KeyPem))
	assert.False(t, nc.IsCA())
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
	require.ErrorIs(t, err, ErrMissingDetails)

	rd, err := nc.details.Marshal()
	require.NoError(t, err)

	nc.rawDetails = rd
	b, err = nc.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(
		t,
		"{\"curve\":\"CURVE25519\",\"details\":{\"groups\":[\"test-group1\",\"test-group2\",\"test-group3\"],\"isCa\":false,\"issuer\":\"1234567890abcedf1234567890abcedf\",\"name\":\"testing\",\"networks\":[\"10.1.1.1/24\",\"10.1.1.2/16\"],\"notAfter\":\"0000-11-30T02:00:00Z\",\"notBefore\":\"0000-11-30T01:00:00Z\",\"unsafeNetworks\":[\"9.1.1.2/24\",\"9.1.1.3/16\"]},\"fingerprint\":\"152d9a7400c1e001cb76cffd035215ebb351f69eeb797f7f847dd086e15e56dd\",\"publicKey\":\"3132333435363738393061626365646631323334353637383930616263656466\",\"signature\":\"31323334353637383930616263656466313233343536373839306162636564663132333435363738393061626365646631323334353637383930616263656466\",\"version\":2}",
		string(b),
	)
}

func TestCertificateV2_VerifyPrivateKey(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	err := ca.VerifyPrivateKey(Curve_CURVE25519, caKey)
	require.NoError(t, err)

	err = ca.VerifyPrivateKey(Curve_CURVE25519, caKey[:16])
	require.ErrorIs(t, err, ErrInvalidPrivateKey)

	_, caKey2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	err = ca.VerifyPrivateKey(Curve_CURVE25519, caKey2)
	require.ErrorIs(t, err, ErrPublicPrivateKeyMismatch)

	c, _, priv, _ := NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	rawPriv, b, curve, err := UnmarshalPrivateKeyFromPEM(priv)
	require.NoError(t, err)
	assert.Empty(t, b)
	assert.Equal(t, Curve_CURVE25519, curve)
	err = c.VerifyPrivateKey(Curve_CURVE25519, rawPriv)
	require.NoError(t, err)

	_, priv2 := X25519Keypair()
	err = c.VerifyPrivateKey(Curve_P256, priv2)
	require.ErrorIs(t, err, ErrPublicPrivateCurveMismatch)

	err = c.VerifyPrivateKey(Curve_CURVE25519, priv2)
	require.ErrorIs(t, err, ErrPublicPrivateKeyMismatch)

	err = c.VerifyPrivateKey(Curve_CURVE25519, priv2[:16])
	require.ErrorIs(t, err, ErrInvalidPrivateKey)

	ac, ok := c.(*certificateV2)
	require.True(t, ok)
	ac.curve = Curve(99)
	err = c.VerifyPrivateKey(Curve(99), priv2)
	require.EqualError(t, err, "invalid curve: 99")

	ca2, _, caKey2, _ := NewTestCaCert(Version2, Curve_P256, time.Time{}, time.Time{}, nil, nil, nil)
	err = ca.VerifyPrivateKey(Curve_CURVE25519, caKey)
	require.NoError(t, err)

	err = ca2.VerifyPrivateKey(Curve_P256, caKey2[:16])
	require.ErrorIs(t, err, ErrInvalidPrivateKey)

	c, _, priv, _ = NewTestCert(Version2, Curve_P256, ca2, caKey2, "test", time.Time{}, time.Time{}, nil, nil, nil)
	rawPriv, b, curve, err = UnmarshalPrivateKeyFromPEM(priv)

	err = c.VerifyPrivateKey(Curve_P256, priv[:16])
	require.ErrorIs(t, err, ErrInvalidPrivateKey)

	err = c.VerifyPrivateKey(Curve_P256, priv)
	require.ErrorIs(t, err, ErrInvalidPrivateKey)

	aCa, ok := ca2.(*certificateV2)
	require.True(t, ok)
	aCa.curve = Curve(99)
	err = aCa.VerifyPrivateKey(Curve(99), priv2)
	require.EqualError(t, err, "invalid curve: 99")

}

func TestCertificateV2_VerifyPrivateKeyP256(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_P256, time.Time{}, time.Time{}, nil, nil, nil)
	err := ca.VerifyPrivateKey(Curve_P256, caKey)
	require.NoError(t, err)

	_, _, caKey2, _ := NewTestCaCert(Version2, Curve_P256, time.Time{}, time.Time{}, nil, nil, nil)
	require.NoError(t, err)
	err = ca.VerifyPrivateKey(Curve_P256, caKey2)
	require.Error(t, err)

	c, _, priv, _ := NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
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

func TestCertificateV2_Copy(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)
	cc := c.Copy()
	test.AssertDeepCopyEqual(t, c, cc)
}

func TestUnmarshalCertificateV2(t *testing.T) {
	data := []byte("\x98\x00\x00")
	_, err := unmarshalCertificateV2(data, nil, Curve_CURVE25519)
	require.EqualError(t, err, "bad wire format")
}

func TestCertificateV2_marshalForSigningStability(t *testing.T) {
	before := time.Date(1996, time.May, 5, 0, 0, 0, 0, time.UTC)
	after := before.Add(time.Second * 60).Round(time.Second)
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

	const expectedRawDetailsStr = "a070800774657374696e67a10e04050a0101021004050a01010118a20e0405090101031004050901010218a3270c0b746573742d67726f7570310c0b746573742d67726f7570320c0b746573742d67726f7570338504318bef808604318befbc87101234567890abcdef1234567890abcdef"
	expectedRawDetails, err := hex.DecodeString(expectedRawDetailsStr)
	require.NoError(t, err)

	db, err := nc.details.Marshal()
	require.NoError(t, err)
	assert.Equal(t, expectedRawDetails, db)

	expectedForSigning, err := hex.DecodeString(expectedRawDetailsStr + "00313233343536373839306162636564666768696a313233343536373839306162")
	b, err := nc.marshalForSigning()
	require.NoError(t, err)
	assert.Equal(t, expectedForSigning, b)
}

// TestCertificateV2_marshalForSigningStability_WithPqPskBinding pins the
// exact DER bytes of the signed TBS region when the optional tag-8
// PQ-PSK binding is present, mirroring
// TestCertificateV2_marshalForSigningStability. The hard-coded hex is
// both a regression guard (any accidental change to the tag-8 encoding
// or field ordering breaks CA signatures fleet-wide) and on-wire
// documentation of the canonical encoding.
func TestCertificateV2_marshalForSigningStability_WithPqPskBinding(t *testing.T) {
	before := time.Date(1996, time.May, 5, 0, 0, 0, 0, time.UTC)
	after := before.Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("1234567890abcedfghij1234567890ab")
	binding := make([]byte, PqPskBindingLen)
	for i := range binding {
		binding[i] = byte(i)
	}

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
			groups:       []string{"test-group1", "test-group2", "test-group3"},
			notBefore:    before,
			notAfter:     after,
			isCA:         false,
			issuer:       "1234567890abcdef1234567890abcdef",
			pqPskBinding: binding,
		},
		signature: []byte("1234567890abcdef1234567890abcdef"),
		publicKey: pubKey,
	}

	// Identical to the no-binding fixture's DER except: the outer
	// EXPLICIT [0] length grows past 0x7f (long-form "8192"), and the
	// binding is appended after issuer as tag [8] primitive, length
	// 0x20, value 00..1f.
	const expectedRawDetailsStr = "a08192800774657374696e67a10e04050a0101021004050a01010118a20e0405090101031004050901010218a3270c0b746573742d67726f7570310c0b746573742d67726f7570320c0b746573742d67726f7570338504318bef808604318befbc87101234567890abcdef1234567890abcdef8820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	expectedRawDetails, err := hex.DecodeString(expectedRawDetailsStr)
	require.NoError(t, err)

	db, err := nc.details.Marshal()
	require.NoError(t, err)
	assert.Equal(t, expectedRawDetails, db)

	expectedForSigning, err := hex.DecodeString(expectedRawDetailsStr + "00313233343536373839306162636564666768696a313233343536373839306162")
	require.NoError(t, err)
	b, err := nc.marshalForSigning()
	require.NoError(t, err)
	assert.Equal(t, expectedForSigning, b)
}

// TestCertificateV2_PqPskBinding_RoundTrip verifies the new optional
// details extension survives marshal -> unmarshal unchanged. Also
// asserts the PqPskBinding() accessor exposes the value for downstream
// consumers.
func TestCertificateV2_PqPskBinding_RoundTrip(t *testing.T) {
	t.Parallel()
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("1234567890abcedfghij1234567890ab")
	binding := make([]byte, PqPskBindingLen)
	for i := range binding {
		binding[i] = byte(i)
	}

	nc := certificateV2{
		details: detailsV2{
			name: "testing",
			networks: []netip.Prefix{
				mustParsePrefixUnmapped("10.1.1.1/24"),
			},
			notBefore:    before,
			notAfter:     after,
			isCA:         false,
			issuer:       "1234567890abcdef1234567890abcdef",
			pqPskBinding: binding,
		},
		signature: []byte("1234567890abcdef1234567890abcdef"),
		publicKey: pubKey,
	}

	db, err := nc.details.Marshal()
	require.NoError(t, err)
	nc.rawDetails = db

	b, err := nc.Marshal()
	require.NoError(t, err)

	nc2, err := unmarshalCertificateV2(b, nil, Curve_CURVE25519)
	require.NoError(t, err)

	assert.Equal(t, binding, nc2.PqPskBinding())
}

// TestCertificateV2_MarshalJSON_LegacyBindingKey guards the backwards-compatible
// JSON contract: `nebula-cert print -json` must keep emitting the historical
// rosenpassPubKeySha256 key (consumed by existing parsers) alongside the new
// canonical pqPskBinding key, both carrying the same hex value.
func TestCertificateV2_MarshalJSON_LegacyBindingKey(t *testing.T) {
	t.Parallel()
	binding := make([]byte, PqPskBindingLen)
	for i := range binding {
		binding[i] = byte(i)
	}
	wantHex := hex.EncodeToString(binding)

	nc := certificateV2{
		details: detailsV2{
			name:         "testing",
			networks:     []netip.Prefix{mustParsePrefixUnmapped("10.1.1.1/24")},
			notBefore:    time.Date(1, 0, 0, 1, 0, 0, 0, time.UTC),
			notAfter:     time.Date(1, 0, 0, 2, 0, 0, 0, time.UTC),
			issuer:       "1234567890abcedf1234567890abcedf",
			pqPskBinding: binding,
		},
		publicKey: []byte("1234567890abcedf1234567890abcedf"),
		signature: []byte("1234567890abcedf1234567890abcedf"),
	}

	rd, err := nc.details.Marshal()
	require.NoError(t, err)
	nc.rawDetails = rd

	b, err := nc.MarshalJSON()
	require.NoError(t, err)

	var parsed struct {
		Details struct {
			PqPskBinding          string `json:"pqPskBinding"`
			RosenpassPubKeySha256 string `json:"rosenpassPubKeySha256"`
		} `json:"details"`
	}
	require.NoError(t, json.Unmarshal(b, &parsed))

	assert.Equal(t, wantHex, parsed.Details.RosenpassPubKeySha256, "legacy rosenpassPubKeySha256 key must remain present")
	assert.Equal(t, wantHex, parsed.Details.PqPskBinding, "canonical pqPskBinding key must be present")
}

// TestCertificateV2_PqPskBinding_AbsentBackwardsCompat verifies the
// unmarshal path tolerates a cert lacking the optional extension —
// i.e. existing certs signed before the field was added still parse and
// expose a nil PqPskBinding(). This is the migration-safety contract:
// TOFU fallback must remain reachable for legacy certs.
func TestCertificateV2_PqPskBinding_AbsentBackwardsCompat(t *testing.T) {
	t.Parallel()
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	nc := certificateV2{
		details: detailsV2{
			name: "testing-no-rp",
			networks: []netip.Prefix{
				mustParsePrefixUnmapped("10.1.1.1/24"),
			},
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
	require.NoError(t, err)

	nc2, err := unmarshalCertificateV2(b, nil, Curve_CURVE25519)
	require.NoError(t, err)
	assert.Nil(t, nc2.PqPskBinding(), "absent extension must round-trip to nil")
}

// TestCertificateV2_PqPskBinding_InvalidLengthRejected pins down the
// validate() check: a non-empty binding whose length is anything other
// than 32 bytes must be rejected at sign time. This guards against
// operator typos (e.g. half-hex paste) — better to fail loudly at cert
// issuance than to ship a cert that downstream parsers refuse.
func TestCertificateV2_PqPskBinding_InvalidLengthRejected(t *testing.T) {
	t.Parallel()
	c := &certificateV2{
		details: detailsV2{
			name: "bad",
			networks: []netip.Prefix{
				mustParsePrefixUnmapped("10.1.1.1/24"),
			},
			notBefore:    time.Now(),
			notAfter:     time.Now().Add(time.Hour),
			pqPskBinding: []byte("too-short"),
		},
		publicKey: []byte("1234567890abcedfghij1234567890ab"),
	}
	err := c.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pqPskBinding")
}

func TestPqPskBindingTagUnchanged(t *testing.T) {
	// Wire-compat guard: the cert v2 extension tag MUST stay 8 forever.
	if TagDetailsPqPskBinding != (8 | classContextSpecific) {
		t.Fatalf("PqPskBinding tag changed: got %d, want %d (breaks existing certs)",
			TagDetailsPqPskBinding, 8|classContextSpecific)
	}
}

func TestPqPskBindingRoundTrip(t *testing.T) {
	bind := make([]byte, 32)
	for i := range bind {
		bind[i] = byte(i)
	}
	c := &certificateV2{details: detailsV2{pqPskBinding: bind}}
	if got := c.PqPskBinding(); !bytes.Equal(got, bind) {
		t.Fatalf("PqPskBinding() round-trip mismatch")
	}
}
