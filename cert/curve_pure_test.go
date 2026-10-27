package cert

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPureCertificate(t *testing.T) {
	skipWithoutHybrid(t)

	ca, _, caKey, caPEM := NewTestCaCert(Version2, Curve_MLKEM1024_MLDSA87, time.Time{}, time.Time{}, nil, nil, []string{"g"})
	assert.Len(t, ca.PublicKey(), PureSigningPublicKeySize)
	assert.Len(t, ca.Signature(), MLDSA87SignatureSize)
	assert.True(t, ca.CheckSignature(ca.PublicKey()))
	require.NoError(t, ca.VerifyPrivateKey(Curve_MLKEM1024_MLDSA87, caKey))

	c, pub, keyPEM, crtPEM := NewTestCert(Version2, Curve_MLKEM1024_MLDSA87, ca, caKey, "host", time.Time{}, time.Time{}, nil, nil, []string{"g"})
	assert.Len(t, pub, PurePublicKeySize)
	key, _, curve, err := UnmarshalPrivateKeyFromPEM(keyPEM)
	require.NoError(t, err)
	assert.Equal(t, Curve_MLKEM1024_MLDSA87, curve)
	require.NoError(t, c.VerifyPrivateKey(curve, key))
	_, other, err := GeneratePureKeypair()
	require.NoError(t, err)
	require.ErrorIs(t, c.VerifyPrivateKey(curve, other), ErrPublicPrivateKeyMismatch)

	fp, err := ca.Fingerprint()
	require.NoError(t, err)
	assert.Len(t, fp, 128, "SHA-512")
	assert.Equal(t, fp, c.Issuer())

	pool, err := NewCAPoolFromPEM(caPEM)
	require.NoError(t, err)
	parsed, _, err := UnmarshalCertificateFromPEM(crtPEM)
	require.NoError(t, err)
	_, err = pool.VerifyCertificate(time.Now(), parsed)
	require.NoError(t, err)

	// A signature without the context, or over anything else, does not verify.
	b, err := c.(*certificateV2).marshalForSigning()
	require.NoError(t, err)
	assert.True(t, pureVerify(ca.PublicKey(), b, c.Signature()))
	assert.False(t, pureVerify(ca.PublicKey(), append(b, 0), c.Signature()))

	// The hybrid and pure curves never sign for each other.
	hybridCA, _, hybridKey, _ := NewTestCaCert(Version2, Curve_P384_MLKEM1024_MLDSA87, time.Time{}, time.Time{}, nil, nil, nil)
	require.NoError(t, pool.AddCA(hybridCA))
	mixed := &TBSCertificate{
		Version: Version2, Curve: Curve_MLKEM1024_MLDSA87, Name: "mixed", PublicKey: pub,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.2/8")},
		NotBefore: hybridCA.NotBefore(), NotAfter: hybridCA.NotAfter(),
	}
	_, err = mixed.Sign(hybridCA, Curve_P384_MLKEM1024_MLDSA87, hybridKey)
	require.Error(t, err)

	j, err := ca.MarshalJSON()
	require.NoError(t, err)
	var v struct{ Curve string }
	require.NoError(t, json.Unmarshal(j, &v))
	assert.Equal(t, "MLKEM1024_MLDSA87", v.Curve)
}

func TestPureCertificateRefused(t *testing.T) {
	skipWithoutHybrid(t)

	pub, priv, err := GeneratePureSigningKeypair()
	require.NoError(t, err)
	tbs := &TBSCertificate{
		Version: Version1, Curve: Curve_MLKEM1024_MLDSA87, Name: "v1",
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), PublicKey: pub, IsCA: true,
	}
	_, err = tbs.Sign(nil, Curve_MLKEM1024_MLDSA87, priv)
	require.Error(t, err, "the post-quantum curve is v2 only")

	// A host key in a CA is refused.
	tbs.Version = Version2
	hostPub, _, err := GeneratePureKeypair()
	require.NoError(t, err)
	tbs.PublicKey = hostPub
	_, err = tbs.Sign(nil, Curve_MLKEM1024_MLDSA87, priv)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
}

func TestPureKeyPEM(t *testing.T) {
	skipWithoutHybrid(t)

	pub, priv, err := GeneratePureKeypair()
	require.NoError(t, err)
	caPub, caPriv, err := GeneratePureSigningKeypair()
	require.NoError(t, err)

	for _, tc := range []struct {
		pem    []byte
		read   func([]byte) ([]byte, []byte, Curve, error)
		expect []byte
	}{
		{MarshalPublicKeyToPEM(Curve_MLKEM1024_MLDSA87, pub), UnmarshalPublicKeyFromPEM, pub},
		{MarshalPrivateKeyToPEM(Curve_MLKEM1024_MLDSA87, priv), UnmarshalPrivateKeyFromPEM, priv},
		{MarshalSigningPublicKeyToPEM(Curve_MLKEM1024_MLDSA87, caPub), UnmarshalSigningPublicKeyFromPEM, caPub},
		{MarshalSigningPrivateKeyToPEM(Curve_MLKEM1024_MLDSA87, caPriv), UnmarshalSigningPrivateKeyFromPEM, caPriv},
	} {
		b, _, curve, err := tc.read(tc.pem)
		require.NoError(t, err)
		assert.Equal(t, Curve_MLKEM1024_MLDSA87, curve)
		assert.Equal(t, tc.expect, b)
	}

	// Hybrid and pure keys never pass for each other.
	_, _, curve, err := UnmarshalPrivateKeyFromPEM(MarshalPrivateKeyToPEM(Curve_P384_MLKEM1024_MLDSA87, make([]byte, HybridPrivateKeySize)))
	require.NoError(t, err)
	assert.Equal(t, Curve_P384_MLKEM1024_MLDSA87, curve)

	kdf := NewArgon2Parameters(64*1024, 4, 3)
	enc, err := EncryptAndMarshalSigningPrivateKey(Curve_MLKEM1024_MLDSA87, caPriv, []byte("pass"), kdf)
	require.NoError(t, err)
	_, _, curve, err = UnmarshalSigningPrivateKeyFromPEM(enc)
	require.ErrorIs(t, err, ErrPrivateKeyEncrypted)
	assert.Equal(t, Curve_MLKEM1024_MLDSA87, curve)
	curve, b, _, err := DecryptAndUnmarshalSigningPrivateKey([]byte("pass"), enc)
	require.NoError(t, err)
	assert.Equal(t, Curve_MLKEM1024_MLDSA87, curve)
	assert.Equal(t, caPriv, b)
}
