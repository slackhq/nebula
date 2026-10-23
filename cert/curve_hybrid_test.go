package cert

import (
	"crypto/x509"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skipWithoutHybrid(t *testing.T) {
	t.Helper()
	if err := HybridAvailable(); err != nil {
		t.Skip(err)
	}
}

// TestCompositeVector checks the composite signature against the id-MLDSA87-ECDSA-P384-SHA512 vector of
// draft-ietf-lamps-pq-composite-sigs-19.
func TestCompositeVector(t *testing.T) {
	skipWithoutHybrid(t)

	raw, err := os.ReadFile("testdata/composite_mldsa87_p384.json")
	require.NoError(t, err)
	var v struct{ M, Pk, Sk, S []byte }
	require.NoError(t, json.Unmarshal(raw, &v))

	// The vector's private key is the ML-DSA seed followed by an RFC 5915 ECPrivateKey, ours has the raw scalar.
	ecSK, err := x509.ParseECPrivateKey(v.Sk[MLDSA87SeedSize:])
	require.NoError(t, err)
	scalar, err := ecSK.Bytes()
	require.NoError(t, err)
	sk := append(v.Sk[:MLDSA87SeedSize:MLDSA87SeedSize], scalar...)

	pk, err := hybridSigningPublicKey(sk)
	require.NoError(t, err)
	assert.Equal(t, v.Pk, pk)

	// The vector's ECDSA signature is high-s, which the composite signature allows and we do not.
	ecSig := v.S[MLDSA87SignatureSize:]
	assert.False(t, p384LowS(ecSig))
	assert.False(t, compositeVerify(v.Pk, v.M, v.S))
	low, err := compositeNormalize(v.S)
	require.NoError(t, err)
	assert.True(t, compositeVerify(v.Pk, v.M, low))

	sign, err := compositeSigner(sk)
	require.NoError(t, err)
	sig, err := sign(v.M)
	require.NoError(t, err)
	sig, err = compositeNormalize(sig)
	require.NoError(t, err)
	assert.True(t, compositeVerify(v.Pk, v.M, sig))
	assert.False(t, compositeVerify(v.Pk, append(v.M, 0), sig))
}

func TestCompositeVerifyNeedsBoth(t *testing.T) {
	skipWithoutHybrid(t)

	pk, sk, err := GenerateHybridSigningKeypair()
	require.NoError(t, err)
	sign, err := compositeSigner(sk)
	require.NoError(t, err)
	m := []byte("message")
	sig, err := sign(m)
	require.NoError(t, err)
	sig, err = compositeNormalize(sig)
	require.NoError(t, err)
	require.True(t, compositeVerify(pk, m, sig))

	other, err := sign([]byte("other"))
	require.NoError(t, err)
	other, err = compositeNormalize(other)
	require.NoError(t, err)

	// Each half of another message's signature, spliced in, fails the whole.
	spliced := append(append([]byte{}, other[:MLDSA87SignatureSize]...), sig[MLDSA87SignatureSize:]...)
	assert.False(t, compositeVerify(pk, m, spliced))
	spliced = append(append([]byte{}, sig[:MLDSA87SignatureSize]...), other[MLDSA87SignatureSize:]...)
	assert.False(t, compositeVerify(pk, m, spliced))

	assert.False(t, compositeVerify(pk, m, sig[:MLDSA87SignatureSize]))
	assert.False(t, compositeVerify(pk, m, append(append([]byte{}, sig...), 0)))
	assert.False(t, compositeVerify(pk[:len(pk)-1], m, sig))
}

func TestHybridCertificate(t *testing.T) {
	skipWithoutHybrid(t)

	ca, _, caKey, caPEM := NewTestCaCert(Version2, Curve_P384_MLKEM1024_MLDSA87, time.Time{}, time.Time{}, nil, nil, []string{"g"})
	assert.Len(t, ca.PublicKey(), HybridSigningPublicKeySize)
	assert.True(t, ca.CheckSignature(ca.PublicKey()))
	require.NoError(t, ca.VerifyPrivateKey(Curve_P384_MLKEM1024_MLDSA87, caKey))

	c, pub, keyPEM, crtPEM := NewTestCert(Version2, Curve_P384_MLKEM1024_MLDSA87, ca, caKey, "host", time.Time{}, time.Time{}, nil, nil, []string{"g"})
	assert.Len(t, pub, HybridPublicKeySize)
	key, _, curve, err := UnmarshalPrivateKeyFromPEM(keyPEM)
	require.NoError(t, err)
	assert.Equal(t, Curve_P384_MLKEM1024_MLDSA87, curve)
	require.NoError(t, c.VerifyPrivateKey(curve, key))
	_, other, err := GenerateHybridKeypair()
	require.NoError(t, err)
	require.Error(t, c.VerifyPrivateKey(curve, other))

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

	pool.BlocklistFingerprint(mustFingerprint(t, parsed))
	_, err = pool.VerifyCertificate(time.Now(), parsed)
	require.ErrorIs(t, err, ErrBlockListed)

	// One pool holds CAs of both curves, and a CA signs only its own.
	p256CA, _, p256Key, _ := NewTestCaCert(Version2, Curve_P256, time.Time{}, time.Time{}, nil, nil, nil)
	require.NoError(t, pool.AddCA(p256CA))
	p256Host, _, _, _ := NewTestCert(Version2, Curve_P256, p256CA, p256Key, "p256", time.Time{}, time.Time{}, nil, nil, nil)
	_, err = pool.VerifyCertificate(time.Now(), p256Host)
	require.NoError(t, err)
	hostPub, _, err := GenerateHybridKeypair()
	require.NoError(t, err)
	mixed := &TBSCertificate{
		Version:   Version2,
		Curve:     Curve_P384_MLKEM1024_MLDSA87,
		Name:      "mixed",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.2/8")},
		NotBefore: p256CA.NotBefore(),
		NotAfter:  p256CA.NotAfter(),
		PublicKey: hostPub,
	}
	_, err = mixed.Sign(p256CA, Curve_P256, p256Key)
	require.Error(t, err)
}

func mustFingerprint(t *testing.T, c Certificate) string {
	t.Helper()
	fp, err := c.Fingerprint()
	require.NoError(t, err)
	return fp
}

func TestHybridCertificateRefused(t *testing.T) {
	skipWithoutHybrid(t)

	pub, priv, err := GenerateHybridSigningKeypair()
	require.NoError(t, err)
	tbs := &TBSCertificate{
		Version:   Version1,
		Curve:     Curve_P384_MLKEM1024_MLDSA87,
		Name:      "v1",
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		PublicKey: pub,
		IsCA:      true,
	}
	_, err = tbs.Sign(nil, Curve_P384_MLKEM1024_MLDSA87, priv)
	require.Error(t, err, "the hybrid curve is v2 only")

	// A CA key in a host certificate, or a host key in a CA, is refused.
	tbs.Version = Version2
	hostPub, _, err := GenerateHybridKeypair()
	require.NoError(t, err)
	tbs.PublicKey = hostPub
	_, err = tbs.Sign(nil, Curve_P384_MLKEM1024_MLDSA87, priv)
	require.ErrorIs(t, err, ErrInvalidPublicKey)

	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_P384_MLKEM1024_MLDSA87, time.Time{}, time.Time{}, nil, nil, nil)
	host := &TBSCertificate{
		Version:   Version2,
		Curve:     Curve_P384_MLKEM1024_MLDSA87,
		Name:      "host",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		NotBefore: ca.NotBefore(),
		NotAfter:  ca.NotAfter(),
		PublicKey: pub,
	}
	_, err = host.Sign(ca, Curve_P384_MLKEM1024_MLDSA87, caKey)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
}

func TestHybridKeyPEM(t *testing.T) {
	skipWithoutHybrid(t)

	pub, priv, err := GenerateHybridKeypair()
	require.NoError(t, err)
	caPub, caPriv, err := GenerateHybridSigningKeypair()
	require.NoError(t, err)

	b, _, curve, err := UnmarshalPublicKeyFromPEM(MarshalPublicKeyToPEM(Curve_P384_MLKEM1024_MLDSA87, pub))
	require.NoError(t, err)
	assert.Equal(t, Curve_P384_MLKEM1024_MLDSA87, curve)
	assert.Equal(t, pub, b)

	b, _, curve, err = UnmarshalPrivateKeyFromPEM(MarshalPrivateKeyToPEM(Curve_P384_MLKEM1024_MLDSA87, priv))
	require.NoError(t, err)
	assert.Equal(t, Curve_P384_MLKEM1024_MLDSA87, curve)
	assert.Equal(t, priv, b)

	b, _, curve, err = UnmarshalSigningPublicKeyFromPEM(MarshalSigningPublicKeyToPEM(Curve_P384_MLKEM1024_MLDSA87, caPub))
	require.NoError(t, err)
	assert.Equal(t, Curve_P384_MLKEM1024_MLDSA87, curve)
	assert.Equal(t, caPub, b)

	b, _, curve, err = UnmarshalSigningPrivateKeyFromPEM(MarshalSigningPrivateKeyToPEM(Curve_P384_MLKEM1024_MLDSA87, caPriv))
	require.NoError(t, err)
	assert.Equal(t, Curve_P384_MLKEM1024_MLDSA87, curve)
	assert.Equal(t, caPriv, b)

	// A host key is not a CA key, by banner or by size.
	_, _, _, err = UnmarshalSigningPrivateKeyFromPEM(MarshalPrivateKeyToPEM(Curve_P384_MLKEM1024_MLDSA87, priv))
	require.Error(t, err)
	_, _, _, err = UnmarshalPublicKeyFromPEM(MarshalPublicKeyToPEM(Curve_P384_MLKEM1024_MLDSA87, caPub))
	require.Error(t, err)

	kdf := NewArgon2Parameters(64*1024, 4, 3)
	enc, err := EncryptAndMarshalSigningPrivateKey(Curve_P384_MLKEM1024_MLDSA87, caPriv, []byte("pass"), kdf)
	require.NoError(t, err)
	_, _, curve, err = UnmarshalSigningPrivateKeyFromPEM(enc)
	require.ErrorIs(t, err, ErrPrivateKeyEncrypted)
	assert.Equal(t, Curve_P384_MLKEM1024_MLDSA87, curve)
	curve, b, _, err = DecryptAndUnmarshalSigningPrivateKey([]byte("pass"), enc)
	require.NoError(t, err)
	assert.Equal(t, Curve_P384_MLKEM1024_MLDSA87, curve)
	assert.Equal(t, caPriv, b)
}

func TestHybridMarshalJSON(t *testing.T) {
	skipWithoutHybrid(t)

	ca, _, _, _ := NewTestCaCert(Version2, Curve_P384_MLKEM1024_MLDSA87, time.Time{}, time.Time{}, nil, nil, nil)
	b, err := ca.MarshalJSON()
	require.NoError(t, err)
	var j struct{ Curve string }
	require.NoError(t, json.Unmarshal(b, &j))
	assert.Equal(t, CurveName(Curve_P384_MLKEM1024_MLDSA87), j.Curve)
}

// TestHybridCAPoolBundle loads a bundle of a hybrid CA and a P-256 CA: the build keeps both when it can run the hybrid
// curve, and the P-256 one alone, with an error saying why, when it can not.
func TestHybridCAPoolBundle(t *testing.T) {
	b, err := os.ReadFile("testdata/hybrid_and_p256_ca.txt")
	require.NoError(t, err)
	pool, err := NewCAPoolFromPEM(b)
	if HybridAvailable() == nil {
		require.NoError(t, err)
		assert.Len(t, pool.CAs, 2)
		return
	}
	require.ErrorIs(t, err, ErrPQUnavailable)
	require.Len(t, pool.CAs, 1)
	for _, ca := range pool.CAs {
		assert.Equal(t, Curve_P256, ca.Certificate.Curve())
	}
}
