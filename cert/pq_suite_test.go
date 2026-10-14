package cert

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPQSuite stands in for a second suite. It reuses ML-KEM-1024 and ML-DSA-87 under other names, so it is
// interchangeable with the default suite in everything but its identity, which is what has to keep them apart.
const testPQSuite PQSuite = 200

func registerTestPQSuite(t *testing.T) {
	t.Helper()
	kem, dsa := mlkem1024, mldsa87
	kem.name, dsa.name = "TESTKEM", "TESTDSA"
	registerPQSuite(testPQSuite, &pqSuite{kem: kem, dsa: dsa})
	t.Cleanup(func() {
		delete(pqSuites, testPQSuite)
		for k := range pqKeyBanners {
			if strings.Contains(k, "TESTKEM") || strings.Contains(k, "TESTDSA") {
				delete(pqKeyBanners, k)
			}
		}
	})
}

// newTestV3InSuite issues a v3 CA and host certificate in suite.
func newTestV3InSuite(t *testing.T, curve Curve, suite PQSuite) (ca Certificate, caKey []byte, host Certificate, hostKey []byte) {
	t.Helper()
	ca2, _, caKey2, _ := NewTestCaCert(Version2, curve, time.Time{}, time.Time{}, nil, nil, nil)
	pqPub, pqPriv, err := suite.GenerateKey(true)
	require.NoError(t, err)
	signPQ, err := SignPQ(suite, pqPriv)
	require.NoError(t, err)
	ca, err = ExtendToV3(ca2, suite, pqPub, nil, signPQ)
	require.NoError(t, err)
	caKey = append(caKey2, pqPriv...)

	var pub, priv []byte
	if curve == Curve_P256 {
		pub, priv = P256Keypair()
	} else {
		pub, priv = X25519Keypair()
	}
	hostPQPub, hostPQPriv, err := suite.GenerateKey(false)
	require.NoError(t, err)
	tbs := &TBSCertificate{
		Version:   Version3,
		Curve:     curve,
		PQSuite:   suite,
		Name:      "host",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")},
		NotBefore: ca.NotBefore(),
		NotAfter:  ca.NotAfter(),
		PublicKey: append(pub, hostPQPub...),
	}
	host, err = tbs.Sign(ca, curve, caKey)
	require.NoError(t, err)
	return ca, caKey, host, append(priv, hostPQPriv...)
}

func TestPQSuite_Names(t *testing.T) {
	assert.Equal(t, "MLKEM1024_MLDSA87", PQSuite_MLKEM1024_MLDSA87.String())
	assert.Equal(t, []PQSuite{PQSuite_MLKEM1024_MLDSA87}, PQSuites())
	assert.False(t, PQSuiteUnknown.Valid())

	s, err := ParsePQSuite("mlkem1024_mldsa87")
	require.NoError(t, err)
	assert.Equal(t, PQSuite_MLKEM1024_MLDSA87, s)
	_, err = ParsePQSuite("mlkem768_mldsa65")
	require.ErrorIs(t, err, ErrUnknownPQSuite)

	_, _, host, _ := newTestV3(t, Curve_CURVE25519)
	assert.Equal(t, DefaultPQSuite, PQSuiteOf(host))
	assert.Equal(t, PQSuiteUnknown, PQSuiteOf(V2Form(host)))
}

// A second suite works end to end, and is never confused with the first, even with keys of the same sizes.
func TestPQSuite_Second(t *testing.T) {
	registerTestPQSuite(t)

	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, host, hostKey := newTestV3InSuite(t, curve, testPQSuite)
			assert.Equal(t, testPQSuite, PQSuiteOf(ca))
			assert.Equal(t, testPQSuite, PQSuiteOf(host))
			require.NoError(t, ca.VerifyPrivateKey(curve, caKey))
			require.NoError(t, host.VerifyPrivateKey(curve, hostKey))

			pool := NewCAPool()
			require.NoError(t, pool.AddCA(ca))
			_, err := pool.VerifyCertificate(time.Now(), host)
			require.NoError(t, err)

			// The suite travels in the certificate, handshakes included.
			hs, err := host.MarshalForHandshakes()
			require.NoError(t, err)
			c, err := Recombine(Version3, hs, host.PublicKey(), curve)
			require.NoError(t, err)
			assert.Equal(t, testPQSuite, PQSuiteOf(c))
			assertCertsEqual(t, host, c)

			// Keys get their algorithms' banners.
			b := MarshalPQPrivateKeyToPEM(curve, testPQSuite, hostKey)
			assert.Contains(t, string(b), " TESTKEM PRIVATE KEY-----")
			key, _, _, err := UnmarshalPrivateKeyFromPEM(b)
			require.NoError(t, err)
			assert.Equal(t, hostKey, key)
			assert.Contains(t, string(host.MarshalPublicKeyPEM()), " TESTKEM PUBLIC KEY-----")
			assert.Contains(t, string(ca.MarshalPublicKeyPEM()), " TESTDSA PUBLIC KEY-----")

			// The suite is signed: relabelling a certificate breaks it, though the keys fit either suite.
			_, _, other, _ := newTestV3(t, curve)
			relabelled := other.Copy().(*certificateV3)
			relabelled.pqSuite = testPQSuite
			assert.False(t, relabelled.CheckSignature(ca.PublicKey()))
		})
	}
}

// A CA and the certificates it signs share a suite, like they share a curve.
func TestPQSuite_Mismatch(t *testing.T) {
	registerTestPQSuite(t)

	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, host, _ := newTestV3(t, curve)

			// Signing refuses a certificate in another suite than its CA.
			tbs := &TBSCertificate{
				Version: Version3, Curve: curve, PQSuite: testPQSuite, Name: "x",
				Networks: host.Networks(), NotBefore: host.NotBefore(), NotAfter: host.NotAfter(), PublicKey: host.PublicKey(),
			}
			_, err := tbs.Sign(ca, curve, caKey)
			require.ErrorIs(t, err, ErrPQSuiteMismatch)

			// Extending refuses it too.
			v2CA := V2Form(ca)
			v2Host := V2Form(host)
			_, pqHost, err := DefaultPQSuite.SplitPublicKey(false, host.PublicKey())
			require.NoError(t, err)
			signPQ, err := SignPQ(DefaultPQSuite, caKey[len(caKey)-DefaultPQSuite.PrivateKeySize(true):])
			require.NoError(t, err)
			_, err = ExtendToV3(v2Host, testPQSuite, pqHost, ca, signPQ)
			require.ErrorIs(t, err, ErrPQSuiteMismatch)

			// The pool rejects a certificate whose CA, found by issuer, is in another suite: here the same v2 CA
			// extended once per suite, with only the default suite's extension trusted.
			pqPub, pqPriv, err := testPQSuite.GenerateKey(true)
			require.NoError(t, err)
			signOther, err := SignPQ(testPQSuite, pqPriv)
			require.NoError(t, err)
			otherCA, err := ExtendToV3(v2CA, testPQSuite, pqPub, nil, signOther)
			require.NoError(t, err)
			otherHost, err := ExtendToV3(v2Host, testPQSuite, pqHost, otherCA, signOther)
			require.NoError(t, err)

			pool := NewCAPool()
			require.NoError(t, pool.AddCA(ca))
			_, err = pool.VerifyCertificate(time.Now(), otherHost)
			require.ErrorIs(t, err, ErrPQSuiteMismatch)
		})
	}
}
