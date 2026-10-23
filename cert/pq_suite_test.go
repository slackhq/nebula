package cert

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
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
	sign, err := SignClassical(curve, caKey2)
	require.NoError(t, err)
	signPQ, err := SignPQ(suite, curve, pqPriv)
	require.NoError(t, err)
	ca, err = ExtendToV3(ca2, suite, pqPub, nil, sign, signPQ)
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
	skipWithoutPQ(t)
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
	skipWithoutPQ(t)
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
	skipWithoutPQ(t)
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
			sign, signPQ := compositeSigners(t, curve, caKey)
			_, err = ExtendToV3(v2Host, testPQSuite, pqHost, ca, sign, signPQ)
			require.ErrorIs(t, err, ErrPQSuiteMismatch)

			// The pool rejects a certificate whose CA, found by issuer, is in another suite: here the same v2 CA
			// extended once per suite, with only the default suite's extension trusted.
			pqPub, pqPriv, err := testPQSuite.GenerateKey(true)
			require.NoError(t, err)
			signOther, err := SignPQ(testPQSuite, curve, pqPriv)
			require.NoError(t, err)
			otherCA, err := ExtendToV3(v2CA, testPQSuite, pqPub, nil, sign, signOther)
			require.NoError(t, err)
			otherHost, err := ExtendToV3(v2Host, testPQSuite, pqHost, otherCA, sign, signOther)
			require.NoError(t, err)

			pool := NewCAPool()
			require.NoError(t, pool.AddCA(ca))
			_, err = pool.VerifyCertificate(time.Now(), otherHost)
			require.ErrorIs(t, err, ErrCaNotFound, "otherHost names otherCA, which is not trusted")

			// Naming the trusted CA does not make it the right suite.
			forged := otherHost.Copy().(*certificateV3)
			forged.issuer, err = ca.Fingerprint()
			require.NoError(t, err)
			_, err = pool.VerifyCertificate(time.Now(), forged)
			require.ErrorIs(t, err, ErrPQSuiteMismatch)
		})
	}
}

func TestMLKEMModulusOK(t *testing.T) {
	stdlib := func(pub []byte) bool {
		_, err := mlkem.NewEncapsulationKey1024(pub)
		return err == nil
	}
	setCoeff := func(pub []byte, i int, v uint16) {
		b := pub[i/2*3:]
		if i%2 == 0 {
			b[0] = byte(v)
			b[1] = b[1]&0xf0 | byte(v>>8)
		} else {
			b[1] = b[1]&0x0f | byte(v<<4)
			b[2] = byte(v >> 4)
		}
	}

	for range 8 {
		dk, err := mlkem.GenerateKey1024()
		require.NoError(t, err)
		pub := dk.EncapsulationKey().Bytes()
		require.True(t, mlkem1024.checkPublicKey(pub))
		for _, i := range []int{0, 1, 2, 3, 511, 512, 1022, 1023} {
			for _, v := range []uint16{0, 3328, 3329, 4095} {
				p := bytes.Clone(pub)
				setCoeff(p, i, v)
				assert.Equal(t, stdlib(p), mlkem1024.checkPublicKey(p), "coefficient %d = %d", i, v)
				assert.Equal(t, v < 3329, mlkem1024.checkPublicKey(p), "coefficient %d = %d", i, v)
			}
		}
	}

	pub := make([]byte, mlkem.EncapsulationKeySize1024)
	for range 64 {
		_, _ = rand.Read(pub)
		assert.Equal(t, stdlib(pub), mlkem1024.checkPublicKey(pub))
	}
	assert.False(t, mlkem1024.checkPublicKey(pub[:len(pub)-1]))
}

// unavailablePQSuite stands in for a suite this build can not run, as ML-DSA under the FIPS 140-3 Go Cryptographic
// Module v1.0.0: every call of its signature algorithm fails.
const unavailablePQSuite PQSuite = 201

var errTestUnavailable = errors.New("testdsa: unavailable in this build")

func registerUnavailablePQSuite(t *testing.T) {
	t.Helper()
	kem, dsa := mlkem1024, mldsa87
	kem.name, dsa.name = "NOKEM", "NODSA"
	dsa.publicKey = func([]byte) ([]byte, error) { return nil, errTestUnavailable }
	registerPQSuite(unavailablePQSuite, &pqSuite{kem: kem, dsa: dsa})
	t.Cleanup(func() {
		delete(pqSuites, unavailablePQSuite)
		for k := range pqKeyBanners {
			if strings.Contains(k, "NOKEM") || strings.Contains(k, "NODSA") {
				delete(pqKeyBanners, k)
			}
		}
	})
}

// A v3 CA in a suite this build can not run is left out of the pool with the reason, rather than failing the pool, so
// a bundle shared with v3 nodes stays usable without it.
func TestCAPool_PQUnavailable(t *testing.T) {
	skipWithoutPQ(t)
	registerUnavailablePQSuite(t)
	require.ErrorIs(t, unavailablePQSuite.Available(), ErrPQUnavailable)
	require.ErrorIs(t, unavailablePQSuite.Available(), errTestUnavailable, "the algorithm's own error comes along")
	require.NoError(t, DefaultPQSuite.Available())

	// A v3 CA relabelled into the suite that is not there.
	ca3, _, _, _ := newTestV3(t, Curve_CURVE25519)
	relabelled := rebuildV3(t, ca3, func(fields map[asn1.Tag][]byte, _ *[]asn1.Tag) {
		var b cryptobyte.Builder
		b.AddASN1(TagCertPQSuite, func(b *cryptobyte.Builder) { b.AddUint8(uint8(unavailablePQSuite)) })
		fields[TagCertPQSuite] = b.BytesOrPanic()
	})
	_, err := unmarshalCertificateV3(relabelled, nil, Curve_CURVE25519)
	require.ErrorIs(t, err, ErrPQUnavailable)
	require.ErrorIs(t, err, errTestUnavailable)
	unavailablePEM := pem.EncodeToMemory(&pem.Block{Type: CertificateV3Banner, Bytes: relabelled})

	ca2, _, _, ca2PEM := NewTestCaCert(Version2, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	pool, err := NewCAPoolFromPEM(append(append([]byte{}, unavailablePEM...), ca2PEM...))
	require.ErrorIs(t, err, ErrPQUnavailable)
	require.ErrorIs(t, err, errTestUnavailable)
	assert.NotErrorIs(t, err, ErrExpired)
	require.NotNil(t, pool)
	fp, err := ca2.Fingerprint()
	require.NoError(t, err)
	assert.Contains(t, pool.CAs, fp, "the rest of the bundle loads")
	assert.Len(t, pool.CAs, 1)

	// Expired CAs are reported alongside.
	expired, _, _, expiredPEM := NewTestCaCert(Version2, Curve_CURVE25519, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), nil, nil, nil)
	pool, err = NewCAPoolFromPEM(append(append([]byte{}, unavailablePEM...), expiredPEM...))
	require.ErrorIs(t, err, ErrPQUnavailable)
	require.ErrorIs(t, err, ErrExpired)
	expiredFp, err := expired.Fingerprint()
	require.NoError(t, err)
	assert.Contains(t, pool.CAs, expiredFp)

	// Without anything left out, an expired CA is ErrExpired itself, as before.
	_, err = NewCAPoolFromPEM(expiredPEM)
	assert.Equal(t, ErrExpired, err)
}
