package nebula

import (
	"crypto/fips140"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCipherSuite(t *testing.T) {
	tests := []struct {
		name            string
		curve           cert.Curve
		cipher          string
		fips140Enforced bool
		wantErr         string
		// wantName is the full expected CipherSuite name (<DH>_<Cipher>_<Hash>),
		// only checked when wantErr is empty. Asserting the whole name makes both
		// the curve and cipher selection load-bearing.
		wantName string
	}{
		{
			name:     "curve25519 aesgcm, not enforced",
			curve:    cert.Curve_CURVE25519,
			cipher:   "aesgcm",
			wantName: "25519_AESGCM_SHA256",
		},
		{
			name:     "curve25519 chachapoly, not enforced",
			curve:    cert.Curve_CURVE25519,
			cipher:   "chachapoly",
			wantName: "25519_ChaChaPoly_SHA256",
		},
		{
			name:     "p256 aesgcm, not enforced",
			curve:    cert.Curve_P256,
			cipher:   "aesgcm",
			wantName: "P256_AESGCM_SHA256",
		},
		{
			name:            "p256 aesgcm, enforced is allowed",
			curve:           cert.Curve_P256,
			cipher:          "aesgcm",
			fips140Enforced: true,
			wantName:        "P256_AESGCM_SHA256",
		},
		{
			name:            "curve25519 rejected when enforced",
			curve:           cert.Curve_CURVE25519,
			cipher:          "aesgcm",
			fips140Enforced: true,
			wantErr:         "pki: use of Curve25519 is not allowed in FIPS 140-only mode",
		},
		{
			name:            "chachapoly rejected when enforced",
			curve:           cert.Curve_P256,
			cipher:          "chachapoly",
			fips140Enforced: true,
			wantErr:         "pki: use of ChaChaPoly is not allowed in FIPS 140-only mode",
		},
		{
			// Curve is checked before cipher, so a Curve25519+ChaChaPoly
			// request reports the Curve25519 rejection.
			name:            "curve25519 chachapoly rejected on curve when enforced",
			curve:           cert.Curve_CURVE25519,
			cipher:          "chachapoly",
			fips140Enforced: true,
			wantErr:         "pki: use of Curve25519 is not allowed in FIPS 140-only mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs, err := newCipherSuite(tt.curve, false, tt.cipher, tt.fips140Enforced)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				assert.Nil(t, cs)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cs)
			assert.Equal(t, tt.wantName, string(cs.Name()))
		})
	}
}

func TestNewCipherSuiteUnsupportedCurve(t *testing.T) {
	cs, err := newCipherSuite(cert.Curve(99), false, "aesgcm", false)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "unsupported curve:"), "got: %v", err)
	assert.Nil(t, cs)
}

func TestPKIReloadRestartRequired(t *testing.T) {
	ca, _, caKey, caPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	pkiConfig := func(cipher, network string) string {
		_, _, keyPEM, certPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix(network)}, nil, nil)
		return fmt.Sprintf("cipher: %s\npki:\n  ca: %q\n  cert: %q\n  key: %q\n", cipher, caPEM, certPEM, keyPEM)
	}

	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(pkiConfig("aes", "10.1.0.2/24")))
	p, err := NewPKIFromConfig(test.NewLogger(), c)
	require.NoError(t, err)

	// A cert that changes our networks is refused and needs a restart, it is not a failure
	res := c.ReloadConfigString(pkiConfig("aes", "10.1.0.3/24"))
	require.NoError(t, res.Err)
	assert.True(t, res.RestartRequired)
	assert.False(t, res.Failed)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")}, p.getCertState().myVpnNetworks)

	// The cipher only applies at startup
	c2 := config.NewC(test.NewLogger())
	require.NoError(t, c2.LoadString(pkiConfig("aes", "10.1.0.2/24")))
	p, err = NewPKIFromConfig(test.NewLogger(), c2)
	require.NoError(t, err)
	res = c2.ReloadConfigString(pkiConfig("chachapoly", "10.1.0.2/24"))
	require.NoError(t, res.Err)
	assert.True(t, res.RestartRequired)
	assert.Equal(t, "aes", p.getCertState().cipher)

	// A cipher we can't run would fail the restart, so it fails the reload instead of asking for one
	c4 := config.NewC(test.NewLogger())
	require.NoError(t, c4.LoadString(pkiConfig("aes", "10.1.0.2/24")))
	_, err = NewPKIFromConfig(test.NewLogger(), c4)
	require.NoError(t, err)
	for range 2 {
		res = c4.ReloadConfigString(pkiConfig("nope", "10.1.0.2/24"))
		require.NoError(t, res.Err)
		assert.True(t, res.Failed, "a bad cipher that didn't change since the last reload is still bad")
		assert.False(t, res.RestartRequired)
	}
	// Fixing it back to the running cipher needs nothing
	res = c4.ReloadConfigString(pkiConfig("aes", "10.1.0.2/24"))
	require.NoError(t, res.Err)
	assert.False(t, res.Failed)
	assert.False(t, res.RestartRequired)

	// A cert that keeps our networks applies without a restart
	c3 := config.NewC(test.NewLogger())
	require.NoError(t, c3.LoadString(pkiConfig("aes", "10.1.0.2/24")))
	_, err = NewPKIFromConfig(test.NewLogger(), c3)
	require.NoError(t, err)
	res = c3.ReloadConfigString(pkiConfig("aes", "10.1.0.2/24"))
	require.NoError(t, res.Err)
	assert.False(t, res.RestartRequired)

	// A cert that can't be read is a failure, and a restart wouldn't help
	res = c3.ReloadConfigString(strings.Replace(pkiConfig("aes", "10.1.0.2/24"), "cert: \"", "cert: \"-----BEGIN NEBULA CERTIFICATE V2-----\\ngarbage\\n-----END NEBULA CERTIFICATE V2-----\\n", 1))
	require.NoError(t, res.Err)
	assert.True(t, res.Failed)
	assert.False(t, res.RestartRequired)
}

// A cert for a version we weren't running is accepted without comparing networks, so switching to one with different
// networks needs a restart. One with the same networks doesn't
func TestPKIReloadNewVersionWithOtherNetworks(t *testing.T) {
	ca1, _, ca1Key, ca1PEM := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	ca2, _, ca2Key, ca2PEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	caPEM := string(ca1PEM) + string(ca2PEM)
	pkiConfig := func(v cert.Version, network string) string {
		ca, caKey := ca1, ca1Key
		if v == cert.Version2 {
			ca, caKey = ca2, ca2Key
		}
		_, _, keyPEM, certPEM := cert_test.NewTestCert(v, cert.Curve_CURVE25519, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix(network)}, nil, nil)
		return fmt.Sprintf("pki:\n  ca: %q\n  cert: %q\n  key: %q\n", caPEM, certPEM, keyPEM)
	}

	for _, tc := range []struct {
		network string
		restart bool
	}{
		{"10.9.0.7/24", true},
		{"10.1.0.2/24", false},
	} {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(pkiConfig(cert.Version1, "10.1.0.2/24")))
		p, err := NewPKIFromConfig(test.NewLogger(), c)
		require.NoError(t, err)

		res := c.ReloadConfigString(pkiConfig(cert.Version2, tc.network))
		require.NoError(t, res.Err)
		assert.False(t, res.Failed, tc.network)
		assert.Equal(t, tc.restart, res.RestartRequired, tc.network)
		assert.Equal(t, []netip.Prefix{netip.MustParsePrefix(tc.network)}, p.getCertState().myVpnNetworks, "accepted either way, as before")
	}
}

// FIPS 140-only mode refuses chachapoly at startup, so reloading to it fails rather than asks for a restart
func TestPKIReloadChachapolyInFIPSOnlyFails(t *testing.T) {
	fipsOnly = func() bool { return true }
	t.Cleanup(func() { fipsOnly = fips140.Enforced })
	ca, _, caKey, caPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_P256, time.Time{}, time.Time{}, nil, nil, nil)
	_, _, keyPEM, certPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_P256, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")}, nil, nil)
	pkiConfig := func(cipher string) string {
		return fmt.Sprintf("cipher: %s\npki:\n  ca: %q\n  cert: %q\n  key: %q\n", cipher, caPEM, certPEM, keyPEM)
	}

	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(pkiConfig("aes")))
	_, err := NewPKIFromConfig(test.NewLogger(), c)
	require.NoError(t, err)

	res := c.ReloadConfigString(pkiConfig("chachapoly"))
	require.NoError(t, res.Err)
	assert.True(t, res.Failed)
	assert.False(t, res.RestartRequired)
}

func TestLoadCAPoolBlocklist(t *testing.T) {
	ca, _, caKey, caPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	crt, _, _, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")}, nil, nil)
	fp, err := crt.Fingerprint()
	require.NoError(t, err)

	load := func(entry string) (*cert.CAPool, error) {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(fmt.Sprintf("pki:\n  ca: %q\n  blocklist:\n    - %q\n", caPEM, entry)))
		return loadCAPoolFromConfig(test.NewLogger(), c)
	}

	for _, entry := range []string{fp, strings.ToUpper(fp), " " + fp + "\t"} {
		pool, err := load(entry)
		require.NoError(t, err, entry)
		assert.True(t, pool.IsBlocklisted(fp), entry)
	}

	for _, entry := range []string{fp[1:], fp + "00", "sha256:" + fp, "zz" + fp[2:], ""} {
		_, err := load(entry)
		require.Error(t, err, entry)
	}

	// A bad entry on reload fails it, the valid entries are still blocked
	_, _, keyPEM, certPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "me", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/24")}, nil, nil)
	pkiConfig := func(entry string) string {
		return fmt.Sprintf("pki:\n  ca: %q\n  cert: %q\n  key: %q\n  blocklist:\n    - %q\n", caPEM, certPEM, keyPEM, entry)
	}
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(pkiConfig(fp)))
	p, err := NewPKIFromConfig(test.NewLogger(), c)
	require.NoError(t, err)

	other, _, _, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "other", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.3/24")}, nil, nil)
	otherFp, err := other.Fingerprint()
	require.NoError(t, err)

	res := c.ReloadConfigString(pkiConfig(fp) + fmt.Sprintf("    - %q\n    - %q\n", otherFp, fp[1:]))
	assert.True(t, res.Failed)
	assert.True(t, p.GetCAPool().IsBlocklisted(fp))
	assert.True(t, p.GetCAPool().IsBlocklisted(otherFp))
}

func TestNewCertStateFromConfig_V3(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version3, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	host, _, keyPEM, certPEM := cert_test.NewTestCert(cert.Version3, cert.Curve_CURVE25519, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, nil)
	v2PEM, err := cert.V2Form(host).MarshalPEM()
	require.NoError(t, err)
	key, _, _, err := cert.UnmarshalPrivateKeyFromPEM(keyPEM)
	require.NoError(t, err)
	classicalPEM := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, key[:len(key)-cert.MLKEM1024PrivateKeySize])

	load := func(certPEM, keyPEM []byte) (*CertState, error) {
		c := config.NewC(test.NewLogger())
		c.Settings["pki"] = map[string]any{"cert": string(certPEM), "key": string(keyPEM)}
		return newCertStateFromConfig(test.NewLogger(), c, "aes")
	}

	cs, err := load(certPEM, keyPEM)
	require.NoError(t, err)
	assert.Equal(t, host, cs.GetCredential(cert.Version3).Cert)
	assert.Equal(t, cert.V2Form(host), cs.GetCredential(cert.Version2).Cert, "the v2 form comes with it")
	assert.Equal(t, cert.Version2, cs.DefaultVersion(), "classical handshakes still start with v2")

	// Listing the v2 form as well is fine.
	_, err = load(append(append([]byte{}, certPEM...), v2PEM...), keyPEM)
	require.NoError(t, err)

	// Any other v2 certificate is not.
	_, _, _, otherPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, cert.V2Form(ca), caKey[:len(caKey)-cert.MLDSA87PrivateKeySize], "other", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, nil)
	_, err = load(append(append([]byte{}, certPEM...), otherPEM...), keyPEM)
	require.ErrorContains(t, err, "not the v2 form of the v3 certificate")

	// A v3 certificate needs the composite key.
	_, err = load(certPEM, classicalPEM)
	require.ErrorContains(t, err, "not a pair")

	// A composite key also serves a lone v2 certificate.
	cs, err = load(v2PEM, keyPEM)
	require.NoError(t, err)
	assert.Nil(t, cs.GetCredential(cert.Version3))
	assert.NotNil(t, cs.GetCredential(cert.Version2))
}

// A v3 certificate without a v2 form stands alone: the node speaks hybrid handshakes only, takes its networks from it,
// and initiates as version 3.
func TestNewCertStateFromConfig_V3WithoutV2Form(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	ca, _, caKey, caPEM := cert_test.NewTestV3CaCertWithoutV2Form(cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	network := netip.MustParsePrefix("10.1.0.1/16")
	host, _, keyPEM, certPEM := cert_test.NewTestCert(cert.Version3, cert.Curve_CURVE25519, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{network}, nil, nil)
	require.Nil(t, cert.V2Form(host))

	load := func(extra string, certPEMs ...[]byte) *config.C {
		c := config.NewC(test.NewLogger())
		var all []byte
		for _, b := range certPEMs {
			all = append(all, b...)
		}
		require.NoError(t, c.LoadString(fmt.Sprintf("pki:\n  ca: %q\n  cert: %q\n  key: %q\n%s", caPEM, all, keyPEM, extra)))
		return c
	}

	cs, err := newCertStateFromConfig(test.NewLogger(), load("", certPEM), "aes")
	require.NoError(t, err)
	assert.Equal(t, cert.Version3, cs.DefaultVersion())
	assert.Equal(t, host, cs.GetDefaultCertificate())
	assert.Equal(t, host, cs.ownCertificate())
	assert.Nil(t, cs.GetCredential(cert.Version2))
	assert.Nil(t, cs.GetCredential(cert.Version1))
	assert.NotNil(t, cs.GetCredential(cert.Version3))
	assert.False(t, cs.classicalCapable())
	assert.Equal(t, []netip.Prefix{network}, cs.myVpnNetworks)

	// A v1 or v2 certificate can not be listed with it, and only version 3 initiates.
	v2CA, _, v2CAKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	_, _, _, v2PEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, v2CA, v2CAKey, "host", time.Time{}, time.Time{}, []netip.Prefix{network}, nil, nil)
	_, err = newCertStateFromConfig(test.NewLogger(), load("", certPEM, v2PEM), "aes")
	require.ErrorContains(t, err, "has no v2 form")
	_, err = newCertStateFromConfig(test.NewLogger(), load("  initiating_version: 2\n", certPEM), "aes")
	require.ErrorContains(t, err, "without a v2 certificate")
	_, err = newCertStateFromConfig(test.NewLogger(), load("  initiating_version: 3\n", certPEM), "aes")
	require.NoError(t, err)

	// Reloading onto a v3 certificate without a v2 form compares it with the certificate it replaces.
	interopCA, _, interopKey, interopCAPEM := cert_test.NewTestCaCert(cert.Version3, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	_, _, iKeyPEM, iCertPEM := cert_test.NewTestCert(cert.Version3, cert.Curve_CURVE25519, interopCA, interopKey, "host", time.Time{}, time.Time{}, []netip.Prefix{network}, nil, nil)
	_, _, pKeyPEM, pCertPEM := cert_test.NewTestCert(cert.Version3, cert.Curve_CURVE25519, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.2.0.1/16")}, nil, nil)
	pkiConfig := func(certPEM, keyPEM []byte) string {
		return fmt.Sprintf("pki:\n  ca: %q\n  cert: %q\n  key: %q\n", string(caPEM)+string(interopCAPEM), certPEM, keyPEM)
	}
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(pkiConfig(iCertPEM, iKeyPEM)))
	p, err := NewPKIFromConfig(test.NewLogger(), c)
	require.NoError(t, err)
	res := c.ReloadConfigString(pkiConfig(certPEM, keyPEM))
	require.NoError(t, res.Err)
	assert.False(t, res.Failed)
	assert.False(t, res.RestartRequired, "same networks")
	assert.False(t, p.getCertState().classicalCapable())
	res = c.ReloadConfigString(pkiConfig(pCertPEM, pKeyPEM))
	require.NoError(t, res.Err)
	assert.True(t, res.RestartRequired, "other networks")
	assert.Equal(t, []netip.Prefix{network}, p.getCertState().myVpnNetworks)
}

// A build without ML-DSA, the FIPS 140-3 Go Cryptographic Module v1.0.0, leaves version 3 CAs out of the pool with a
// warning, so a bundle shared with v3 nodes keeps working; a bundle of nothing else leaves no CA. It can not make a v3
// CA, so the one here is testdata/v3-ca.crt, made by nebula-cert ca -version 3.
func TestLoadCAPoolWithoutPQ(t *testing.T) {
	if cert.DefaultPQSuite.Available() == nil {
		t.Skip("this build runs ML-DSA, see cert.TestCAPool_PQUnavailable")
	}
	v3PEM, err := os.ReadFile("testdata/v3-ca.crt")
	require.NoError(t, err)
	_, _, _, v2PEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)

	load := func(caPEM []byte) (*cert.CAPool, error) {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(fmt.Sprintf("pki:\n  ca: %q\n", caPEM)))
		return loadCAPoolFromConfig(test.NewLogger(), c)
	}
	pool, err := load(append(append([]byte{}, v3PEM...), v2PEM...))
	require.NoError(t, err)
	assert.Len(t, pool.CAs, 1)
	_, err = load(v3PEM)
	require.ErrorContains(t, err, "no valid CA certificates present")
}

// A newer nebula may add certificate versions, a pki.ca bundle shared with it keeps working and the ones we can't use
// are skipped with a warning
func TestLoadCAPoolSkipsUnsupported(t *testing.T) {
	ca, _, _, caPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	fp, err := ca.Fingerprint()
	require.NoError(t, err)
	_, _, _, expiredPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), nil, nil, nil)
	newVersionPEM := pem.EncodeToMemory(&pem.Block{Type: "NEBULA CERTIFICATE V9", Bytes: []byte{0x30, 0x00}})

	load := func(ca []byte) (*cert.CAPool, error) {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(fmt.Sprintf("pki:\n  ca: %q\n", ca)))
		return loadCAPoolFromConfig(test.NewLogger(), c)
	}

	pool, err := load(append(append([]byte{}, newVersionPEM...), caPEM...))
	require.NoError(t, err)
	assert.Len(t, pool.CAs, 1)
	assert.Contains(t, pool.CAs, fp)

	_, err = load(newVersionPEM)
	require.EqualError(t, err, "no valid CA certificates present")

	_, err = load(append(append([]byte{}, expiredPEM...), newVersionPEM...))
	require.EqualError(t, err, "no valid CA certificates present")

	// A CA for a newer curve is skipped the same way
	pool, err = load(append(append([]byte{}, cert_test.WithCurve(caPEM, cert.Curve(2))...), caPEM...))
	require.NoError(t, err)
	assert.Len(t, pool.CAs, 1)
	assert.Contains(t, pool.CAs, fp)

	// Anything else is fatal and keeps its cause
	_, err = load([]byte("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n"))
	require.ErrorIs(t, err, cert.ErrInvalidPEMCertificateBanner)
}

// pki.cert may hold certificates for versions a newer nebula added, we use the ones we can and skip the rest
func TestPKICertSkipsUnsupported(t *testing.T) {
	ca, _, caKey, caPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	_, _, keyPEM, certPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")}, nil, nil)
	newVersionPEM := pem.EncodeToMemory(&pem.Block{Type: "NEBULA CERTIFICATE V9", Bytes: []byte{0x30, 0x00}})
	_, _, _, otherPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")}, nil, nil)
	newCurvePEM := cert_test.WithCurve(otherPEM, cert.Curve(2))

	load := func(crt []byte) (*PKI, error) {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(fmt.Sprintf("pki:\n  ca: %q\n  cert: %q\n  key: %q\n", caPEM, crt, keyPEM)))
		return NewPKIFromConfig(test.NewLogger(), c)
	}

	for _, crt := range [][]byte{
		append(append([]byte{}, newVersionPEM...), certPEM...),
		append(append([]byte{}, certPEM...), newVersionPEM...),
		append(append([]byte{}, newCurvePEM...), certPEM...),
	} {
		p, err := load(crt)
		require.NoError(t, err)
		assert.Equal(t, cert.Version2, p.getCertState().initiatingVersion)
	}

	// With nothing left the error says which certificates were skipped and why
	_, err := load(append(append([]byte{}, newVersionPEM...), newCurvePEM...))
	require.ErrorIs(t, err, cert.ErrUnknownVersion)
	require.ErrorIs(t, err, cert.ErrUnknownCurve)
	require.ErrorContains(t, err, "no valid certificates found in pki.cert")
	require.ErrorContains(t, err, "certificate 1: certificate version unrecognized")
	require.ErrorContains(t, err, `certificate 2: "host": certificate curve unrecognized: 2`)

	// Anything after the last certificate that isn't one is still an error, as is a block that never ends
	_, err = load(append(append([]byte{}, certPEM...), "trailing garbage\n"...))
	require.ErrorIs(t, err, cert.ErrInvalidPEMBlock)
	require.ErrorIs(t, err, cert.ErrTruncatedPEMBlock)
	_, err = load(append(append([]byte{}, certPEM...), "-----BEGIN NEBULA CERTIFICATE V2-----\nAAAA\n"...))
	require.ErrorIs(t, err, cert.ErrInvalidPEMBlock)
	require.ErrorIs(t, err, cert.ErrTruncatedPEMBlock)

	// A newer curve is skipped before anything else is checked, the same as a newer version that can't be parsed
	_, _, _, netCAPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}, nil, nil)
	_, err = load(cert_test.WithCurve(netCAPEM, cert.Curve(2)))
	require.ErrorIs(t, err, cert.ErrUnknownCurve)
	oldCA, _, oldCAKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now().Add(-3*time.Hour), time.Now().Add(time.Hour), nil, nil, nil)
	_, _, _, expiredHostPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, oldCA, oldCAKey, "host", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")}, nil, nil)
	_, err = load(append(append([]byte{}, cert_test.WithCurve(expiredHostPEM, cert.Curve(2))...), certPEM...))
	require.NoError(t, err)
}
