package nebula

import (
	"crypto/fips140"
	"fmt"
	"net/netip"
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
			name:     "hybrid aesgcm takes SHA-512",
			curve:    cert.Curve_P384_MLKEM1024_MLDSA87,
			cipher:   "aesgcm",
			wantName: "P384_AESGCM_SHA512",
		},
		{
			name:     "hybrid chachapoly takes SHA-512",
			curve:    cert.Curve_P384_MLKEM1024_MLDSA87,
			cipher:   "chachapoly",
			wantName: "P384_ChaChaPoly_SHA512",
		},
		{
			name:            "hybrid aesgcm, enforced is allowed",
			curve:           cert.Curve_P384_MLKEM1024_MLDSA87,
			cipher:          "aesgcm",
			fips140Enforced: true,
			wantName:        "P384_AESGCM_SHA512",
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
	res = c3.ReloadConfigString(strings.Replace(pkiConfig("aes", "10.1.0.2/24"), "cert: \"", "cert: \"garbage", 1))
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

// A hybrid node holds one certificate on the hybrid curve, version 2, and its key, as a classical node holds its own.
func TestNewCertStateFromConfig_Hybrid(t *testing.T) {
	if err := cert.HybridAvailable(); err != nil {
		t.Skip(err)
	}
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_P384_MLKEM1024_MLDSA87, time.Time{}, time.Time{}, nil, nil, nil)
	host, _, keyPEM, certPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_P384_MLKEM1024_MLDSA87, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, nil)
	load := func(certPEM, keyPEM []byte) (*CertState, error) {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(fmt.Sprintf("pki:\n  cert: %q\n  key: %q\n", certPEM, keyPEM)))
		return newCertStateFromConfig(c, "aes")
	}

	cs, err := load(certPEM, keyPEM)
	require.NoError(t, err)
	assert.Equal(t, host, cs.GetCredential(cert.Version2).Cert)
	assert.Equal(t, cert.Version2, cs.DefaultVersion())
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, cs.myVpnNetworks)

	// The curves of a node's certificates never mix.
	classicalCA, _, classicalCAKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	_, _, _, v1PEM := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, classicalCA, classicalCAKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, nil)
	_, err = load(append(append([]byte{}, v1PEM...), certPEM...), keyPEM)
	require.Error(t, err)

	// Nor does a key of another curve fit.
	_, _, otherKeyPEM, _ := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, classicalCA, classicalCAKey, "other", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.2/16")}, nil, nil)
	_, err = load(certPEM, otherKeyPEM)
	require.ErrorContains(t, err, "not a pair")
}
