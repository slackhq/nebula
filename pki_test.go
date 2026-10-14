package nebula

import (
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

func TestNewCertStateFromConfig_V3(t *testing.T) {
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
		return newCertStateFromConfig(c, "aes")
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
