package nebula

import (
	"strings"
	"testing"

	"github.com/slackhq/nebula/cert"
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
