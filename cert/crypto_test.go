package cert

import (
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

func TestNewArgon2Parameters(t *testing.T) {
	p := NewArgon2Parameters(64*1024, 4, 3)
	assert.Equal(t, &Argon2Parameters{
		version:     argon2.Version,
		Memory:      64 * 1024,
		Parallelism: 4,
		Iterations:  3,
	}, p)
	p = NewArgon2Parameters(2*1024*1024, 2, 1)
	assert.Equal(t, &Argon2Parameters{
		version:     argon2.Version,
		Memory:      2 * 1024 * 1024,
		Parallelism: 2,
		Iterations:  1,
	}, p)
}

func TestDecryptAndUnmarshalSigningPrivateKey(t *testing.T) {
	passphrase := []byte("DO NOT USE")
	privKey := []byte(`# A good key
-----BEGIN NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
CjsKC0FFUy0yNTYtR0NNEiwIExCAgAQYAyAEKiCPoDfGQiosxNPTbPn5EsMlc2MI
c0Bt4oz6gTrFQhX3aBJcimhHKeAuhyTGvllD0Z19fe+DFPcLH3h5VrdjVfIAajg0
KrbV3n9UHif/Au5skWmquNJzoW1E4MTdRbvpti6o+WdQ49DxjBFhx0YH8LBqrbPU
0BGkUHmIO7daP24=
-----END NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
`)
	shortKey := []byte(`# A key which, once decrypted, is too short
-----BEGIN NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
CjsKC0FFUy0yNTYtR0NNEiwIExCAgAQYAyAEKiAVJwdfl3r+eqi/vF6S7OMdpjfo
hAzmTCRnr58Su4AqmBJbCv3zleYCEKYJP6UI3S8ekLMGISsgO4hm5leukCCyqT0Z
cQ76yrberpzkJKoPLGisX8f+xdy4aXSZl7oEYWQte1+vqbtl/eY9PGZhxUQdcyq7
hqzIyrRqfUgVuA==
-----END NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
`)
	invalidBanner := []byte(`# Invalid banner (not encrypted)
-----BEGIN NEBULA ED25519 PRIVATE KEY-----
bWRp2CTVFhW9HD/qCd28ltDgK3w8VXSeaEYczDWos8sMUBqDb9jP3+NYwcS4lURG
XgLvodMXZJuaFPssp+WwtA==
-----END NEBULA ED25519 PRIVATE KEY-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
CjwKC0FFUy0yNTYtR0NNEi0IExCAgIABGAEgBCognnjujd67Vsv99p22wfAjQaDT
oCMW1mdjkU3gACKNW4MSXOWR9Sts4C81yk1RUku2gvGKs3TB9LYoklLsIizSYOLl
+Vs//O1T0I1Xbml2XBAROsb/VSoDln/6LMqR4B6fn6B3GOsLBBqRI8daDl9lRMPB
qrlJ69wer3ZUHFXA
-END NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
`)

	keyBundle := appendByteSlices(privKey, shortKey, invalidBanner, invalidPem)

	// Success test case
	curve, k, rest, err := DecryptAndUnmarshalSigningPrivateKey(passphrase, keyBundle)
	require.NoError(t, err)
	assert.Equal(t, Curve_CURVE25519, curve)
	assert.Len(t, k, 64)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))

	// Fail due to short key
	curve, k, rest, err = DecryptAndUnmarshalSigningPrivateKey(passphrase, rest)
	require.EqualError(t, err, "key was not 64 bytes, is invalid ed25519 private key")
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))

	// Fail due to invalid banner
	curve, k, rest, err = DecryptAndUnmarshalSigningPrivateKey(passphrase, rest)
	require.EqualError(t, err, "bytes did not contain a proper nebula encrypted Ed25519/ECDSA private key banner")
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)

	// Fail due to invalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	curve, k, rest, err = DecryptAndUnmarshalSigningPrivateKey(passphrase, rest)
	require.EqualError(t, err, "input did not contain a valid PEM encoded block")
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)

	// Fail due to invalid passphrase
	curve, k, rest, err = DecryptAndUnmarshalSigningPrivateKey([]byte("invalid passphrase"), privKey)
	require.EqualError(t, err, "invalid passphrase or corrupt private key")
	assert.Nil(t, k)
	assert.Equal(t, []byte{}, rest)
}

func TestEncryptAndMarshalSigningPrivateKey(t *testing.T) {
	// Having proved that decryption works correctly above, we can test the
	// encryption function produces a value which can be decrypted
	passphrase := []byte("passphrase")
	bytes := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	kdfParams := NewArgon2Parameters(64*1024, 4, 3)
	key, err := EncryptAndMarshalSigningPrivateKey(Curve_CURVE25519, bytes, passphrase, kdfParams)
	require.NoError(t, err)

	// Verify the "key" can be decrypted successfully
	curve, k, rest, err := DecryptAndUnmarshalSigningPrivateKey(passphrase, key)
	assert.Len(t, k, 64)
	assert.Equal(t, Curve_CURVE25519, curve)
	assert.Equal(t, []byte{}, rest)
	require.NoError(t, err)

	// EncryptAndMarshalEd25519PrivateKey does not create any errors itself
}

func TestUnmarshalArgon2Parameters_Validation(t *testing.T) {
	salt := []byte{1, 2, 3, 4}

	tests := []struct {
		name             string
		params           *RawNebulaArgon2Parameters
		wantErr          bool
		wantErrSubstring string
		wantOut          *Argon2Parameters
	}{
		{
			name: "memory == 0 is rejected",
			params: &RawNebulaArgon2Parameters{
				Version: 0x13, Memory: 0, Parallelism: 4, Iterations: 3, Salt: salt,
			},
			wantErr:          true,
			wantErrSubstring: "memory",
		},
		{
			name: "parallelism == 0 is rejected",
			params: &RawNebulaArgon2Parameters{
				Version: 0x13, Memory: 65536, Parallelism: 0, Iterations: 3, Salt: salt,
			},
			wantErr:          true,
			wantErrSubstring: "parallelism",
		},
		{
			name: "parallelism > MaxUint8 is rejected (proto field is uint32, struct field is uint8)",
			params: &RawNebulaArgon2Parameters{
				Version: 0x13, Memory: 65536, Parallelism: 256, Iterations: 3, Salt: salt,
			},
			wantErr:          true,
			wantErrSubstring: "parallelism",
		},
		{
			name: "parallelism = 1000 is rejected (mid-range silent-truncation hazard if bounds check were weakened)",
			params: &RawNebulaArgon2Parameters{
				Version: 0x13, Memory: 65536, Parallelism: 1000, Iterations: 3, Salt: salt,
			},
			wantErr:          true,
			wantErrSubstring: "parallelism",
		},
		{
			name: "parallelism = MaxUint32 is rejected (extreme overflow case)",
			params: &RawNebulaArgon2Parameters{
				Version: 0x13, Memory: 65536, Parallelism: math.MaxUint32, Iterations: 3, Salt: salt,
			},
			wantErr:          true,
			wantErrSubstring: "parallelism",
		},
		{
			name: "iterations == 0 is rejected",
			params: &RawNebulaArgon2Parameters{
				Version: 0x13, Memory: 65536, Parallelism: 4, Iterations: 0, Salt: salt,
			},
			wantErr:          true,
			wantErrSubstring: "iterations",
		},
		{
			name: "valid params forward every field through to the Argon2Parameters struct",
			params: &RawNebulaArgon2Parameters{
				Version: 0x13, Memory: 65536, Parallelism: 4, Iterations: 3, Salt: salt,
			},
			wantErr: false,
			wantOut: &Argon2Parameters{
				version:     0x13,
				Memory:      65536,
				Parallelism: 4,
				Iterations:  3,
				salt:        salt,
			},
		},
		{
			name: "max-uint8 parallelism is accepted (boundary just below the rejection threshold)",
			params: &RawNebulaArgon2Parameters{
				Version: 0x13, Memory: 65536, Parallelism: 255, Iterations: 3, Salt: salt,
			},
			wantErr: false,
			wantOut: &Argon2Parameters{
				version:     0x13,
				Memory:      65536,
				Parallelism: 255,
				Iterations:  3,
				salt:        salt,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := unmarshalArgon2Parameters(tc.params)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, strings.ToLower(err.Error()), tc.wantErrSubstring,
					"error message must name the offending field so operators can find it")
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantOut, got)
		})
	}
}
