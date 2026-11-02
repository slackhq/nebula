package cert

import (
	"encoding/pem"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"
)

func TestNewArgon2Parameters(t *testing.T) {
	tests := []struct {
		name        string
		memory      uint32
		parallelism uint8
		iterations  uint32
	}{
		{"typical / RFC-9106 second-recommended", 64 * 1024, 4, 3},
		{"larger / RFC-9106 first-recommended", 2 * 1024 * 1024, 2, 1},
		{"zero values pass through (NewArgon2Parameters does not validate)", 0, 0, 0},
		{"max-of-each-type passes through", math.MaxUint32, math.MaxUint8, math.MaxUint32},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NewArgon2Parameters(tc.memory, tc.parallelism, tc.iterations)
			assert.Equal(t, &Argon2Parameters{
				version:     argon2.Version,
				Memory:      tc.memory,
				Parallelism: tc.parallelism,
				Iterations:  tc.iterations,
			}, got)
		})
	}
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

func TestUnmarshalArgon2Parameters_Validation(t *testing.T) {
	salt := []byte{1, 2, 3, 4}

	tests := []struct {
		name             string
		params           *RawNebulaArgon2Parameters
		wantErr          bool
		wantErrSubstring string // present iff wantErr; lowercase substring
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

func TestEncryptAndMarshalSigningPrivateKey(t *testing.T) {
	passphrase := []byte("passphrase")
	ed25519Bytes := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 64 bytes
	p256Bytes := []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")                                    // 32 bytes
	kdfParams := NewArgon2Parameters(64*1024, 4, 3)

	tests := []struct {
		name         string
		curve        Curve
		plaintext    []byte
		wantBanner   string
		wantErr      bool
		wantErrPart  string // lowercase substring expected in the error
		wantKeyBytes int    // expected len(k) after a round-trip decrypt
	}{
		{
			name:         "Ed25519 happy round-trip",
			curve:        Curve_CURVE25519,
			plaintext:    ed25519Bytes,
			wantBanner:   EncryptedEd25519PrivateKeyBanner,
			wantKeyBytes: 64,
		},
		{
			name:         "P256 happy round-trip",
			curve:        Curve_P256,
			plaintext:    p256Bytes,
			wantBanner:   EncryptedECDSAP256PrivateKeyBanner,
			wantKeyBytes: 32,
		},
		{
			name:        "invalid curve is rejected",
			curve:       Curve(99),
			plaintext:   ed25519Bytes,
			wantErr:     true,
			wantErrPart: "invalid curve",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := EncryptAndMarshalSigningPrivateKey(tc.curve, tc.plaintext, passphrase, kdfParams)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, strings.ToLower(err.Error()), tc.wantErrPart)
				require.Nil(t, key)
				return
			}
			require.NoError(t, err)
			require.Contains(t, string(key), tc.wantBanner,
				"emitted PEM must use the curve-specific banner")

			gotCurve, k, rest, err := DecryptAndUnmarshalSigningPrivateKey(passphrase, key)
			require.NoError(t, err)
			assert.Len(t, k, tc.wantKeyBytes)
			assert.Equal(t, tc.curve, gotCurve)
			assert.Equal(t, []byte{}, rest)
		})
	}
}

func TestUnmarshalNebulaEncryptedData_RejectsBadInput(t *testing.T) {
	validArgon := &RawNebulaArgon2Parameters{
		Version: 0x13, Memory: 65536, Parallelism: 4, Iterations: 3, Salt: []byte{1, 2, 3, 4},
	}

	missingMetadata, err := proto.Marshal(&RawNebulaEncryptedData{
		Ciphertext: []byte{1, 2, 3},
	})
	require.NoError(t, err)
	missingParams, err := proto.Marshal(&RawNebulaEncryptedData{
		EncryptionMetadata: &RawNebulaEncryptionMetadata{EncryptionAlgorithm: "AES-256-GCM"},
		Ciphertext:         []byte{1, 2, 3},
	})
	require.NoError(t, err)
	valid, err := proto.Marshal(&RawNebulaEncryptedData{
		EncryptionMetadata: &RawNebulaEncryptionMetadata{
			EncryptionAlgorithm: "AES-256-GCM",
			Argon2Parameters:    validArgon,
		},
		Ciphertext: []byte{1, 2, 3},
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		in          []byte
		wantErr     bool
		wantErrPart string
	}{
		{
			name:        "empty bytes rejected",
			in:          nil,
			wantErr:     true,
			wantErrPart: "nil byte array",
		},
		{
			name:        "garbage non-proto bytes rejected",
			in:          []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			wantErr:     true,
			wantErrPart: "", // proto.Unmarshal error wording is libversion-dependent; existence suffices
		},
		{
			name:        "missing EncryptionMetadata rejected",
			in:          missingMetadata,
			wantErr:     true,
			wantErrPart: "encryptionmetadata was nil",
		},
		{
			name:        "missing Argon2Parameters rejected",
			in:          missingParams,
			wantErr:     true,
			wantErrPart: "argon2parameters was nil",
		},
		{
			name: "well-formed input accepted and fields forwarded",
			in:   valid,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnmarshalNebulaEncryptedData(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrPart != "" {
					require.Contains(t, strings.ToLower(err.Error()), tc.wantErrPart)
				}
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, "AES-256-GCM", got.EncryptionMetadata.EncryptionAlgorithm)
			assert.Equal(t, uint32(65536), got.EncryptionMetadata.Argon2Parameters.Memory)
			assert.Equal(t, []byte{1, 2, 3}, got.Ciphertext)
		})
	}
}

func TestSplitNonceCiphertext(t *testing.T) {
	const nonceSize = 12

	tests := []struct {
		name         string
		blob         []byte
		nonceSize    int
		wantErr      bool
		wantNonceLen int
		wantCipher   []byte
	}{
		{
			name:         "blob = nonce + 1 byte ciphertext: smallest valid input",
			blob:         []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0xCC},
			nonceSize:    nonceSize,
			wantNonceLen: nonceSize,
			wantCipher:   []byte{0xCC},
		},
		{
			name:         "blob = nonce + many bytes ciphertext: typical case",
			blob:         append(make([]byte, nonceSize), []byte("ciphertext-payload-bytes")...),
			nonceSize:    nonceSize,
			wantNonceLen: nonceSize,
			wantCipher:   []byte("ciphertext-payload-bytes"),
		},
		{
			name:      "blob exactly nonce length: rejected (no room for ciphertext)",
			blob:      make([]byte, nonceSize),
			nonceSize: nonceSize,
			wantErr:   true,
		},
		{
			name:      "blob shorter than nonce: rejected",
			blob:      make([]byte, nonceSize-1),
			nonceSize: nonceSize,
			wantErr:   true,
		},
		{
			name:      "blob empty: rejected",
			blob:      []byte{},
			nonceSize: nonceSize,
			wantErr:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nonce, ciphertext, err := splitNonceCiphertext(tc.blob, tc.nonceSize)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, nonce)
				assert.Nil(t, ciphertext)
				return
			}
			require.NoError(t, err)
			assert.Len(t, nonce, tc.wantNonceLen)
			assert.Equal(t, tc.wantCipher, ciphertext)
		})
	}
}

func TestDeriveKey_Validation(t *testing.T) {
	const keySize = uint32(32)
	const minSaltBytes = 16
	goodSalt := make([]byte, minSaltBytes)
	for i := range goodSalt {
		goodSalt[i] = byte(i)
	}

	tests := []struct {
		name        string
		params      *Argon2Parameters
		wantErr     bool
		wantErrPart string
	}{
		{
			name: "incompatible argon version is rejected",
			params: &Argon2Parameters{
				version: argon2.Version - 1, Memory: 1, Parallelism: 1, Iterations: 1, salt: goodSalt,
			},
			wantErr:     true,
			wantErrPart: "incompatible argon2 version",
		},
		{
			name: "nil salt is rejected",
			params: &Argon2Parameters{
				version: argon2.Version, Memory: 1, Parallelism: 1, Iterations: 1, salt: nil,
			},
			wantErr:     true,
			wantErrPart: "salt must be set",
		},
		{
			name: "salt below 128 bits is rejected",
			params: &Argon2Parameters{
				version: argon2.Version, Memory: 1, Parallelism: 1, Iterations: 1, salt: make([]byte, minSaltBytes-1),
			},
			wantErr:     true,
			wantErrPart: "at least 128",
		},
		{
			name: "happy path returns a key of the requested size",
			params: &Argon2Parameters{
				version: argon2.Version, Memory: 1, Parallelism: 1, Iterations: 1, salt: goodSalt,
			},
		},
		{
			name: "boundary: exactly 128-bit salt is accepted",
			params: &Argon2Parameters{
				version: argon2.Version, Memory: 1, Parallelism: 1, Iterations: 1, salt: make([]byte, minSaltBytes),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveKey([]byte("passphrase"), keySize, tc.params)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, strings.ToLower(err.Error()), tc.wantErrPart,
					"error message must name the offending field so operators can find it")
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got, int(keySize),
				"happy path must return a key of exactly keySize bytes")
		})
	}
}

func TestAes256Decrypt_RejectsBadInput(t *testing.T) {
	passphrase := []byte("passphrase")
	plaintext := []byte("attack at dawn")
	kdfParams := NewArgon2Parameters(1, 1, 1)

	// Encrypt once so we have a known-valid blob to corrupt.
	validBlob, err := aes256Encrypt(passphrase, kdfParams, plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, validBlob)

	// gcm.NonceSize() returns 12 bytes for AES-GCM. The blob is
	// nonce || ciphertext || tag, so total len > 12.
	const gcmNonceSize = 12
	require.Greater(t, len(validBlob), gcmNonceSize)

	tamperedCiphertext := append([]byte(nil), validBlob...)
	tamperedCiphertext[gcmNonceSize+1] ^= 0x01 // flip a bit in the ciphertext

	tamperedNonce := append([]byte(nil), validBlob...)
	tamperedNonce[0] ^= 0x01 // flip a bit in the nonce

	tests := []struct {
		name        string
		blob        []byte
		passphrase  []byte
		wantErr     bool
		wantErrPart string
	}{
		{
			name:        "empty blob rejected (splitNonceCiphertext)",
			blob:        nil,
			passphrase:  passphrase,
			wantErr:     true,
			wantErrPart: "shorter than nonce length",
		},
		{
			name:        "blob shorter than nonce rejected",
			blob:        []byte{0, 1, 2, 3, 4, 5},
			passphrase:  passphrase,
			wantErr:     true,
			wantErrPart: "shorter than nonce length",
		},
		{
			name:        "blob equal to nonce length rejected (no room for ciphertext)",
			blob:        make([]byte, gcmNonceSize),
			passphrase:  passphrase,
			wantErr:     true,
			wantErrPart: "shorter than nonce length",
		},
		{
			name:        "tampered ciphertext rejected by GCM auth",
			blob:        tamperedCiphertext,
			passphrase:  passphrase,
			wantErr:     true,
			wantErrPart: "invalid passphrase or corrupt private key",
		},
		{
			name:        "tampered nonce rejected by GCM auth",
			blob:        tamperedNonce,
			passphrase:  passphrase,
			wantErr:     true,
			wantErrPart: "invalid passphrase or corrupt private key",
		},
		{
			name:        "wrong passphrase rejected by GCM auth",
			blob:        validBlob,
			passphrase:  []byte("wrong"),
			wantErr:     true,
			wantErrPart: "invalid passphrase or corrupt private key",
		},
		{
			name:       "round-trip with correct passphrase recovers plaintext",
			blob:       validBlob,
			passphrase: passphrase,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Each row gets a fresh params object so any salt mutation
			// inside aes256DeriveKey on the wrong-passphrase row does not
			// leak into other rows. Same minimal params as the outer block.
			rowParams := NewArgon2Parameters(1, 1, 1)
			rowParams.salt = kdfParams.salt
			got, err := aes256Decrypt(tc.passphrase, rowParams, tc.blob)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.wantErrPart))
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, plaintext, got, "round-trip must recover the original plaintext")
		})
	}
}

func TestDecryptAndUnmarshalSigningPrivateKey_AlgorithmAndCurveCases(t *testing.T) {
	passphrase := []byte("passphrase")

	// Build the salt + Argon2 params we'll embed in the proto.
	kdfParams := NewArgon2Parameters(1, 1, 1)
	kdfParams.salt = make([]byte, 32)
	for i := range kdfParams.salt {
		kdfParams.salt[i] = byte(i)
	}
	rawArgon := &RawNebulaArgon2Parameters{
		Version:     kdfParams.version,
		Memory:      kdfParams.Memory,
		Parallelism: uint32(kdfParams.Parallelism),
		Iterations:  kdfParams.Iterations,
		Salt:        kdfParams.salt,
	}

	// Encrypt a 31-byte payload with the P256 banner: aes256Decrypt
	// will succeed (the ciphertext is valid AES-GCM), but the curve-
	// specific length check will fail because P256 expects 32 bytes.
	shortP256Plain := []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") // 31 bytes
	shortP256Cipher, err := aes256Encrypt(passphrase, kdfParams, shortP256Plain)
	require.NoError(t, err)
	shortP256Proto, err := proto.Marshal(&RawNebulaEncryptedData{
		EncryptionMetadata: &RawNebulaEncryptionMetadata{
			EncryptionAlgorithm: "AES-256-GCM",
			Argon2Parameters:    rawArgon,
		},
		Ciphertext: shortP256Cipher,
	})
	require.NoError(t, err)
	shortP256PEM := pem.EncodeToMemory(&pem.Block{
		Type: EncryptedECDSAP256PrivateKeyBanner, Bytes: shortP256Proto,
	})

	// Build a valid-looking proto but with an algorithm we don't
	// support. Decrypt should hit the algorithm-switch default branch.
	unsupportedProto, err := proto.Marshal(&RawNebulaEncryptedData{
		EncryptionMetadata: &RawNebulaEncryptionMetadata{
			EncryptionAlgorithm: "DES-EDE-CBC", // arbitrary unsupported value
			Argon2Parameters:    rawArgon,
		},
		Ciphertext: []byte{1, 2, 3},
	})
	require.NoError(t, err)
	unsupportedPEM := pem.EncodeToMemory(&pem.Block{
		Type: EncryptedEd25519PrivateKeyBanner, Bytes: unsupportedProto,
	})

	tests := []struct {
		name        string
		in          []byte
		wantCurve   Curve
		wantErrPart string
	}{
		{
			name:        "unsupported EncryptionAlgorithm is rejected by the default switch branch",
			in:          unsupportedPEM,
			wantCurve:   Curve_CURVE25519,
			wantErrPart: "unsupported encryption algorithm",
		},
		{
			name:        "P256 banner with wrong-length plaintext is rejected by the curve length check",
			in:          shortP256PEM,
			wantCurve:   Curve_P256,
			wantErrPart: "key was not 32 bytes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			curve, k, rest, err := DecryptAndUnmarshalSigningPrivateKey(passphrase, tc.in)
			require.Error(t, err)
			require.Contains(t, strings.ToLower(err.Error()), tc.wantErrPart)
			assert.Equal(t, tc.wantCurve, curve, "curve must still be set for diagnostics")
			assert.Nil(t, k, "no key bytes returned on the error path")
			assert.Equal(t, []byte{}, rest, "rest must be empty because the single PEM block was consumed")
		})
	}
}
