package cert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/argon2"
)

func TestNewArgon2Parameters(t *testing.T) {
	p := NewArgon2Parameters(64*1024, 4, 3)
	assert.EqualValues(t, &Argon2Parameters{
		version:     argon2.Version,
		Memory:      64 * 1024,
		Parallelism: 4,
		Iterations:  3,
	}, p)
	p = NewArgon2Parameters(2*1024*1024, 2, 1)
	assert.EqualValues(t, &Argon2Parameters{
		version:     argon2.Version,
		Memory:      2 * 1024 * 1024,
		Parallelism: 2,
		Iterations:  1,
	}, p)
}

func TestDecryptAndUnmarshalSigningPrivateKey(t *testing.T) {
	passphrase := []byte("DO NOT USE THIS KEY")
	privKey := []byte(`# A good key
-----BEGIN NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
CjwKC0FFUy0yNTYtR0NNEi0IExCAgIABGAEgBCognnjujd67Vsv99p22wfAjQaDT
oCMW1mdjkU3gACKNW4MSXOWR9Sts4C81yk1RUku2gvGKs3TB9LYoklLsIizSYOLl
+Vs//O1T0I1Xbml2XBAROsb/VSoDln/6LMqR4B6fn6B3GOsLBBqRI8daDl9lRMPB
qrlJ69wer3ZUHFXA
-----END NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
`)
	shortKey := []byte(`# A key which, once decrypted, is too short
-----BEGIN NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
CjwKC0FFUy0yNTYtR0NNEi0IExCAgIABGAEgBCoga5h8owMEBWRSMMJKzuUvWce7
k0qlBkQmCxiuLh80MuASW70YcKt8jeEIS2axo2V6zAKA9TSMcCsJW1kDDXEtL/xe
GLF5T7sDl5COp4LU3pGxpV+KoeQ/S3gQCAAcnaOtnJQX+aSDnbO3jCHyP7U9CHbs
rQr3bdH3Oy/WiYU=
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
	assert.Nil(t, err)
	assert.Equal(t, Curve_CURVE25519, curve)
	assert.Len(t, k, 64)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))

	// Fail due to short key
	curve, k, rest, err = DecryptAndUnmarshalSigningPrivateKey(passphrase, rest)
	assert.EqualError(t, err, "key was not 64 bytes, is invalid ed25519 private key")
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))

	// Fail due to invalid banner
	curve, k, rest, err = DecryptAndUnmarshalSigningPrivateKey(passphrase, rest)
	assert.EqualError(t, err, "bytes did not contain a proper nebula encrypted Ed25519/ECDSA private key banner")
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	curve, k, rest, err = DecryptAndUnmarshalSigningPrivateKey(passphrase, rest)
	assert.EqualError(t, err, "input did not contain a valid PEM encoded block")
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)

	// Fail due to invalid passphrase
	curve, k, rest, err = DecryptAndUnmarshalSigningPrivateKey([]byte("invalid passphrase"), privKey)
	assert.EqualError(t, err, "invalid passphrase or corrupt private key")
	assert.Nil(t, k)
	assert.Equal(t, rest, []byte{})
}

func TestEncryptAndMarshalSigningPrivateKey(t *testing.T) {
	// Having proved that decryption works correctly above, we can test the
	// encryption function produces a value which can be decrypted
	passphrase := []byte("passphrase")
	bytes := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	kdfParams := NewArgon2Parameters(64*1024, 4, 3)
	key, err := EncryptAndMarshalSigningPrivateKey(Curve_CURVE25519, bytes, passphrase, kdfParams)
	assert.Nil(t, err)

	// Verify the "key" can be decrypted successfully
	curve, k, rest, err := DecryptAndUnmarshalSigningPrivateKey(passphrase, key)
	assert.Len(t, k, 64)
	assert.Equal(t, Curve_CURVE25519, curve)
	assert.Equal(t, rest, []byte{})
	assert.Nil(t, err)

	// EncryptAndMarshalEd25519PrivateKey does not create any errors itself
}
