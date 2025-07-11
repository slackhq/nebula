package cert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalCertificateFromPEM(t *testing.T) {
	goodCert := []byte(`
# A good cert
-----BEGIN NEBULA CERTIFICATE-----
CkAKDm5lYnVsYSByb290IGNhKJfap9AFMJfg1+YGOiCUQGByMuNRhIlQBOyzXWbL
vcKBwDhov900phEfJ5DN3kABEkDCq5R8qBiu8sl54yVfgRcQXEDt3cHr8UTSLszv
bzBEr00kERQxxTzTsH8cpYEgRoipvmExvg8WP8NdAJEYJosB
-----END NEBULA CERTIFICATE-----
`)
	badBanner := []byte(`# A bad banner
-----BEGIN NOT A NEBULA CERTIFICATE-----
CkAKDm5lYnVsYSByb290IGNhKJfap9AFMJfg1+YGOiCUQGByMuNRhIlQBOyzXWbL
vcKBwDhov900phEfJ5DN3kABEkDCq5R8qBiu8sl54yVfgRcQXEDt3cHr8UTSLszv
bzBEr00kERQxxTzTsH8cpYEgRoipvmExvg8WP8NdAJEYJosB
-----END NOT A NEBULA CERTIFICATE-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA CERTIFICATE-----
CkAKDm5lYnVsYSByb290IGNhKJfap9AFMJfg1+YGOiCUQGByMuNRhIlQBOyzXWbL
vcKBwDhov900phEfJ5DN3kABEkDCq5R8qBiu8sl54yVfgRcQXEDt3cHr8UTSLszv
bzBEr00kERQxxTzTsH8cpYEgRoipvmExvg8WP8NdAJEYJosB
-END NEBULA CERTIFICATE----`)

	certBundle := appendByteSlices(goodCert, badBanner, invalidPem)

	// Success test case
	cert, rest, err := UnmarshalCertificateFromPEM(certBundle)
	assert.NotNil(t, cert)
	assert.Equal(t, rest, append(badBanner, invalidPem...))
	require.NoError(t, err)

	// Fail due to invalid banner.
	cert, rest, err = UnmarshalCertificateFromPEM(rest)
	assert.Nil(t, cert)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "bytes did not contain a proper certificate banner")

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	cert, rest, err = UnmarshalCertificateFromPEM(rest)
	assert.Nil(t, cert)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

func TestUnmarshalSigningPrivateKeyFromPEM(t *testing.T) {
	privKey := []byte(`# A good key
-----BEGIN NEBULA ED25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END NEBULA ED25519 PRIVATE KEY-----
`)
	privP256Key := []byte(`# A good key
-----BEGIN NEBULA ECDSA P256 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA ECDSA P256 PRIVATE KEY-----
`)
	shortKey := []byte(`# A short key
-----BEGIN NEBULA ED25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END NEBULA ED25519 PRIVATE KEY-----
`)
	invalidBanner := []byte(`# Invalid banner
-----BEGIN NOT A NEBULA PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END NOT A NEBULA PRIVATE KEY-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA ED25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-END NEBULA ED25519 PRIVATE KEY-----`)

	keyBundle := appendByteSlices(privKey, privP256Key, shortKey, invalidBanner, invalidPem)

	// Success test case
	k, rest, curve, err := UnmarshalSigningPrivateKeyFromPEM(keyBundle)
	assert.Len(t, k, 64)
	assert.Equal(t, rest, appendByteSlices(privP256Key, shortKey, invalidBanner, invalidPem))
	assert.Equal(t, Curve_CURVE25519, curve)
	require.NoError(t, err)

	// Success test case
	k, rest, curve, err = UnmarshalSigningPrivateKeyFromPEM(rest)
	assert.Len(t, k, 32)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))
	assert.Equal(t, Curve_P256, curve)
	require.NoError(t, err)

	// Fail due to short key
	k, rest, curve, err = UnmarshalSigningPrivateKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))
	require.EqualError(t, err, "key was not 64 bytes, is invalid Ed25519 private key")

	// Fail due to invalid banner
	k, rest, curve, err = UnmarshalSigningPrivateKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "bytes did not contain a proper Ed25519/ECDSA private key banner")

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, curve, err = UnmarshalSigningPrivateKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

func TestUnmarshalPrivateKeyFromPEM(t *testing.T) {
	privKey := []byte(`# A good key
-----BEGIN NEBULA X25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA X25519 PRIVATE KEY-----
`)
	privP256Key := []byte(`# A good key
-----BEGIN NEBULA P256 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA P256 PRIVATE KEY-----
`)
	shortKey := []byte(`# A short key
-----BEGIN NEBULA X25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END NEBULA X25519 PRIVATE KEY-----
`)
	invalidBanner := []byte(`# Invalid banner
-----BEGIN NOT A NEBULA PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NOT A NEBULA PRIVATE KEY-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA X25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-END NEBULA X25519 PRIVATE KEY-----`)

	keyBundle := appendByteSlices(privKey, privP256Key, shortKey, invalidBanner, invalidPem)

	// Success test case
	k, rest, curve, err := UnmarshalPrivateKeyFromPEM(keyBundle)
	assert.Len(t, k, 32)
	assert.Equal(t, rest, appendByteSlices(privP256Key, shortKey, invalidBanner, invalidPem))
	assert.Equal(t, Curve_CURVE25519, curve)
	require.NoError(t, err)

	// Success test case
	k, rest, curve, err = UnmarshalPrivateKeyFromPEM(rest)
	assert.Len(t, k, 32)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))
	assert.Equal(t, Curve_P256, curve)
	require.NoError(t, err)

	// Fail due to short key
	k, rest, curve, err = UnmarshalPrivateKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))
	require.EqualError(t, err, "key was not 32 bytes, is invalid CURVE25519 private key")

	// Fail due to invalid banner
	k, rest, curve, err = UnmarshalPrivateKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "bytes did not contain a proper private key banner")

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, curve, err = UnmarshalPrivateKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

func TestUnmarshalPublicKeyFromPEM(t *testing.T) {
	pubKey := []byte(`# A good key
-----BEGIN NEBULA ED25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA ED25519 PUBLIC KEY-----
`)
	shortKey := []byte(`# A short key
-----BEGIN NEBULA ED25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END NEBULA ED25519 PUBLIC KEY-----
`)
	invalidBanner := []byte(`# Invalid banner
-----BEGIN NOT A NEBULA PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NOT A NEBULA PUBLIC KEY-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA ED25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-END NEBULA ED25519 PUBLIC KEY-----`)

	keyBundle := appendByteSlices(pubKey, shortKey, invalidBanner, invalidPem)

	// Success test case
	k, rest, curve, err := UnmarshalPublicKeyFromPEM(keyBundle)
	assert.Len(t, k, 32)
	assert.Equal(t, Curve_CURVE25519, curve)
	require.NoError(t, err)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))

	// Fail due to short key
	k, rest, curve, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, Curve_CURVE25519, curve)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))
	require.EqualError(t, err, "key was not 32 bytes, is invalid CURVE25519 public key")

	// Fail due to invalid banner
	k, rest, curve, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, Curve_CURVE25519, curve)
	require.EqualError(t, err, "bytes did not contain a proper public key banner")
	assert.Equal(t, rest, invalidPem)

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, curve, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, Curve_CURVE25519, curve)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

func TestUnmarshalX25519PublicKey(t *testing.T) {
	pubKey := []byte(`# A good key
-----BEGIN NEBULA X25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA X25519 PUBLIC KEY-----
`)
	pubP256Key := []byte(`# A good key
-----BEGIN NEBULA P256 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA P256 PUBLIC KEY-----
`)
	shortKey := []byte(`# A short key
-----BEGIN NEBULA X25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END NEBULA X25519 PUBLIC KEY-----
`)
	invalidBanner := []byte(`# Invalid banner
-----BEGIN NOT A NEBULA PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NOT A NEBULA PUBLIC KEY-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA X25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-END NEBULA X25519 PUBLIC KEY-----`)

	keyBundle := appendByteSlices(pubKey, pubP256Key, shortKey, invalidBanner, invalidPem)

	// Success test case
	k, rest, curve, err := UnmarshalPublicKeyFromPEM(keyBundle)
	assert.Len(t, k, 32)
	require.NoError(t, err)
	assert.Equal(t, rest, appendByteSlices(pubP256Key, shortKey, invalidBanner, invalidPem))
	assert.Equal(t, Curve_CURVE25519, curve)

	// Success test case
	k, rest, curve, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Len(t, k, 65)
	require.NoError(t, err)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))
	assert.Equal(t, Curve_P256, curve)

	// Fail due to short key
	k, rest, curve, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))
	require.EqualError(t, err, "key was not 32 bytes, is invalid CURVE25519 public key")

	// Fail due to invalid banner
	k, rest, curve, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	require.EqualError(t, err, "bytes did not contain a proper public key banner")
	assert.Equal(t, rest, invalidPem)

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, curve, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "input did not contain a valid PEM encoded block")
}
