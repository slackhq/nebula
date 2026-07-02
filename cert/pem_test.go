package cert

import (
	"bufio"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scanAll(t *testing.T, input string) ([]string, error) {
	t.Helper()
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Split(SplitPEM)
	var blocks []string
	for scanner.Scan() {
		blocks = append(blocks, scanner.Text())
	}
	return blocks, scanner.Err()
}

func TestSplitPEM_Single(t *testing.T) {
	input := "-----BEGIN TEST-----\ndata\n-----END TEST-----\n"
	blocks, err := scanAll(t, input)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, input, blocks[0])
}

func TestSplitPEM_Multiple(t *testing.T) {
	block1 := "-----BEGIN TEST-----\naaa\n-----END TEST-----\n"
	block2 := "-----BEGIN TEST-----\nbbb\n-----END TEST-----\n"
	blocks, err := scanAll(t, block1+block2)
	require.NoError(t, err)
	require.Len(t, blocks, 2)
	require.Equal(t, block1, blocks[0])
	require.Equal(t, block2, blocks[1])
}

func TestSplitPEM_CommentsAndWhitespaceBetweenBlocks(t *testing.T) {
	input := "# comment\n\n-----BEGIN TEST-----\naaa\n-----END TEST-----\n\n# another comment\n\n-----BEGIN TEST-----\nbbb\n-----END TEST-----\n"
	blocks, err := scanAll(t, input)
	require.NoError(t, err)
	require.Len(t, blocks, 2)
}

func TestSplitPEM_Empty(t *testing.T) {
	blocks, err := scanAll(t, "")
	require.NoError(t, err)
	require.Empty(t, blocks)
}

func TestSplitPEM_WhitespaceOnly(t *testing.T) {
	blocks, err := scanAll(t, "  \n\t\n  ")
	require.NoError(t, err)
	require.Empty(t, blocks)
}

func TestSplitPEM_TrailingGarbage(t *testing.T) {
	input := "-----BEGIN TEST-----\ndata\n-----END TEST-----\ngarbage"
	blocks, err := scanAll(t, input)
	require.ErrorIs(t, err, ErrTruncatedPEMBlock)
	require.Len(t, blocks, 1)
}

func TestSplitPEM_TruncatedBlock(t *testing.T) {
	input := "-----BEGIN TEST-----\npartial data with no end"
	_, err := scanAll(t, input)
	require.ErrorIs(t, err, ErrTruncatedPEMBlock)
}

func TestSplitPEM_NoEndNewline(t *testing.T) {
	input := "-----BEGIN TEST-----\ndata\n-----END TEST-----"
	blocks, err := scanAll(t, input)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, input, blocks[0])
}

func TestSplitPEM_GarbageOnly(t *testing.T) {
	_, err := scanAll(t, "this is not PEM data")
	require.ErrorIs(t, err, ErrTruncatedPEMBlock)
}

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

	// Fail due to invalid PEM format, because
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

	// Fail due to invalid PEM format, because
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

	// Fail due to invalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, curve, err = UnmarshalPrivateKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

func TestUnmarshalPublicKeyFromPEM(t *testing.T) {
	t.Parallel()
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
	signingKey := []byte(`# A signing key has the wrong scope for this function
-----BEGIN NEBULA ECDSA P256 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA ECDSA P256 PUBLIC KEY-----
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

	keyBundle := appendByteSlices(pubKey, pubP256Key, signingKey, shortKey, invalidBanner, invalidPem)

	// X25519 key
	k, rest, curve, err := UnmarshalPublicKeyFromPEM(keyBundle)
	assert.Len(t, k, 32)
	require.NoError(t, err)
	assert.Equal(t, rest, appendByteSlices(pubP256Key, signingKey, shortKey, invalidBanner, invalidPem))
	assert.Equal(t, Curve_CURVE25519, curve)

	// P256 key
	k, rest, curve, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Len(t, k, 65)
	require.NoError(t, err)
	assert.Equal(t, rest, appendByteSlices(signingKey, shortKey, invalidBanner, invalidPem))
	assert.Equal(t, Curve_P256, curve)

	// Reject a signing public key (Ed25519/ECDSA banner)
	k, rest, _, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))
	require.EqualError(t, err, "bytes did not contain a proper public key banner")

	// Fail due to short key
	k, rest, _, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))
	require.EqualError(t, err, "key was not 32 bytes, is invalid CURVE25519 public key")

	// Fail due to invalid banner
	k, rest, _, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	require.EqualError(t, err, "bytes did not contain a proper public key banner")
	assert.Equal(t, rest, invalidPem)

	// Fail due to invalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, _, err = UnmarshalPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

func TestUnmarshalSigningPublicKeyFromPEM(t *testing.T) {
	t.Parallel()
	pubKey := []byte(`# A good key
-----BEGIN NEBULA ED25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA ED25519 PUBLIC KEY-----
`)
	pubP256Key := []byte(`# A good key
-----BEGIN NEBULA ECDSA P256 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA ECDSA P256 PUBLIC KEY-----
`)
	ecdhKey := []byte(`# A key-agreement key has the wrong scope for this function
-----BEGIN NEBULA X25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA X25519 PUBLIC KEY-----
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

	keyBundle := appendByteSlices(pubKey, pubP256Key, ecdhKey, shortKey, invalidBanner, invalidPem)

	// Ed25519 key
	k, rest, curve, err := UnmarshalSigningPublicKeyFromPEM(keyBundle)
	assert.Len(t, k, 32)
	require.NoError(t, err)
	assert.Equal(t, rest, appendByteSlices(pubP256Key, ecdhKey, shortKey, invalidBanner, invalidPem))
	assert.Equal(t, Curve_CURVE25519, curve)

	// ECDSA P256 key
	k, rest, curve, err = UnmarshalSigningPublicKeyFromPEM(rest)
	assert.Len(t, k, 65)
	require.NoError(t, err)
	assert.Equal(t, rest, appendByteSlices(ecdhKey, shortKey, invalidBanner, invalidPem))
	assert.Equal(t, Curve_P256, curve)

	// Reject a key-agreement public key (X25519/P256 banner)
	k, rest, _, err = UnmarshalSigningPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))
	require.EqualError(t, err, "bytes did not contain a proper Ed25519/ECDSA public key banner")

	// Fail due to short key
	k, rest, _, err = UnmarshalSigningPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))
	require.EqualError(t, err, "key was not 32 bytes, is invalid CURVE25519 public key")

	// Fail due to invalid banner
	k, rest, _, err = UnmarshalSigningPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	require.EqualError(t, err, "bytes did not contain a proper Ed25519/ECDSA public key banner")
	assert.Equal(t, rest, invalidPem)

	// Fail due to invalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, _, err = UnmarshalSigningPublicKeyFromPEM(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	require.EqualError(t, err, "input did not contain a valid PEM encoded block")
}
