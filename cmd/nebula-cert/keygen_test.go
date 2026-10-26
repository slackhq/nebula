package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_keygenSummary(t *testing.T) {
	assert.Equal(t, "keygen <flags>: create a public/private key pair. the public key can be passed to `nebula-cert sign`", keygenSummary())
}

func Test_keygenHelp(t *testing.T) {
	ob := &bytes.Buffer{}
	keygenHelp(ob)
	assert.Equal(
		t,
		"Usage of "+os.Args[0]+" keygen <flags>: create a public/private key pair. the public key can be passed to `nebula-cert sign`\n"+
			"  Pass \"-\" to any path flag to read from stdin or write to stdout.\n"+
			"  -curve string\n"+
			"    \tECDH Curve (25519, P256) (default \"25519\")\n"+
			"  -out-key string\n"+
			"    \tRequired: path to write the private key to\n"+
			"  -out-pub string\n"+
			"    \tRequired: path to write the public key to\n"+
			optionalPkcs11String("  -pkcs11 string\n    \tOptional: PKCS#11 URI to an existing private key\n"),
		ob.String(),
	)
}

func Test_keygen(t *testing.T) {
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}

	// required args
	assertHelpError(t, keygen([]string{"-out-pub", "nope"}, ob, eb), "-out-key is required")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	assertHelpError(t, keygen([]string{"-out-key", "nope"}, ob, eb), "-out-pub is required")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// failed key write
	ob.Reset()
	eb.Reset()
	args := []string{"-out-pub", "/do/not/write/pleasepub", "-out-key", "/do/not/write/pleasekey"}
	require.EqualError(t, keygen(args, ob, eb), "error while writing out-key: open /do/not/write/pleasekey: "+NoSuchDirError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")

	// failed pub write
	ob.Reset()
	eb.Reset()
	args = []string{"-out-pub", "/do/not/write/pleasepub", "-out-key", keyPath}
	require.EqualError(t, keygen(args, ob, eb), "error while writing out-pub: open /do/not/write/pleasepub: "+NoSuchDirError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// test proper keygen
	require.NoError(t, os.Remove(keyPath))
	ob.Reset()
	eb.Reset()
	args = []string{"-out-pub", pubPath, "-out-key", keyPath}
	require.NoError(t, keygen(args, ob, eb))
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// read cert and key files
	rb, _ := os.ReadFile(keyPath)
	lKey, b, curve, err := cert.UnmarshalPrivateKeyFromPEM(rb)
	assert.Equal(t, cert.Curve_CURVE25519, curve)
	assert.Empty(t, b)
	require.NoError(t, err)
	assert.Len(t, lKey, 32)

	rb, _ = os.ReadFile(pubPath)
	lPub, b, curve, err := cert.UnmarshalPublicKeyFromPEM(rb)
	assert.Equal(t, cert.Curve_CURVE25519, curve)
	assert.Empty(t, b)
	require.NoError(t, err)
	assert.Len(t, lPub, 32)

	// test that we won't overwrite existing key or pub files
	keyBefore, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.EqualError(t, keygen(args, ob, eb), "refusing to overwrite existing key: "+keyPath)
	keyAfter, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, keyBefore, keyAfter)

	require.NoError(t, os.Remove(keyPath))
	require.EqualError(t, keygen(args, ob, eb), "refusing to overwrite existing public key: "+pubPath)
	_, err = os.Stat(keyPath)
	assert.True(t, os.IsNotExist(err), "key must not be written when pub is refused")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
}

func Test_keygen_stdio(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")

	// out-pub on stdout, out-key on disk
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}
	require.NoError(t, keygen([]string{"-out-pub", "-", "-out-key", keyPath}, ob, eb))
	assert.Empty(t, eb.String())
	lPub, _, curve, err := cert.UnmarshalPublicKeyFromPEM(ob.Bytes())
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_CURVE25519, curve)
	assert.Len(t, lPub, 32)

	// out-key on stdout, out-pub on disk
	require.NoError(t, os.Remove(keyPath))
	ob.Reset()
	eb.Reset()
	require.NoError(t, keygen([]string{"-out-pub", pubPath, "-out-key", "-"}, ob, eb))
	assert.Empty(t, eb.String())
	lKey, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(ob.Bytes())
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_CURVE25519, curve)
	assert.Len(t, lKey, 32)

	// both on stdout is a conflict caught up front
	ob.Reset()
	eb.Reset()
	require.EqualError(t, keygen([]string{"-out-pub", "-", "-out-key", "-"}, ob, eb),
		`-out-key and -out-pub both set to "-", only one output may write to stdout`)
	assert.Empty(t, ob.String())
}
