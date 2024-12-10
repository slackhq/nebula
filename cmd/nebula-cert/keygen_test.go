package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
)

//TODO: test file permissions

func Test_keygenSummary(t *testing.T) {
	assert.Equal(t, "keygen <flags>: create a public/private key pair. the public key can be passed to `nebula-cert sign`", keygenSummary())
}

func Test_keygenHelp(t *testing.T) {
	ob := &bytes.Buffer{}
	keygenHelp(ob)
	assert.Equal(
		t,
		"Usage of "+os.Args[0]+" keygen <flags>: create a public/private key pair. the public key can be passed to `nebula-cert sign`\n"+
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
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	assertHelpError(t, keygen([]string{"-out-key", "nope"}, ob, eb), "-out-pub is required")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// failed key write
	ob.Reset()
	eb.Reset()
	args := []string{"-out-pub", "/do/not/write/pleasepub", "-out-key", "/do/not/write/pleasekey"}
	assert.EqualError(t, keygen(args, ob, eb), "error while writing out-key: open /do/not/write/pleasekey: "+NoSuchDirError)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// create temp key file
	keyF, err := os.CreateTemp("", "test.key")
	assert.Nil(t, err)
	defer os.Remove(keyF.Name())

	// failed pub write
	ob.Reset()
	eb.Reset()
	args = []string{"-out-pub", "/do/not/write/pleasepub", "-out-key", keyF.Name()}
	assert.EqualError(t, keygen(args, ob, eb), "error while writing out-pub: open /do/not/write/pleasepub: "+NoSuchDirError)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// create temp pub file
	pubF, err := os.CreateTemp("", "test.pub")
	assert.Nil(t, err)
	defer os.Remove(pubF.Name())

	// test proper keygen
	ob.Reset()
	eb.Reset()
	args = []string{"-out-pub", pubF.Name(), "-out-key", keyF.Name()}
	assert.Nil(t, keygen(args, ob, eb))
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// read cert and key files
	rb, _ := os.ReadFile(keyF.Name())
	lKey, b, curve, err := cert.UnmarshalPrivateKeyFromPEM(rb)
	assert.Equal(t, cert.Curve_CURVE25519, curve)
	assert.Len(t, b, 0)
	assert.Nil(t, err)
	assert.Len(t, lKey, 32)

	rb, _ = os.ReadFile(pubF.Name())
	lPub, b, curve, err := cert.UnmarshalPublicKeyFromPEM(rb)
	assert.Equal(t, cert.Curve_CURVE25519, curve)
	assert.Len(t, b, 0)
	assert.Nil(t, err)
	assert.Len(t, lPub, 32)
}
