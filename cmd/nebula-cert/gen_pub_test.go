package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
)

//TODO: test file permissions

func Test_genPubSummary(t *testing.T) {
	assert.Equal(t, "gen-pub <flags>: prints the public key given the private key", genPubSummary())
}

func Test_genPubHelp(t *testing.T) {
	ob := &bytes.Buffer{}
	genPubHelp(ob)
	assert.Equal(
		t,
		"Usage of "+os.Args[0]+" gen-pub <flags>: prints the public key given the private key\n"+
			"  -in-key string\n"+
			"    \tRequired: path to read the private key from\n"+
			"  -out-pub string\n"+
			"    \tOptional: path to write the public key to\n",
		ob.String(),
	)
}

func Test_genPub(t *testing.T) {
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}
	// gb := &bytes.Buffer{}

	// required args
	assertHelpError(t, genPub([]string{"-out-pub", "some-key"}, ob, eb), "-in-key is required")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// create temp key file
	keyF, err := ioutil.TempFile("", "test.key")
	assert.Nil(t, err)
	defer os.Remove(keyF.Name())

	// create temp pub file
	pubF, err := ioutil.TempFile("", "test.pub")
	assert.Nil(t, err)
	defer os.Remove(pubF.Name())

	ob.Reset()
	eb.Reset()
	args := []string{"-out-pub", pubF.Name(), "-out-key", keyF.Name()}
	assert.Nil(t, keygen(args, ob, eb))

	// read key file
	rb, _ := ioutil.ReadFile(keyF.Name())
	lKey, b, err := cert.UnmarshalX25519PrivateKey(rb)
	assert.Len(t, b, 0)
	assert.Nil(t, err)
	assert.Len(t, lKey, 32)

	// read public key
	pb, _ := ioutil.ReadFile(pubF.Name())
	rKey, b, err := cert.UnmarshalX25519PublicKey(pb)
	assert.Len(t, b, 0)
	assert.Nil(t, err)
	assert.Len(t, rKey, 32)

	ob.Reset()
	eb.Reset()

	// create temp pub file for genPub public key
	genPubF, err := ioutil.TempFile("", "gen.pub")
	assert.Nil(t, err)
	defer os.Remove(genPubF.Name())

	genPub([]string{"-in-key", keyF.Name(), "-out-pub", genPubF.Name()}, ob, eb)
	genPub, _ := ioutil.ReadFile(genPubF.Name())

	assert.Equal(t, pb, genPub)
}
