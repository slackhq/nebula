package main

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func Test_verifySummary(t *testing.T) {
	assert.Equal(t, "verify <flags>: verifies a certificate isn't expired and was signed by a trusted authority.", verifySummary())
}

func Test_verifyHelp(t *testing.T) {
	ob := &bytes.Buffer{}
	verifyHelp(ob)
	assert.Equal(
		t,
		"Usage of "+os.Args[0]+" verify <flags>: verifies a certificate isn't expired and was signed by a trusted authority.\n"+
			"  -ca string\n"+
			"    \tRequired: path to a file containing one or more ca certificates\n"+
			"  -crt string\n"+
			"    \tRequired: path to a file containing a single certificate\n",
		ob.String(),
	)
}

func Test_verify(t *testing.T) {
	time.Local = time.UTC
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}

	// required args
	assertHelpError(t, verify([]string{"-ca", "derp"}, ob, eb), "-crt is required")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	assertHelpError(t, verify([]string{"-crt", "derp"}, ob, eb), "-ca is required")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// no ca at path
	ob.Reset()
	eb.Reset()
	err := verify([]string{"-ca", "does_not_exist", "-crt", "does_not_exist"}, ob, eb)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	assert.EqualError(t, err, "error while reading ca: open does_not_exist: "+NoSuchFileError)

	// invalid ca at path
	ob.Reset()
	eb.Reset()
	caFile, err := ioutil.TempFile("", "verify-ca")
	assert.Nil(t, err)
	defer os.Remove(caFile.Name())

	caFile.WriteString("-----BEGIN NOPE-----")
	err = verify([]string{"-ca", caFile.Name(), "-crt", "does_not_exist"}, ob, eb)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	assert.EqualError(t, err, "error while adding ca cert to pool: input did not contain a valid PEM encoded block")

	// make a ca for later
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      "test-ca",
			NotBefore: time.Now().Add(time.Hour * -1),
			NotAfter:  time.Now().Add(time.Hour),
			PublicKey: caPub,
			IsCA:      true,
		},
	}
	ca.Sign(caPriv)
	b, _ := ca.MarshalToPEM()
	caFile.Truncate(0)
	caFile.Seek(0, 0)
	caFile.Write(b)

	// no crt at path
	err = verify([]string{"-ca", caFile.Name(), "-crt", "does_not_exist"}, ob, eb)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	assert.EqualError(t, err, "unable to read crt; open does_not_exist: "+NoSuchFileError)

	// invalid crt at path
	ob.Reset()
	eb.Reset()
	certFile, err := ioutil.TempFile("", "verify-cert")
	assert.Nil(t, err)
	defer os.Remove(certFile.Name())

	certFile.WriteString("-----BEGIN NOPE-----")
	err = verify([]string{"-ca", caFile.Name(), "-crt", certFile.Name()}, ob, eb)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	assert.EqualError(t, err, "error while parsing crt: input did not contain a valid PEM encoded block")

	// unverifiable cert at path
	_, badPriv, _ := ed25519.GenerateKey(rand.Reader)
	certPub, _ := x25519Keypair()
	signer, _ := ca.Sha256Sum()
	crt := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      "test-cert",
			NotBefore: time.Now().Add(time.Hour * -1),
			NotAfter:  time.Now().Add(time.Hour),
			PublicKey: certPub,
			IsCA:      false,
			Issuer:    signer,
		},
	}

	crt.Sign(badPriv)
	b, _ = crt.MarshalToPEM()
	certFile.Truncate(0)
	certFile.Seek(0, 0)
	certFile.Write(b)

	err = verify([]string{"-ca", caFile.Name(), "-crt", certFile.Name()}, ob, eb)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	assert.EqualError(t, err, "certificate signature did not match")

	// verified cert at path
	crt.Sign(caPriv)
	b, _ = crt.MarshalToPEM()
	certFile.Truncate(0)
	certFile.Seek(0, 0)
	certFile.Write(b)

	err = verify([]string{"-ca", caFile.Name(), "-crt", certFile.Name()}, ob, eb)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	assert.Nil(t, err)
}
