package main

import (
	"bytes"
	"crypto/rand"
	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"os"
	"testing"
	"time"
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
	assert := assert.New(t)

	time.Local = time.UTC
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}

	// required args
	assertHelpError(t, verify([]string{"-ca", "derp"}, ob, eb), "-crt is required")
	assert.Equal("", ob.String())
	assert.Equal("", eb.String())

	assertHelpError(t, verify([]string{"-crt", "derp"}, ob, eb), "-ca is required")
	assert.Equal("", ob.String())
	assert.Equal("", eb.String())

	// no ca at path
	ob.Reset()
	eb.Reset()
	err := verify([]string{"-ca", "does_not_exist", "-crt", "does_not_exist"}, ob, eb)
	assert.Equal("", ob.String())
	assert.Equal("", eb.String())
	assert.EqualError(err, "error while reading ca: open does_not_exist: "+NoSuchFileError)

	// invalid ca at path
	ob.Reset()
	eb.Reset()
	caFile, err := ioutil.TempFile("", "verify-ca")
	assert.NoError(err, "ioutil.TempFile")
	defer os.Remove(caFile.Name())

	_, err = caFile.WriteString("-----BEGIN NOPE-----")
	assert.NoError(err, "WriteString")
	err = verify([]string{"-ca", caFile.Name(), "-crt", "does_not_exist"}, ob, eb)
	assert.Equal("", ob.String())
	assert.Equal("", eb.String())
	assert.EqualError(err, "error while adding ca cert to pool: input did not contain a valid PEM encoded block")

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
	err = ca.Sign(caPriv)
	assert.NoError(err, "ca.Sign")
	marshalPEM(t, ca, caFile)

	// no crt at path
	err = verify([]string{"-ca", caFile.Name(), "-crt", "does_not_exist"}, ob, eb)
	assert.Equal("", ob.String())
	assert.Equal("", eb.String())
	assert.EqualError(err, "unable to read crt; open does_not_exist: "+NoSuchFileError)

	// invalid crt at path
	ob.Reset()
	eb.Reset()
	certFile, err := ioutil.TempFile("", "verify-cert")
	assert.NoError(err)
	defer os.Remove(certFile.Name())

	_, err = certFile.WriteString("-----BEGIN NOPE-----")
	assert.NoError(err, "certFile.WriteString")
	err = verify([]string{"-ca", caFile.Name(), "-crt", certFile.Name()}, ob, eb)
	assert.Equal("", ob.String())
	assert.Equal("", eb.String())
	assert.EqualError(err, "error while parsing crt: input did not contain a valid PEM encoded block")

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

	err = crt.Sign(badPriv)
	assert.NoError(err, "crt.Sign")
	marshalPEM(t, crt, certFile)

	err = verify([]string{"-ca", caFile.Name(), "-crt", certFile.Name()}, ob, eb)
	assert.Equal("", ob.String())
	assert.Equal("", eb.String())
	assert.EqualError(err, "certificate signature did not match")

	// verified cert at path
	err = crt.Sign(caPriv)
	assert.NoError(err, "crt.Sign")
	marshalPEM(t, crt, certFile)

	err = verify([]string{"-ca", caFile.Name(), "-crt", certFile.Name()}, ob, eb)
	assert.Equal("", ob.String())
	assert.Equal("", eb.String())
	assert.NoError(err)
}

func marshalPEM(t *testing.T, crt cert.NebulaCertificate, f *os.File) {
	b, err := crt.MarshalToPEM()
	assert.NoError(t, err, "crt.MarshalToPEM")
	err = f.Truncate(0)
	assert.NoError(t, err, "certFile.Truncate")
	_, err = f.Seek(0, 0)
	assert.NoError(t, err, "certFile.Seek")
	_, err = f.Write(b)
	assert.NoError(t, err, "certFile.Write")
}
