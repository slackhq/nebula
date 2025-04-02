package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	assertHelpError(t, verify([]string{"-crt", "derp"}, ob, eb), "-ca is required")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// no ca at path
	ob.Reset()
	eb.Reset()
	err := verify([]string{"-ca", "does_not_exist", "-crt", "does_not_exist"}, ob, eb)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	require.EqualError(t, err, "error while reading ca: open does_not_exist: "+NoSuchFileError)

	// invalid ca at path
	ob.Reset()
	eb.Reset()
	caFile, err := os.CreateTemp("", "verify-ca")
	require.NoError(t, err)
	defer os.Remove(caFile.Name())

	caFile.WriteString("-----BEGIN NOPE-----")
	err = verify([]string{"-ca", caFile.Name(), "-crt", "does_not_exist"}, ob, eb)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	require.EqualError(t, err, "error while adding ca cert to pool: input did not contain a valid PEM encoded block")

	// make a ca for later
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := NewTestCaCert("test-ca", caPub, caPriv, time.Now().Add(time.Hour*-1), time.Now().Add(time.Hour*2), nil, nil, nil)
	b, _ := ca.MarshalPEM()
	caFile.Truncate(0)
	caFile.Seek(0, 0)
	caFile.Write(b)

	// no crt at path
	err = verify([]string{"-ca", caFile.Name(), "-crt", "does_not_exist"}, ob, eb)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	require.EqualError(t, err, "unable to read crt: open does_not_exist: "+NoSuchFileError)

	// invalid crt at path
	ob.Reset()
	eb.Reset()
	certFile, err := os.CreateTemp("", "verify-cert")
	require.NoError(t, err)
	defer os.Remove(certFile.Name())

	certFile.WriteString("-----BEGIN NOPE-----")
	err = verify([]string{"-ca", caFile.Name(), "-crt", certFile.Name()}, ob, eb)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	require.EqualError(t, err, "error while parsing crt: input did not contain a valid PEM encoded block")

	// unverifiable cert at path
	crt, _ := NewTestCert(ca, caPriv, "test-cert", time.Now().Add(time.Hour*-1), time.Now().Add(time.Hour), nil, nil, nil)
	// Slightly evil hack to modify the certificate after it was sealed to generate an invalid signature
	pub := crt.PublicKey()
	for i, _ := range pub {
		pub[i] = 0
	}
	b, _ = crt.MarshalPEM()
	certFile.Truncate(0)
	certFile.Seek(0, 0)
	certFile.Write(b)

	err = verify([]string{"-ca", caFile.Name(), "-crt", certFile.Name()}, ob, eb)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	require.ErrorIs(t, err, cert.ErrSignatureMismatch)

	// verified cert at path
	crt, _ = NewTestCert(ca, caPriv, "test-cert", time.Now().Add(time.Hour*-1), time.Now().Add(time.Hour), nil, nil, nil)
	b, _ = crt.MarshalPEM()
	certFile.Truncate(0)
	certFile.Seek(0, 0)
	certFile.Write(b)

	err = verify([]string{"-ca", caFile.Name(), "-crt", certFile.Name()}, ob, eb)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	require.NoError(t, err)
}
