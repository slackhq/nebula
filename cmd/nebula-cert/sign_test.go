//go:build !windows
// +build !windows

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func Test_signSummary(t *testing.T) {
	assert.Equal(t, "sign <flags>: create and sign a certificate", signSummary())
}

func Test_signHelp(t *testing.T) {
	ob := &bytes.Buffer{}
	signHelp(ob)
	assert.Equal(
		t,
		"Usage of "+os.Args[0]+" sign <flags>: create and sign a certificate\n"+
			"  -ca-crt string\n"+
			"    \tOptional: path to the signing CA cert (default \"ca.crt\")\n"+
			"  -ca-key string\n"+
			"    \tOptional: path to the signing CA key (default \"ca.key\")\n"+
			"  -duration duration\n"+
			"    \tOptional: how long the cert should be valid for. The default is 1 second before the signing cert expires. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\"\n"+
			"  -groups string\n"+
			"    \tOptional: comma separated list of groups\n"+
			"  -in-pub string\n"+
			"    \tOptional (if out-key not set): path to read a previously generated public key\n"+
			"  -ip string\n"+
			"    \tDeprecated, see -networks\n"+
			"  -name string\n"+
			"    \tRequired: name of the cert, usually a hostname\n"+
			"  -networks string\n"+
			"    \tRequired: comma separated list of ip address and network in CIDR notation to assign to this cert\n"+
			"  -out-crt string\n"+
			"    \tOptional: path to write the certificate to\n"+
			"  -out-key string\n"+
			"    \tOptional (if in-pub not set): path to write the private key to\n"+
			"  -out-qr string\n"+
			"    \tOptional: output a qr code image (png) of the certificate\n"+
			optionalPkcs11String("  -pkcs11 string\n    \tOptional: PKCS#11 URI to an existing private key\n")+
			"  -subnets string\n"+
			"    \tDeprecated, see -unsafe-networks\n"+
			"  -unsafe-networks string\n"+
			"    \tOptional: comma separated list of ip address and network in CIDR notation. Unsafe networks this cert can route for\n"+
			"  -version uint\n"+
			"    \tOptional: version of the certificate format to use. The default is to match the version of the signing CA\n",
		ob.String(),
	)
}

func Test_signCert(t *testing.T) {
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}

	nopw := &StubPasswordReader{
		password: []byte(""),
		err:      nil,
	}

	errpw := &StubPasswordReader{
		password: []byte(""),
		err:      errors.New("stub error"),
	}

	passphrase := []byte("DO NOT USE THIS KEY")
	testpw := &StubPasswordReader{
		password: passphrase,
		err:      nil,
	}

	// required args
	assertHelpError(t, signCert(
		[]string{"-version", "1", "-ca-crt", "./nope", "-ca-key", "./nope", "-ip", "1.1.1.1/24", "-out-key", "nope", "-out-crt", "nope"}, ob, eb, nopw,
	), "-name is required")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	assertHelpError(t, signCert(
		[]string{"-version", "1", "-ca-crt", "./nope", "-ca-key", "./nope", "-name", "test", "-out-key", "nope", "-out-crt", "nope"}, ob, eb, nopw,
	), "-networks is required")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// cannot set -in-pub and -out-key
	assertHelpError(t, signCert(
		[]string{"-version", "1", "-ca-crt", "./nope", "-ca-key", "./nope", "-name", "test", "-in-pub", "nope", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope"}, ob, eb, nopw,
	), "cannot set both -in-pub and -out-key")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// failed to read key
	ob.Reset()
	eb.Reset()
	args := []string{"-version", "1", "-ca-crt", "./nope", "-ca-key", "./nope", "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "error while reading ca-key: open ./nope: "+NoSuchFileError)

	// failed to unmarshal key
	ob.Reset()
	eb.Reset()
	caKeyF, err := os.CreateTemp("", "sign-cert.key")
	require.NoError(t, err)
	defer os.Remove(caKeyF.Name())

	args = []string{"-version", "1", "-ca-crt", "./nope", "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "error while parsing ca-key: input did not contain a valid PEM encoded block")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// Write a proper ca key for later
	ob.Reset()
	eb.Reset()
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caKeyF.Write(cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, caPriv))

	// failed to read cert
	args = []string{"-version", "1", "-ca-crt", "./nope", "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "error while reading ca-crt: open ./nope: "+NoSuchFileError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// failed to unmarshal cert
	ob.Reset()
	eb.Reset()
	caCrtF, err := os.CreateTemp("", "sign-cert.crt")
	require.NoError(t, err)
	defer os.Remove(caCrtF.Name())

	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "error while parsing ca-crt: input did not contain a valid PEM encoded block")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// write a proper ca cert for later
	ca, _ := NewTestCaCert("ca", caPub, caPriv, time.Now(), time.Now().Add(time.Minute*200), nil, nil, nil)
	b, _ := ca.MarshalPEM()
	caCrtF.Write(b)

	// failed to read pub
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-in-pub", "./nope", "-duration", "100m"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "error while reading in-pub: open ./nope: "+NoSuchFileError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// failed to unmarshal pub
	ob.Reset()
	eb.Reset()
	inPubF, err := os.CreateTemp("", "in.pub")
	require.NoError(t, err)
	defer os.Remove(inPubF.Name())

	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-in-pub", inPubF.Name(), "-duration", "100m"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "error while parsing in-pub: input did not contain a valid PEM encoded block")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// write a proper pub for later
	ob.Reset()
	eb.Reset()
	inPub, _ := x25519Keypair()
	inPubF.Write(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, inPub))

	// bad ip cidr
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "a1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	assertHelpError(t, signCert(args, ob, eb, nopw), "invalid -networks definition: a1.1.1.1/24")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "100::100/100", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	assertHelpError(t, signCert(args, ob, eb, nopw), "invalid -networks definition: v1 certificates can only have a single ipv4 address")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24,1.1.1.2/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	assertHelpError(t, signCert(args, ob, eb, nopw), "invalid -networks definition: v1 certificates can only have a single ipv4 address")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// bad subnet cidr
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m", "-subnets", "a"}
	assertHelpError(t, signCert(args, ob, eb, nopw), "invalid -unsafe-networks definition: a")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m", "-subnets", "100::100/100"}
	assertHelpError(t, signCert(args, ob, eb, nopw), "invalid -unsafe-networks definition: v1 certificates can only contain ipv4 addresses")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// mismatched ca key
	_, caPriv2, _ := ed25519.GenerateKey(rand.Reader)
	caKeyF2, err := os.CreateTemp("", "sign-cert-2.key")
	require.NoError(t, err)
	defer os.Remove(caKeyF2.Name())
	caKeyF2.Write(cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, caPriv2))

	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF2.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m", "-subnets", "a"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "refusing to sign, root certificate does not match private key")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// failed key write
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "/do/not/write/pleasecrt", "-out-key", "/do/not/write/pleasekey", "-duration", "100m", "-subnets", "10.1.1.1/32"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "error while writing out-key: open /do/not/write/pleasekey: "+NoSuchDirError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// create temp key file
	keyF, err := os.CreateTemp("", "test.key")
	require.NoError(t, err)
	os.Remove(keyF.Name())

	// failed cert write
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "/do/not/write/pleasecrt", "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "error while writing out-crt: open /do/not/write/pleasecrt: "+NoSuchDirError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	os.Remove(keyF.Name())

	// create temp cert file
	crtF, err := os.CreateTemp("", "test.crt")
	require.NoError(t, err)
	os.Remove(crtF.Name())

	// test proper cert with removed empty groups and subnets
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.NoError(t, signCert(args, ob, eb, nopw))
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// read cert and key files
	rb, _ := os.ReadFile(keyF.Name())
	lKey, b, curve, err := cert.UnmarshalPrivateKeyFromPEM(rb)
	assert.Equal(t, cert.Curve_CURVE25519, curve)
	assert.Empty(t, b)
	require.NoError(t, err)
	assert.Len(t, lKey, 32)

	rb, _ = os.ReadFile(crtF.Name())
	lCrt, b, err := cert.UnmarshalCertificateFromPEM(rb)
	assert.Empty(t, b)
	require.NoError(t, err)

	assert.Equal(t, "test", lCrt.Name())
	assert.Equal(t, "1.1.1.1/24", lCrt.Networks()[0].String())
	assert.Len(t, lCrt.Networks(), 1)
	assert.False(t, lCrt.IsCA())
	assert.Equal(t, []string{"1", "2", "3", "4", "5"}, lCrt.Groups())
	assert.Len(t, lCrt.UnsafeNetworks(), 3)
	assert.Len(t, lCrt.PublicKey(), 32)
	assert.Equal(t, time.Duration(time.Minute*100), lCrt.NotAfter().Sub(lCrt.NotBefore()))

	sns := []string{}
	for _, sn := range lCrt.UnsafeNetworks() {
		sns = append(sns, sn.String())
	}
	assert.Equal(t, []string{"10.1.1.1/32", "10.2.2.2/32", "10.5.5.5/32"}, sns)

	issuer, _ := ca.Fingerprint()
	assert.Equal(t, issuer, lCrt.Issuer())

	assert.True(t, lCrt.CheckSignature(caPub))

	// test proper cert with in-pub
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-in-pub", inPubF.Name(), "-duration", "100m", "-groups", "1"}
	require.NoError(t, signCert(args, ob, eb, nopw))
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// read cert file and check pub key matches in-pub
	rb, _ = os.ReadFile(crtF.Name())
	lCrt, b, err = cert.UnmarshalCertificateFromPEM(rb)
	assert.Empty(t, b)
	require.NoError(t, err)
	assert.Equal(t, lCrt.PublicKey(), inPub)

	// test refuse to sign cert with duration beyond root
	ob.Reset()
	eb.Reset()
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "1000m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "error while signing: certificate expires after signing certificate")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// create valid cert/key for overwrite tests
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.NoError(t, signCert(args, ob, eb, nopw))

	// test that we won't overwrite existing key file
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "refusing to overwrite existing key: "+keyF.Name())
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// create valid cert/key for overwrite tests
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.NoError(t, signCert(args, ob, eb, nopw))

	// test that we won't overwrite existing certificate file
	os.Remove(keyF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "refusing to overwrite existing cert: "+crtF.Name())
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// create valid cert/key using encrypted CA key
	os.Remove(caKeyF.Name())
	os.Remove(caCrtF.Name())
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()

	caKeyF, err = os.CreateTemp("", "sign-cert.key")
	require.NoError(t, err)
	defer os.Remove(caKeyF.Name())

	caCrtF, err = os.CreateTemp("", "sign-cert.crt")
	require.NoError(t, err)
	defer os.Remove(caCrtF.Name())

	// generate the encrypted key
	caPub, caPriv, _ = ed25519.GenerateKey(rand.Reader)
	kdfParams := cert.NewArgon2Parameters(64*1024, 4, 3)
	b, _ = cert.EncryptAndMarshalSigningPrivateKey(cert.Curve_CURVE25519, caPriv, passphrase, kdfParams)
	caKeyF.Write(b)

	ca, _ = NewTestCaCert("ca", caPub, caPriv, time.Now(), time.Now().Add(time.Minute*200), nil, nil, nil)
	b, _ = ca.MarshalPEM()
	caCrtF.Write(b)

	// test with the proper password
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.NoError(t, signCert(args, ob, eb, testpw))
	assert.Equal(t, "Enter passphrase: ", ob.String())
	assert.Empty(t, eb.String())

	// test with the proper password in the environment
	os.Remove(crtF.Name())
	os.Remove(keyF.Name())
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	os.Setenv("NEBULA_CA_PASSPHRASE", string(passphrase))
	require.NoError(t, signCert(args, ob, eb, testpw))
	assert.Empty(t, eb.String())
	os.Setenv("NEBULA_CA_PASSPHRASE", "")

	// test with the wrong password
	ob.Reset()
	eb.Reset()

	testpw.password = []byte("invalid password")
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.Error(t, signCert(args, ob, eb, testpw))
	assert.Equal(t, "Enter passphrase: ", ob.String())
	assert.Empty(t, eb.String())

	// test with the wrong password in environment
	ob.Reset()
	eb.Reset()

	os.Setenv("NEBULA_CA_PASSPHRASE", "invalid password")
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.EqualError(t, signCert(args, ob, eb, nopw), "error while parsing encrypted ca-key: invalid passphrase or corrupt private key")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	os.Setenv("NEBULA_CA_PASSPHRASE", "")

	// test with the user not entering a password
	ob.Reset()
	eb.Reset()

	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.Error(t, signCert(args, ob, eb, nopw))
	// normally the user hitting enter on the prompt would add newlines between these
	assert.Equal(t, "Enter passphrase: Enter passphrase: Enter passphrase: Enter passphrase: Enter passphrase: ", ob.String())
	assert.Empty(t, eb.String())

	// test an error condition
	ob.Reset()
	eb.Reset()

	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.Error(t, signCert(args, ob, eb, errpw))
	assert.Equal(t, "Enter passphrase: ", ob.String())
	assert.Empty(t, eb.String())
}
