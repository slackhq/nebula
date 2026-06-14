//go:build !windows
// +build !windows

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
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
			"  Pass \"-\" to any path flag to read from stdin or write to stdout.\n"+
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
			"  -pq-psk-binding string\n"+
			"    \tOptional: hex-encoded SHA-256 (64 hex chars / 32 bytes) PQ PSK binding for the holder's post-quantum provider public key. Binds the PQ keypair to this cert (the sole trust binding for PQ). v2 certs only. Canonical alias for -rp-pubkey-sha256.\n"+
			"  -rp-pubkey-from string\n"+
			"    \tOptional: path to a rosenpass public key file (e.g. the rp.pub written by 'rosenpass gen-keys' or by the embedded rosenpass state_dir). Its SHA-256 is computed and stored in the cert as the PQ PSK binding. Mutually exclusive with -pq-psk-binding / -rp-pubkey-sha256. v2 certs only.\n"+
			"  -rp-pubkey-sha256 string\n"+
			"    \tOptional: deprecated alias for -pq-psk-binding; hex-encoded SHA-256 (64 hex chars / 32 bytes) of the holder's Rosenpass public key. v2 certs only.\n"+
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
	assert.Empty(t, ob.String())
	assert.Equal(t, "Enter passphrase: ", eb.String())

	// test with the proper password in the environment
	os.Remove(crtF.Name())
	os.Remove(keyF.Name())
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	os.Setenv("NEBULA_CA_PASSPHRASE", string(passphrase))
	ob.Reset()
	eb.Reset()
	require.NoError(t, signCert(args, ob, eb, testpw))
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	os.Setenv("NEBULA_CA_PASSPHRASE", "")

	// test with the wrong password
	ob.Reset()
	eb.Reset()

	testpw.password = []byte("invalid password")
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.Error(t, signCert(args, ob, eb, testpw))
	assert.Empty(t, ob.String())
	assert.Equal(t, "Enter passphrase: ", eb.String())

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
	assert.Empty(t, ob.String())
	assert.Equal(t, "Enter passphrase: Enter passphrase: Enter passphrase: Enter passphrase: Enter passphrase: ", eb.String())

	// test an error condition
	ob.Reset()
	eb.Reset()

	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	require.Error(t, signCert(args, ob, eb, errpw))
	assert.Empty(t, ob.String())
	assert.Equal(t, "Enter passphrase: ", eb.String())
}

func Test_signCert_stdio(t *testing.T) {
	nopw := &StubPasswordReader{
		password: []byte(""),
		err:      nil,
	}

	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	rawCAKey := cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, caPriv)

	ca, _ := NewTestCaCert("ca", caPub, caPriv, time.Now(), time.Now().Add(time.Minute*200), nil, nil, nil)
	rawCACrt, _ := ca.MarshalPEM()

	caCrtF, err := os.CreateTemp("", "sign-cert.crt")
	require.NoError(t, err)
	defer os.Remove(caCrtF.Name())
	caCrtF.Write(rawCACrt)

	caKeyF, err := os.CreateTemp("", "sign-cert.key")
	require.NoError(t, err)
	defer os.Remove(caKeyF.Name())
	caKeyF.Write(rawCAKey)

	keyF, err := os.CreateTemp("", "sign.key")
	require.NoError(t, err)
	os.Remove(keyF.Name())
	defer os.Remove(keyF.Name())

	// ca-key on stdin, cert to stdout
	withStdin(t, bytes.NewReader(rawCAKey))
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}
	args := []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", "-", "-name", "stdin-test", "-ip", "1.1.1.1/24", "-out-crt", "-", "-out-key", keyF.Name(), "-duration", "100m"}
	require.NoError(t, signCert(args, ob, eb, nopw))
	assert.Empty(t, eb.String())

	lCrt, _, err := cert.UnmarshalCertificateFromPEM(ob.Bytes())
	require.NoError(t, err)
	assert.Equal(t, "stdin-test", lCrt.Name())
	assert.True(t, lCrt.CheckSignature(caPub))

	// two flags reading from stdin should error before any read attempt;
	// otherwise an interactive shell would hang on io.ReadAll
	stdinIn := bytes.NewReader(rawCAKey)
	withStdin(t, stdinIn)
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", "-", "-ca-key", "-", "-name", "stdin-test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	require.EqualError(t, signCert(args, ob, eb, nopw),
		`-ca-key and -ca-crt both set to "-", only one input may read from stdin`)
	assert.Equal(t, len(rawCAKey), stdinIn.Len(), "stdin should be untouched when conflict is caught up front")

	// two flags writing to stdout should error before any output is written
	// AND before stdin is consumed
	stdinR := bytes.NewReader(rawCAKey)
	withStdin(t, stdinR)
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", "-", "-name", "stdin-test", "-ip", "1.1.1.1/24", "-out-crt", "-", "-out-key", "-", "-duration", "100m"}
	require.EqualError(t, signCert(args, ob, eb, nopw),
		`-out-key and -out-crt both set to "-", only one output may write to stdout`)
	assert.Empty(t, ob.String())
	// stdin should be untouched because the conflict was caught up front
	assert.Equal(t, len(rawCAKey), stdinR.Len())

	// out-key on stdout, cert on disk
	keyF2, err := os.CreateTemp("", "sign.key")
	require.NoError(t, err)
	os.Remove(keyF2.Name())
	defer os.Remove(keyF2.Name())
	crtF, err := os.CreateTemp("", "sign.crt")
	require.NoError(t, err)
	os.Remove(crtF.Name())
	defer os.Remove(crtF.Name())

	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "stdin-test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", "-", "-duration", "100m"}
	require.NoError(t, signCert(args, ob, eb, nopw))
	assert.Empty(t, eb.String())
	_, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(ob.Bytes())
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_CURVE25519, curve)

	// in-pub on stdin (caller already has a keypair, only the cert is generated)
	inPub, _ := x25519Keypair()
	rawInPub := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, inPub)

	withStdin(t, bytes.NewReader(rawInPub))
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "in-pub-test", "-ip", "1.1.1.1/24", "-in-pub", "-", "-out-crt", "-", "-duration", "100m"}
	require.NoError(t, signCert(args, ob, eb, nopw))
	assert.Empty(t, eb.String())
	stdinCrt, _, err := cert.UnmarshalCertificateFromPEM(ob.Bytes())
	require.NoError(t, err)
	assert.Equal(t, "in-pub-test", stdinCrt.Name())
	assert.Equal(t, inPub, stdinCrt.PublicKey())
}

// writeV2TestCA materialises a v2 CA cert + curve25519 signing key on disk
// and returns the paths. Used by the rp-pubkey-from tests which need a v2
// signing CA (the existing NewTestCaCert helper only produces v1).
func writeV2TestCA(t *testing.T, dir string) (caCrtPath, caKeyPath string) {
	t.Helper()

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      "test-ca",
		Networks:  []netip.Prefix{netip.MustParsePrefix("100.66.66.0/24")},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
		PublicKey: caPub,
		IsCA:      true,
		Curve:     cert.Curve_CURVE25519,
	}
	ca, err := tbs.Sign(nil, cert.Curve_CURVE25519, caPriv)
	require.NoError(t, err)

	caCrtPath = filepath.Join(dir, "ca.crt")
	caKeyPath = filepath.Join(dir, "ca.key")

	caCrtPEM, err := ca.MarshalPEM()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(caCrtPath, caCrtPEM, 0600))
	require.NoError(t, os.WriteFile(caKeyPath, cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, caPriv), 0600))
	return caCrtPath, caKeyPath
}

func Test_signRPPubkeyFromFile(t *testing.T) {
	dir := t.TempDir()
	caCrt, caKey := writeV2TestCA(t, dir)

	// Simulate a real rosenpass public key file (the actual McEliece pubkey
	// is ~524KB but the cert tool only cares about SHA-256 of the bytes, so
	// any non-empty blob exercises the same code path).
	rpPub := make([]byte, 1024)
	_, err := rand.Read(rpPub)
	require.NoError(t, err)
	rpPubPath := filepath.Join(dir, "rp.pub")
	require.NoError(t, os.WriteFile(rpPubPath, rpPub, 0644))

	outCrt := filepath.Join(dir, "host.crt")
	outKey := filepath.Join(dir, "host.key")

	args := []string{
		"-version", "2",
		"-ca-crt", caCrt, "-ca-key", caKey,
		"-name", "node-a",
		"-networks", "100.66.66.1/24",
		"-rp-pubkey-from", rpPubPath,
		"-out-crt", outCrt, "-out-key", outKey,
		"-duration", "30m",
	}
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}
	require.NoError(t, signCert(args, ob, eb, &StubPasswordReader{}))

	rawCrt, err := os.ReadFile(outCrt)
	require.NoError(t, err)
	signed, _, err := cert.UnmarshalCertificateFromPEM(rawCrt)
	require.NoError(t, err)

	want := sha256.Sum256(rpPub)
	require.Equal(t, want[:], signed.PqPskBinding(), "cert extension must equal sha256(rp.pub)")
}

func Test_signRPPubkeyFromMutuallyExclusiveWithHash(t *testing.T) {
	dir := t.TempDir()
	caCrt, caKey := writeV2TestCA(t, dir)

	rpPubPath := filepath.Join(dir, "rp.pub")
	require.NoError(t, os.WriteFile(rpPubPath, []byte("anything"), 0644))

	hashHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	args := []string{
		"-version", "2",
		"-ca-crt", caCrt, "-ca-key", caKey,
		"-name", "node-a",
		"-networks", "100.66.66.1/24",
		"-rp-pubkey-from", rpPubPath,
		"-rp-pubkey-sha256", hashHex,
		"-out-crt", filepath.Join(dir, "host.crt"),
		"-out-key", filepath.Join(dir, "host.key"),
		"-duration", "30m",
	}
	err := signCert(args, &bytes.Buffer{}, &bytes.Buffer{}, &StubPasswordReader{})
	assertHelpError(t, err, "-rp-pubkey-from and -pq-psk-binding/-rp-pubkey-sha256 are mutually exclusive")
}

// Test_signPqPskBindingFlag verifies the canonical -pq-psk-binding flag and the
// deprecated -rp-pubkey-sha256 alias both populate the cert binding identically,
// and that the generic flag takes precedence when both are supplied.
func Test_signPqPskBindingFlag(t *testing.T) {
	genericHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	legacyHex := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	genericBytes, err := hex.DecodeString(genericHex)
	require.NoError(t, err)
	legacyBytes, err := hex.DecodeString(legacyHex)
	require.NoError(t, err)

	signWith := func(t *testing.T, extra ...string) cert.Certificate {
		t.Helper()
		dir := t.TempDir()
		caCrt, caKey := writeV2TestCA(t, dir)
		outCrt := filepath.Join(dir, "host.crt")
		outKey := filepath.Join(dir, "host.key")
		args := append([]string{
			"-version", "2",
			"-ca-crt", caCrt, "-ca-key", caKey,
			"-name", "node-a",
			"-networks", "100.66.66.1/24",
			"-out-crt", outCrt, "-out-key", outKey,
			"-duration", "30m",
		}, extra...)
		require.NoError(t, signCert(args, &bytes.Buffer{}, &bytes.Buffer{}, &StubPasswordReader{}))
		raw, err := os.ReadFile(outCrt)
		require.NoError(t, err)
		signed, _, err := cert.UnmarshalCertificateFromPEM(raw)
		require.NoError(t, err)
		return signed
	}

	t.Run("canonical flag", func(t *testing.T) {
		signed := signWith(t, "-pq-psk-binding", genericHex)
		require.Equal(t, genericBytes, signed.PqPskBinding())
	})

	t.Run("legacy alias", func(t *testing.T) {
		signed := signWith(t, "-rp-pubkey-sha256", legacyHex)
		require.Equal(t, legacyBytes, signed.PqPskBinding())
	})

	t.Run("canonical takes precedence", func(t *testing.T) {
		signed := signWith(t, "-pq-psk-binding", genericHex, "-rp-pubkey-sha256", legacyHex)
		require.Equal(t, genericBytes, signed.PqPskBinding())
	})
}

func Test_signRPPubkeyFromMissingFile(t *testing.T) {
	dir := t.TempDir()
	caCrt, caKey := writeV2TestCA(t, dir)

	missing := filepath.Join(dir, "does-not-exist.pub")
	args := []string{
		"-version", "2",
		"-ca-crt", caCrt, "-ca-key", caKey,
		"-name", "node-a",
		"-networks", "100.66.66.1/24",
		"-rp-pubkey-from", missing,
		"-out-crt", filepath.Join(dir, "host.crt"),
		"-out-key", filepath.Join(dir, "host.key"),
		"-duration", "30m",
	}
	err := signCert(args, &bytes.Buffer{}, &bytes.Buffer{}, &StubPasswordReader{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "error while reading rp-pubkey-from")
}

func Test_signRPPubkeyFromEmptyFile(t *testing.T) {
	dir := t.TempDir()
	caCrt, caKey := writeV2TestCA(t, dir)

	empty := filepath.Join(dir, "empty.pub")
	require.NoError(t, os.WriteFile(empty, nil, 0644))

	args := []string{
		"-version", "2",
		"-ca-crt", caCrt, "-ca-key", caKey,
		"-name", "node-a",
		"-networks", "100.66.66.1/24",
		"-rp-pubkey-from", empty,
		"-out-crt", filepath.Join(dir, "host.crt"),
		"-out-key", filepath.Join(dir, "host.key"),
		"-duration", "30m",
	}
	err := signCert(args, &bytes.Buffer{}, &bytes.Buffer{}, &StubPasswordReader{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "rp-pubkey-from file is empty")
}

func Test_signRPPubkeyFromRejectedOnV1(t *testing.T) {
	// Use the existing v1 CA helper for this — v1 CAs default to v1 children
	// and the version check at line 333 should reject the flag.
	dir := t.TempDir()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ca, _ := NewTestCaCert("ca", caPub, caPriv, time.Now(), time.Now().Add(time.Hour), nil, nil, nil)
	caCrtPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	pem, err := ca.MarshalPEM()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(caCrtPath, pem, 0600))
	require.NoError(t, os.WriteFile(caKeyPath, cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, caPriv), 0600))

	rpPubPath := filepath.Join(dir, "rp.pub")
	require.NoError(t, os.WriteFile(rpPubPath, []byte("does-not-matter"), 0644))

	args := []string{
		"-version", "1",
		"-ca-crt", caCrtPath, "-ca-key", caKeyPath,
		"-name", "node-a",
		"-ip", "1.1.1.1/24",
		"-rp-pubkey-from", rpPubPath,
		"-out-crt", filepath.Join(dir, "host.crt"),
		"-out-key", filepath.Join(dir, "host.key"),
		"-duration", "30m",
	}
	err = signCert(args, &bytes.Buffer{}, &bytes.Buffer{}, &StubPasswordReader{})
	assertHelpError(t, err, "-pq-psk-binding / -rp-pubkey-sha256 / -rp-pubkey-from requires a v2 certificate; v1 certificates have no extension area")
}
