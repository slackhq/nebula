// +build !windows

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

//TODO: test file permissions

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
			"    \tRequired: ip and network in CIDR notation to assign the cert\n"+
			"  -name string\n"+
			"    \tRequired: name of the cert, usually a hostname\n"+
			"  -out-crt string\n"+
			"    \tOptional: path to write the certificate to\n"+
			"  -out-key string\n"+
			"    \tOptional (if in-pub not set): path to write the private key to\n"+
			"  -out-qr string\n"+
			"    \tOptional: output a qr code image (png) of the certificate\n"+
			"  -subnets string\n"+
			"    \tOptional: comma separated list of subnet this cert can serve for\n",
		ob.String(),
	)
}

func Test_signCert(t *testing.T) {
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}

	// required args

	assertHelpError(t, signCert([]string{"-ca-crt", "./nope", "-ca-key", "./nope", "-ip", "1.1.1.1/24", "-out-key", "nope", "-out-crt", "nope"}, ob, eb), "-name is required")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	assertHelpError(t, signCert([]string{"-ca-crt", "./nope", "-ca-key", "./nope", "-name", "test", "-out-key", "nope", "-out-crt", "nope"}, ob, eb), "-ip is required")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// cannot set -in-pub and -out-key
	assertHelpError(t, signCert([]string{"-ca-crt", "./nope", "-ca-key", "./nope", "-name", "test", "-in-pub", "nope", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope"}, ob, eb), "cannot set both -in-pub and -out-key")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// failed to read key
	ob.Reset()
	eb.Reset()
	args := []string{"-ca-crt", "./nope", "-ca-key", "./nope", "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	assert.EqualError(t, signCert(args, ob, eb), "error while reading ca-key: open ./nope: "+NoSuchFileError)

	// failed to unmarshal key
	ob.Reset()
	eb.Reset()
	caKeyF, err := ioutil.TempFile("", "sign-cert.key")
	assert.Nil(t, err)
	defer os.Remove(caKeyF.Name())

	args = []string{"-ca-crt", "./nope", "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	assert.EqualError(t, signCert(args, ob, eb), "error while parsing ca-key: input did not contain a valid PEM encoded block")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// Write a proper ca key for later
	ob.Reset()
	eb.Reset()
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caKeyF.Write(cert.MarshalEd25519PrivateKey(caPriv))

	// failed to read cert
	args = []string{"-ca-crt", "./nope", "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	assert.EqualError(t, signCert(args, ob, eb), "error while reading ca-crt: open ./nope: "+NoSuchFileError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// failed to unmarshal cert
	ob.Reset()
	eb.Reset()
	caCrtF, err := ioutil.TempFile("", "sign-cert.crt")
	assert.Nil(t, err)
	defer os.Remove(caCrtF.Name())

	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	assert.EqualError(t, signCert(args, ob, eb), "error while parsing ca-crt: input did not contain a valid PEM encoded block")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// write a proper ca cert for later
	ca := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      "ca",
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Minute * 200),
			PublicKey: caPub,
			IsCA:      true,
		},
	}
	b, _ := ca.MarshalToPEM()
	caCrtF.Write(b)

	// failed to read pub
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-in-pub", "./nope", "-duration", "100m"}
	assert.EqualError(t, signCert(args, ob, eb), "error while reading in-pub: open ./nope: "+NoSuchFileError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// failed to unmarshal pub
	ob.Reset()
	eb.Reset()
	inPubF, err := ioutil.TempFile("", "in.pub")
	assert.Nil(t, err)
	defer os.Remove(inPubF.Name())

	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-in-pub", inPubF.Name(), "-duration", "100m"}
	assert.EqualError(t, signCert(args, ob, eb), "error while parsing in-pub: input did not contain a valid PEM encoded block")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// write a proper pub for later
	ob.Reset()
	eb.Reset()
	inPub, _ := x25519Keypair()
	inPubF.Write(cert.MarshalX25519PublicKey(inPub))

	// bad ip cidr
	ob.Reset()
	eb.Reset()
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "a1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m"}
	assertHelpError(t, signCert(args, ob, eb), "invalid ip definition: invalid CIDR address: a1.1.1.1/24")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// bad subnet cidr
	ob.Reset()
	eb.Reset()
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope", "-duration", "100m", "-subnets", "a"}
	assertHelpError(t, signCert(args, ob, eb), "invalid subnet definition: invalid CIDR address: a")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// failed key write
	ob.Reset()
	eb.Reset()
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "/do/not/write/pleasecrt", "-out-key", "/do/not/write/pleasekey", "-duration", "100m", "-subnets", "10.1.1.1/32"}
	assert.EqualError(t, signCert(args, ob, eb), "error while writing out-key: open /do/not/write/pleasekey: "+NoSuchDirError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// create temp key file
	keyF, err := ioutil.TempFile("", "test.key")
	assert.Nil(t, err)
	os.Remove(keyF.Name())

	// failed cert write
	ob.Reset()
	eb.Reset()
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", "/do/not/write/pleasecrt", "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32"}
	assert.EqualError(t, signCert(args, ob, eb), "error while writing out-crt: open /do/not/write/pleasecrt: "+NoSuchDirError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	os.Remove(keyF.Name())

	// create temp cert file
	crtF, err := ioutil.TempFile("", "test.crt")
	assert.Nil(t, err)
	os.Remove(crtF.Name())

	// test proper cert with removed empty groups and subnets
	ob.Reset()
	eb.Reset()
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	assert.Nil(t, signCert(args, ob, eb))
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// read cert and key files
	rb, _ := ioutil.ReadFile(keyF.Name())
	lKey, b, err := cert.UnmarshalX25519PrivateKey(rb)
	assert.Len(t, b, 0)
	assert.Nil(t, err)
	assert.Len(t, lKey, 32)

	rb, _ = ioutil.ReadFile(crtF.Name())
	lCrt, b, err := cert.UnmarshalNebulaCertificateFromPEM(rb)
	assert.Len(t, b, 0)
	assert.Nil(t, err)

	assert.Equal(t, "test", lCrt.Details.Name)
	assert.Equal(t, "1.1.1.1/24", lCrt.Details.Ips[0].String())
	assert.Len(t, lCrt.Details.Ips, 1)
	assert.False(t, lCrt.Details.IsCA)
	assert.Equal(t, []string{"1", "2", "3", "4", "5"}, lCrt.Details.Groups)
	assert.Len(t, lCrt.Details.Subnets, 3)
	assert.Len(t, lCrt.Details.PublicKey, 32)
	assert.Equal(t, time.Duration(time.Minute*100), lCrt.Details.NotAfter.Sub(lCrt.Details.NotBefore))

	sns := []string{}
	for _, sn := range lCrt.Details.Subnets {
		sns = append(sns, sn.String())
	}
	assert.Equal(t, []string{"10.1.1.1/32", "10.2.2.2/32", "10.5.5.5/32"}, sns)

	issuer, _ := ca.Sha256Sum()
	assert.Equal(t, issuer, lCrt.Details.Issuer)

	assert.True(t, lCrt.CheckSignature(caPub))

	// test proper cert with in-pub
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-in-pub", inPubF.Name(), "-duration", "100m", "-groups", "1"}
	assert.Nil(t, signCert(args, ob, eb))
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// read cert file and check pub key matches in-pub
	rb, _ = ioutil.ReadFile(crtF.Name())
	lCrt, b, err = cert.UnmarshalNebulaCertificateFromPEM(rb)
	assert.Len(t, b, 0)
	assert.Nil(t, err)
	assert.Equal(t, lCrt.Details.PublicKey, inPub)

	// test refuse to sign cert with duration beyond root
	ob.Reset()
	eb.Reset()
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "1000m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	assert.EqualError(t, signCert(args, ob, eb), "refusing to sign, root certificate constraints violated: certificate expires after signing certificate")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// create valid cert/key for overwrite tests
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	assert.Nil(t, signCert(args, ob, eb))

	// test that we won't overwrite existing key file
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	assert.EqualError(t, signCert(args, ob, eb), "refusing to overwrite existing key: "+keyF.Name())
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// create valid cert/key for overwrite tests
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	assert.Nil(t, signCert(args, ob, eb))

	// test that we won't overwrite existing certificate file
	os.Remove(keyF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-ca-crt", caCrtF.Name(), "-ca-key", caKeyF.Name(), "-name", "test", "-ip", "1.1.1.1/24", "-out-crt", crtF.Name(), "-out-key", keyF.Name(), "-duration", "100m", "-subnets", "10.1.1.1/32, ,   10.2.2.2/32   ,   ,  ,, 10.5.5.5/32", "-groups", "1,,   2    ,        ,,,3,4,5"}
	assert.EqualError(t, signCert(args, ob, eb), "refusing to overwrite existing cert: "+crtF.Name())
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
}
