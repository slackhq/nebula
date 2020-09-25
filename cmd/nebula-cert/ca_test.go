// +build !windows

package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
)

//TODO: test file permissions

func Test_caSummary(t *testing.T) {
	assert.Equal(t, "ca <flags>: create a self signed certificate authority", caSummary())
}

func Test_caHelp(t *testing.T) {
	ob := &bytes.Buffer{}
	caHelp(ob)
	assert.Equal(
		t,
		"Usage of "+os.Args[0]+" ca <flags>: create a self signed certificate authority\n"+
			"  -duration duration\n"+
			"    \tOptional: amount of time the certificate should be valid for. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\" (default 8760h0m0s)\n"+
			"  -groups string\n"+
			"    \tOptional: comma separated list of groups. This will limit which groups subordinate certs can use\n"+
			"  -ips string\n"+
			"    \tOptional: comma separated list of ip and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use\n"+
			"  -name string\n"+
			"    \tRequired: name of the certificate authority\n"+
			"  -out-crt string\n"+
			"    \tOptional: path to write the certificate to (default \"ca.crt\")\n"+
			"  -out-key string\n"+
			"    \tOptional: path to write the private key to (default \"ca.key\")\n"+
			"  -out-qr string\n"+
			"    \tOptional: output a qr code image (png) of the certificate\n"+
			"  -subnets string\n"+
			"    \tOptional: comma separated list of ip and network in CIDR notation. This will limit which subnet addresses and networks subordinate certs can use\n",
		ob.String(),
	)
}

func Test_ca(t *testing.T) {
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}

	// required args
	assertHelpError(t, ca([]string{"-out-key", "nope", "-out-crt", "nope", "duration", "100m"}, ob, eb), "-name is required")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// failed key write
	ob.Reset()
	eb.Reset()
	args := []string{"-name", "test", "-duration", "100m", "-out-crt", "/do/not/write/pleasecrt", "-out-key", "/do/not/write/pleasekey"}
	assert.EqualError(t, ca(args, ob, eb), "error while writing out-key: open /do/not/write/pleasekey: "+NoSuchDirError)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// create temp key file
	keyF, err := ioutil.TempFile("", "test.key")
	assert.Nil(t, err)
	os.Remove(keyF.Name())

	// failed cert write
	ob.Reset()
	eb.Reset()
	args = []string{"-name", "test", "-duration", "100m", "-out-crt", "/do/not/write/pleasecrt", "-out-key", keyF.Name()}
	assert.EqualError(t, ca(args, ob, eb), "error while writing out-crt: open /do/not/write/pleasecrt: "+NoSuchDirError)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// create temp cert file
	crtF, err := ioutil.TempFile("", "test.crt")
	assert.Nil(t, err)
	os.Remove(crtF.Name())
	os.Remove(keyF.Name())

	// test proper cert with removed empty groups and subnets
	ob.Reset()
	eb.Reset()
	args = []string{"-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.Nil(t, ca(args, ob, eb))
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// read cert and key files
	rb, _ := ioutil.ReadFile(keyF.Name())
	lKey, b, err := cert.UnmarshalEd25519PrivateKey(rb)
	assert.Len(t, b, 0)
	assert.Nil(t, err)
	assert.Len(t, lKey, 64)

	rb, _ = ioutil.ReadFile(crtF.Name())
	lCrt, b, err := cert.UnmarshalNebulaCertificateFromPEM(rb)
	assert.Len(t, b, 0)
	assert.Nil(t, err)

	assert.Equal(t, "test", lCrt.Details.Name)
	assert.Len(t, lCrt.Details.Ips, 0)
	assert.True(t, lCrt.Details.IsCA)
	assert.Equal(t, []string{"1", "2", "3", "4", "5"}, lCrt.Details.Groups)
	assert.Len(t, lCrt.Details.Subnets, 0)
	assert.Len(t, lCrt.Details.PublicKey, 32)
	assert.Equal(t, time.Duration(time.Minute*100), lCrt.Details.NotAfter.Sub(lCrt.Details.NotBefore))
	assert.Equal(t, "", lCrt.Details.Issuer)
	assert.True(t, lCrt.CheckSignature(lCrt.Details.PublicKey))

	// create valid cert/key for overwrite tests
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.Nil(t, ca(args, ob, eb))

	// test that we won't overwrite existing certificate file
	ob.Reset()
	eb.Reset()
	args = []string{"-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.EqualError(t, ca(args, ob, eb), "refusing to overwrite existing CA key: "+keyF.Name())
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// test that we won't overwrite existing key file
	os.Remove(keyF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.EqualError(t, ca(args, ob, eb), "refusing to overwrite existing CA cert: "+crtF.Name())
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	os.Remove(keyF.Name())

}
