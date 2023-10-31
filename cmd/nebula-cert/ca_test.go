//go:build !windows
// +build !windows

package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"os"
	"strings"
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
			"  -argon-iterations uint\n"+
			"    \tOptional: Argon2 iterations parameter used for encrypted private key passphrase (default 1)\n"+
			"  -argon-memory uint\n"+
			"    \tOptional: Argon2 memory parameter (in KiB) used for encrypted private key passphrase (default 2097152)\n"+
			"  -argon-parallelism uint\n"+
			"    \tOptional: Argon2 parallelism parameter used for encrypted private key passphrase (default 4)\n"+
			"  -curve string\n"+
			"    \tEdDSA/ECDSA Curve (25519, P256) (default \"25519\")\n"+
			"  -duration duration\n"+
			"    \tOptional: amount of time the certificate should be valid for. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\" (default 8760h0m0s)\n"+
			"  -encrypt\n"+
			"    \tOptional: prompt for passphrase and write out-key in an encrypted format\n"+
			"  -groups string\n"+
			"    \tOptional: comma separated list of groups. This will limit which groups subordinate certs can use\n"+
			"  -ips string\n"+
			"    \tOptional: comma separated list of ipv4 address and network in CIDR notation. This will limit which ipv4 addresses and networks subordinate certs can use for ip addresses\n"+
			"  -name string\n"+
			"    \tRequired: name of the certificate authority\n"+
			"  -out-crt string\n"+
			"    \tOptional: path to write the certificate to (default \"ca.crt\")\n"+
			"  -out-key string\n"+
			"    \tOptional: path to write the private key to (default \"ca.key\")\n"+
			"  -out-qr string\n"+
			"    \tOptional: output a qr code image (png) of the certificate\n"+
			"  -subnets string\n"+
			"    \tOptional: comma separated list of ipv4 address and network in CIDR notation. This will limit which ipv4 addresses and networks subordinate certs can use in subnets\n",
		ob.String(),
	)
}

func Test_ca(t *testing.T) {
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

	pwPromptOb := "Enter passphrase: "

	// required args
	assertHelpError(t, ca(
		[]string{"-out-key", "nope", "-out-crt", "nope", "duration", "100m"}, ob, eb, nopw,
	), "-name is required")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// ipv4 only ips
	assertHelpError(t, ca([]string{"-name", "ipv6", "-ips", "100::100/100"}, ob, eb, nopw), "invalid ip definition: can only be ipv4, have 100::100/100")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// ipv4 only subnets
	assertHelpError(t, ca([]string{"-name", "ipv6", "-subnets", "100::100/100"}, ob, eb, nopw), "invalid subnet definition: can only be ipv4, have 100::100/100")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// failed key write
	ob.Reset()
	eb.Reset()
	args := []string{"-name", "test", "-duration", "100m", "-out-crt", "/do/not/write/pleasecrt", "-out-key", "/do/not/write/pleasekey"}
	assert.EqualError(t, ca(args, ob, eb, nopw), "error while writing out-key: open /do/not/write/pleasekey: "+NoSuchDirError)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// create temp key file
	keyF, err := os.CreateTemp("", "test.key")
	assert.Nil(t, err)
	os.Remove(keyF.Name())

	// failed cert write
	ob.Reset()
	eb.Reset()
	args = []string{"-name", "test", "-duration", "100m", "-out-crt", "/do/not/write/pleasecrt", "-out-key", keyF.Name()}
	assert.EqualError(t, ca(args, ob, eb, nopw), "error while writing out-crt: open /do/not/write/pleasecrt: "+NoSuchDirError)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// create temp cert file
	crtF, err := os.CreateTemp("", "test.crt")
	assert.Nil(t, err)
	os.Remove(crtF.Name())
	os.Remove(keyF.Name())

	// test proper cert with removed empty groups and subnets
	ob.Reset()
	eb.Reset()
	args = []string{"-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.Nil(t, ca(args, ob, eb, nopw))
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// read cert and key files
	rb, _ := os.ReadFile(keyF.Name())
	lKey, b, err := cert.UnmarshalEd25519PrivateKey(rb)
	assert.Len(t, b, 0)
	assert.Nil(t, err)
	assert.Len(t, lKey, 64)

	rb, _ = os.ReadFile(crtF.Name())
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

	// test encrypted key
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-encrypt", "-name", "test", "-duration", "100m", "-groups", "1,2,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.Nil(t, ca(args, ob, eb, testpw))
	assert.Equal(t, pwPromptOb, ob.String())
	assert.Equal(t, "", eb.String())

	// read encrypted key file and verify default params
	rb, _ = os.ReadFile(keyF.Name())
	k, _ := pem.Decode(rb)
	ned, err := cert.UnmarshalNebulaEncryptedData(k.Bytes)
	assert.Nil(t, err)
	// we won't know salt in advance, so just check start of string
	assert.Equal(t, uint32(2*1024*1024), ned.EncryptionMetadata.Argon2Parameters.Memory)
	assert.Equal(t, uint8(4), ned.EncryptionMetadata.Argon2Parameters.Parallelism)
	assert.Equal(t, uint32(1), ned.EncryptionMetadata.Argon2Parameters.Iterations)

	// verify the key is valid and decrypt-able
	var curve cert.Curve
	curve, lKey, b, err = cert.DecryptAndUnmarshalSigningPrivateKey(passphrase, rb)
	assert.Equal(t, cert.Curve_CURVE25519, curve)
	assert.Nil(t, err)
	assert.Len(t, b, 0)
	assert.Len(t, lKey, 64)

	// test when reading passsword results in an error
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-encrypt", "-name", "test", "-duration", "100m", "-groups", "1,2,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.Error(t, ca(args, ob, eb, errpw))
	assert.Equal(t, pwPromptOb, ob.String())
	assert.Equal(t, "", eb.String())

	// test when user fails to enter a password
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-encrypt", "-name", "test", "-duration", "100m", "-groups", "1,2,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.EqualError(t, ca(args, ob, eb, nopw), "no passphrase specified, remove -encrypt flag to write out-key in plaintext")
	assert.Equal(t, strings.Repeat(pwPromptOb, 5), ob.String()) // prompts 5 times before giving up
	assert.Equal(t, "", eb.String())

	// create valid cert/key for overwrite tests
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.Nil(t, ca(args, ob, eb, nopw))

	// test that we won't overwrite existing certificate file
	ob.Reset()
	eb.Reset()
	args = []string{"-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.EqualError(t, ca(args, ob, eb, nopw), "refusing to overwrite existing CA key: "+keyF.Name())
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// test that we won't overwrite existing key file
	os.Remove(keyF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	assert.EqualError(t, ca(args, ob, eb, nopw), "refusing to overwrite existing CA cert: "+crtF.Name())
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	os.Remove(keyF.Name())

}
