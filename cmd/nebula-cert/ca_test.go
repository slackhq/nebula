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
	"github.com/stretchr/testify/require"
)

func Test_caSummary(t *testing.T) {
	assert.Equal(t, "ca <flags>: create a self signed certificate authority", caSummary())
}

func Test_caHelp(t *testing.T) {
	ob := &bytes.Buffer{}
	caHelp(ob)
	assert.Equal(
		t,
		"Usage of "+os.Args[0]+" ca <flags>: create a self signed certificate authority\n"+
			"  Pass \"-\" to any path flag to read from stdin or write to stdout.\n"+
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
			"    	Deprecated, see -networks\n"+
			"  -name string\n"+
			"    \tRequired: name of the certificate authority\n"+
			"  -networks string\n"+
			"    \tOptional: comma separated list of ip address and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use in networks\n"+
			"  -out-crt string\n"+
			"    \tOptional: path to write the certificate to (default \"ca.crt\")\n"+
			"  -out-key string\n"+
			"    \tOptional: path to write the private key to (default \"ca.key\")\n"+
			"  -out-qr string\n"+
			"    \tOptional: output a qr code image (png) of the certificate\n"+
			optionalPkcs11String("  -pkcs11 string\n    \tOptional: PKCS#11 URI to an existing private key\n")+
			"  -subnets string\n"+
			"    \tDeprecated, see -unsafe-networks\n"+
			"  -unsafe-networks string\n"+
			"    \tOptional: comma separated list of ip address and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use in unsafe networks\n"+
			"  -version uint\n"+
			"    \tOptional: version of the certificate format to use (default 2)\n",
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

	pwPromptEB := "Enter passphrase: "

	// required args
	assertHelpError(t, ca(
		[]string{"-version", "1", "-out-key", "nope", "-out-crt", "nope", "duration", "100m"}, ob, eb, nopw,
	), "-name is required")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// ipv4 only ips
	assertHelpError(t, ca([]string{"-version", "1", "-name", "ipv6", "-ips", "100::100/100"}, ob, eb, nopw), "invalid -networks definition: v1 certificates can only be ipv4, have 100::100/100")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// ipv4 only subnets
	assertHelpError(t, ca([]string{"-version", "1", "-name", "ipv6", "-subnets", "100::100/100"}, ob, eb, nopw), "invalid -unsafe-networks definition: v1 certificates can only be ipv4, have 100::100/100")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// failed key write
	ob.Reset()
	eb.Reset()
	args := []string{"-version", "1", "-name", "test", "-duration", "100m", "-out-crt", "/do/not/write/pleasecrt", "-out-key", "/do/not/write/pleasekey"}
	require.EqualError(t, ca(args, ob, eb, nopw), "error while writing out-key: open /do/not/write/pleasekey: "+NoSuchDirError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// create temp key file
	keyF, err := os.CreateTemp("", "test.key")
	require.NoError(t, err)
	require.NoError(t, os.Remove(keyF.Name()))

	// failed cert write
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-name", "test", "-duration", "100m", "-out-crt", "/do/not/write/pleasecrt", "-out-key", keyF.Name()}
	require.EqualError(t, ca(args, ob, eb, nopw), "error while writing out-crt: open /do/not/write/pleasecrt: "+NoSuchDirError)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// create temp cert file
	crtF, err := os.CreateTemp("", "test.crt")
	require.NoError(t, err)
	require.NoError(t, os.Remove(crtF.Name()))
	require.NoError(t, os.Remove(keyF.Name()))

	// test proper cert with removed empty groups and subnets
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	require.NoError(t, ca(args, ob, eb, nopw))
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// read cert and key files
	rb, _ := os.ReadFile(keyF.Name())
	lKey, b, c, err := cert.UnmarshalSigningPrivateKeyFromPEM(rb)
	assert.Equal(t, cert.Curve_CURVE25519, c)
	assert.Empty(t, b)
	require.NoError(t, err)
	assert.Len(t, lKey, 64)

	rb, _ = os.ReadFile(crtF.Name())
	lCrt, b, err := cert.UnmarshalCertificateFromPEM(rb)
	assert.Empty(t, b)
	require.NoError(t, err)

	assert.Equal(t, "test", lCrt.Name())
	assert.Empty(t, lCrt.Networks())
	assert.True(t, lCrt.IsCA())
	assert.Equal(t, []string{"1", "2", "3", "4", "5"}, lCrt.Groups())
	assert.Empty(t, lCrt.UnsafeNetworks())
	assert.Len(t, lCrt.PublicKey(), 32)
	assert.Equal(t, time.Duration(time.Minute*100), lCrt.NotAfter().Sub(lCrt.NotBefore()))
	assert.Empty(t, lCrt.Issuer())
	assert.True(t, lCrt.CheckSignature(lCrt.PublicKey()))

	// test encrypted key
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-encrypt", "-name", "test", "-duration", "100m", "-groups", "1,2,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	require.NoError(t, ca(args, ob, eb, testpw))
	assert.Empty(t, ob.String())
	assert.Equal(t, pwPromptEB, eb.String())

	// test encrypted key with passphrase environment variable
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-encrypt", "-name", "test", "-duration", "100m", "-groups", "1,2,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	os.Setenv("NEBULA_CA_PASSPHRASE", string(passphrase))
	require.NoError(t, ca(args, ob, eb, testpw))
	assert.Empty(t, eb.String())
	os.Setenv("NEBULA_CA_PASSPHRASE", "")

	// read encrypted key file and verify default params
	rb, _ = os.ReadFile(keyF.Name())
	k, _ := pem.Decode(rb)
	ned, err := cert.UnmarshalNebulaEncryptedData(k.Bytes)
	require.NoError(t, err)
	// we won't know salt in advance, so just check start of string
	assert.Equal(t, uint32(2*1024*1024), ned.EncryptionMetadata.Argon2Parameters.Memory)
	assert.Equal(t, uint8(4), ned.EncryptionMetadata.Argon2Parameters.Parallelism)
	assert.Equal(t, uint32(1), ned.EncryptionMetadata.Argon2Parameters.Iterations)

	// verify the key is valid and decrypt-able
	var curve cert.Curve
	curve, lKey, b, err = cert.DecryptAndUnmarshalSigningPrivateKey(passphrase, rb)
	assert.Equal(t, cert.Curve_CURVE25519, curve)
	require.NoError(t, err)
	assert.Empty(t, b)
	assert.Len(t, lKey, 64)

	// test when reading password results in an error
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-encrypt", "-name", "test", "-duration", "100m", "-groups", "1,2,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	require.Error(t, ca(args, ob, eb, errpw))
	assert.Empty(t, ob.String())
	assert.Equal(t, pwPromptEB, eb.String())

	// test when user fails to enter a password
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-encrypt", "-name", "test", "-duration", "100m", "-groups", "1,2,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	require.EqualError(t, ca(args, ob, eb, nopw), "no passphrase specified, remove -encrypt flag to write out-key in plaintext")
	assert.Empty(t, ob.String())
	assert.Equal(t, strings.Repeat(pwPromptEB, 5), eb.String()) // prompts 5 times before giving up

	// create valid cert/key for overwrite tests
	os.Remove(keyF.Name())
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	require.NoError(t, ca(args, ob, eb, nopw))

	// test that we won't overwrite existing certificate file
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	require.EqualError(t, ca(args, ob, eb, nopw), "refusing to overwrite existing CA key: "+keyF.Name())
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// test that we won't overwrite existing key file
	os.Remove(keyF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-name", "test", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name(), "-out-key", keyF.Name()}
	require.EqualError(t, ca(args, ob, eb, nopw), "refusing to overwrite existing CA cert: "+crtF.Name())
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	os.Remove(keyF.Name())

}

func Test_ca_stdio(t *testing.T) {
	nopw := &StubPasswordReader{}

	keyF, err := os.CreateTemp("", "ca.key")
	require.NoError(t, err)
	os.Remove(keyF.Name())
	defer os.Remove(keyF.Name())

	crtF, err := os.CreateTemp("", "ca.crt")
	require.NoError(t, err)
	os.Remove(crtF.Name())
	defer os.Remove(crtF.Name())

	// out-crt on stdout, out-key on disk
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}
	require.NoError(t, ca([]string{"-name", "test-ca", "-duration", "1h", "-out-crt", "-", "-out-key", keyF.Name()}, ob, eb, nopw))
	assert.Empty(t, eb.String())
	c, _, err := cert.UnmarshalCertificateFromPEM(ob.Bytes())
	require.NoError(t, err)
	assert.True(t, c.IsCA())
	assert.Equal(t, "test-ca", c.Name())

	// out-key on stdout, out-crt on disk
	os.Remove(keyF.Name())
	ob.Reset()
	eb.Reset()
	require.NoError(t, ca([]string{"-name", "test-ca", "-duration", "1h", "-out-crt", crtF.Name(), "-out-key", "-"}, ob, eb, nopw))
	assert.Empty(t, eb.String())
	_, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(ob.Bytes())
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_CURVE25519, curve)

	// dual stdout is rejected up front
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	require.EqualError(t,
		ca([]string{"-name", "test-ca", "-duration", "1h", "-out-crt", "-", "-out-key", "-"}, ob, eb, nopw),
		`-out-key and -out-crt both set to "-", only one output may write to stdout`)
	assert.Empty(t, ob.String())

	// an output conflict combined with -encrypt must error BEFORE prompting
	// for a passphrase; pr would record any read attempt
	tracker := &trackingPasswordReader{}
	ob.Reset()
	eb.Reset()
	require.EqualError(t,
		ca([]string{"-name", "test-ca", "-duration", "1h", "-encrypt", "-out-crt", "-", "-out-key", "-"}, ob, eb, tracker),
		`-out-key and -out-crt both set to "-", only one output may write to stdout`)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	assert.Zero(t, tracker.calls, "passphrase prompt should not have been called")
}

type trackingPasswordReader struct {
	calls int
}

func (pr *trackingPasswordReader) ReadPassword() ([]byte, error) {
	pr.calls++
	return []byte(""), nil
}

func TestParseArgonParameters_Validation(t *testing.T) {
	tests := []struct {
		name             string
		memory           uint
		parallelism      uint
		iterations       uint
		wantErr          bool
		wantErrSubstring string
		wantOut          struct {
			memory      uint32
			parallelism uint8
			iterations  uint32
		}
	}{
		{
			name:             "memory == 0 is rejected",
			memory:           0,
			parallelism:      4,
			iterations:       3,
			wantErr:          true,
			wantErrSubstring: "-argon-memory",
		},
		{
			name:             "parallelism == 0 is rejected",
			memory:           65536,
			parallelism:      0,
			iterations:       3,
			wantErr:          true,
			wantErrSubstring: "-argon-parallelism",
		},
		{
			name:             "parallelism > MaxUint8 is rejected (cast on next line would truncate)",
			memory:           65536,
			parallelism:      256,
			iterations:       3,
			wantErr:          true,
			wantErrSubstring: "-argon-parallelism",
		},
		{
			name:             "parallelism = 1000 is rejected (mid-range silent-truncation hazard)",
			memory:           65536,
			parallelism:      1000,
			iterations:       3,
			wantErr:          true,
			wantErrSubstring: "-argon-parallelism",
		},
		{
			name:             "iterations == 0 is rejected",
			memory:           65536,
			parallelism:      4,
			iterations:       0,
			wantErr:          true,
			wantErrSubstring: "-argon-iterations",
		},
		{
			name:        "valid params construct an Argon2Parameters",
			memory:      65536,
			parallelism: 4,
			iterations:  3,
			wantOut: struct {
				memory      uint32
				parallelism uint8
				iterations  uint32
			}{65536, 4, 3},
		},
		{
			name:        "max-uint8 parallelism is accepted (boundary just below the rejection threshold)",
			memory:      65536,
			parallelism: 255,
			iterations:  3,
			wantOut: struct {
				memory      uint32
				parallelism uint8
				iterations  uint32
			}{65536, 255, 3},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseArgonParameters(tc.memory, tc.parallelism, tc.iterations)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrSubstring,
					"error message must name the offending flag so the user can find it")
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tc.wantOut.memory, got.Memory)
			assert.Equal(t, tc.wantOut.parallelism, got.Parallelism)
			assert.Equal(t, tc.wantOut.iterations, got.Iterations)
		})
	}
}
