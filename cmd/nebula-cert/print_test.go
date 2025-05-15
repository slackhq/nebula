package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_printSummary(t *testing.T) {
	assert.Equal(t, "print <flags>: prints details about a certificate", printSummary())
}

func Test_printHelp(t *testing.T) {
	ob := &bytes.Buffer{}
	printHelp(ob)
	assert.Equal(
		t,
		"Usage of "+os.Args[0]+" print <flags>: prints details about a certificate\n"+
			"  -json\n"+
			"    \tOptional: outputs certificates in json format\n"+
			"  -out-qr string\n"+
			"    \tOptional: output a qr code image (png) of the certificate\n"+
			"  -path string\n"+
			"    \tRequired: path to the certificate\n",
		ob.String(),
	)
}

func Test_printCert(t *testing.T) {
	// Orient our local time and avoid headaches
	time.Local = time.UTC
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}

	// no path
	err := printCert([]string{}, ob, eb)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	assertHelpError(t, err, "-path is required")

	// no cert at path
	ob.Reset()
	eb.Reset()
	err = printCert([]string{"-path", "does_not_exist"}, ob, eb)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	require.EqualError(t, err, "unable to read cert; open does_not_exist: "+NoSuchFileError)

	// invalid cert at path
	ob.Reset()
	eb.Reset()
	tf, err := os.CreateTemp("", "print-cert")
	require.NoError(t, err)
	defer os.Remove(tf.Name())

	tf.WriteString("-----BEGIN NOPE-----")
	err = printCert([]string{"-path", tf.Name()}, ob, eb)
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())
	require.EqualError(t, err, "error while unmarshaling cert: input did not contain a valid PEM encoded block")

	// test multiple certs
	ob.Reset()
	eb.Reset()
	tf.Truncate(0)
	tf.Seek(0, 0)
	ca, caKey := NewTestCaCert("test ca", nil, nil, time.Time{}, time.Time{}, nil, nil, nil)
	c, _ := NewTestCert(ca, caKey, "test", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.0.0.123/8")}, nil, []string{"hi"})

	p, _ := c.MarshalPEM()
	tf.Write(p)
	tf.Write(p)
	tf.Write(p)

	err = printCert([]string{"-path", tf.Name()}, ob, eb)
	fp, _ := c.Fingerprint()
	pk := hex.EncodeToString(c.PublicKey())
	sig := hex.EncodeToString(c.Signature())
	require.NoError(t, err)
	assert.Equal(
		t,
		//"NebulaCertificate {\n\tDetails {\n\t\tName: test\n\t\tIps: []\n\t\tSubnets: []\n\t\tGroups: [\n\t\t\t\"hi\"\n\t\t]\n\t\tNot before: 0001-01-01 00:00:00 +0000 UTC\n\t\tNot After: 0001-01-01 00:00:00 +0000 UTC\n\t\tIs CA: false\n\t\tIssuer: "+c.Issuer()+"\n\t\tPublic key: "+pk+"\n\t\tCurve: CURVE25519\n\t}\n\tFingerprint: "+fp+"\n\tSignature: "+sig+"\n}\nNebulaCertificate {\n\tDetails {\n\t\tName: test\n\t\tIps: []\n\t\tSubnets: []\n\t\tGroups: [\n\t\t\t\"hi\"\n\t\t]\n\t\tNot before: 0001-01-01 00:00:00 +0000 UTC\n\t\tNot After: 0001-01-01 00:00:00 +0000 UTC\n\t\tIs CA: false\n\t\tIssuer: "+c.Issuer()+"\n\t\tPublic key: "+pk+"\n\t\tCurve: CURVE25519\n\t}\n\tFingerprint: "+fp+"\n\tSignature: "+sig+"\n}\nNebulaCertificate {\n\tDetails {\n\t\tName: test\n\t\tIps: []\n\t\tSubnets: []\n\t\tGroups: [\n\t\t\t\"hi\"\n\t\t]\n\t\tNot before: 0001-01-01 00:00:00 +0000 UTC\n\t\tNot After: 0001-01-01 00:00:00 +0000 UTC\n\t\tIs CA: false\n\t\tIssuer: "+c.Issuer()+"\n\t\tPublic key: "+pk+"\n\t\tCurve: CURVE25519\n\t}\n\tFingerprint: "+fp+"\n\tSignature: "+sig+"\n}\n",
		`{
	"details": {
		"curve": "CURVE25519",
		"groups": [
			"hi"
		],
		"isCa": false,
		"issuer": "`+c.Issuer()+`",
		"name": "test",
		"networks": [
			"10.0.0.123/8"
		],
		"notAfter": "0001-01-01T00:00:00Z",
		"notBefore": "0001-01-01T00:00:00Z",
		"publicKey": "`+pk+`",
		"unsafeNetworks": []
	},
	"fingerprint": "`+fp+`",
	"signature": "`+sig+`",
	"version": 1
}
{
	"details": {
		"curve": "CURVE25519",
		"groups": [
			"hi"
		],
		"isCa": false,
		"issuer": "`+c.Issuer()+`",
		"name": "test",
		"networks": [
			"10.0.0.123/8"
		],
		"notAfter": "0001-01-01T00:00:00Z",
		"notBefore": "0001-01-01T00:00:00Z",
		"publicKey": "`+pk+`",
		"unsafeNetworks": []
	},
	"fingerprint": "`+fp+`",
	"signature": "`+sig+`",
	"version": 1
}
{
	"details": {
		"curve": "CURVE25519",
		"groups": [
			"hi"
		],
		"isCa": false,
		"issuer": "`+c.Issuer()+`",
		"name": "test",
		"networks": [
			"10.0.0.123/8"
		],
		"notAfter": "0001-01-01T00:00:00Z",
		"notBefore": "0001-01-01T00:00:00Z",
		"publicKey": "`+pk+`",
		"unsafeNetworks": []
	},
	"fingerprint": "`+fp+`",
	"signature": "`+sig+`",
	"version": 1
}
`,
		ob.String(),
	)
	assert.Empty(t, eb.String())

	// test json
	ob.Reset()
	eb.Reset()
	tf.Truncate(0)
	tf.Seek(0, 0)
	tf.Write(p)
	tf.Write(p)
	tf.Write(p)

	err = printCert([]string{"-json", "-path", tf.Name()}, ob, eb)
	fp, _ = c.Fingerprint()
	pk = hex.EncodeToString(c.PublicKey())
	sig = hex.EncodeToString(c.Signature())
	require.NoError(t, err)
	assert.Equal(
		t,
		`[{"details":{"curve":"CURVE25519","groups":["hi"],"isCa":false,"issuer":"`+c.Issuer()+`","name":"test","networks":["10.0.0.123/8"],"notAfter":"0001-01-01T00:00:00Z","notBefore":"0001-01-01T00:00:00Z","publicKey":"`+pk+`","unsafeNetworks":[]},"fingerprint":"`+fp+`","signature":"`+sig+`","version":1},{"details":{"curve":"CURVE25519","groups":["hi"],"isCa":false,"issuer":"`+c.Issuer()+`","name":"test","networks":["10.0.0.123/8"],"notAfter":"0001-01-01T00:00:00Z","notBefore":"0001-01-01T00:00:00Z","publicKey":"`+pk+`","unsafeNetworks":[]},"fingerprint":"`+fp+`","signature":"`+sig+`","version":1},{"details":{"curve":"CURVE25519","groups":["hi"],"isCa":false,"issuer":"`+c.Issuer()+`","name":"test","networks":["10.0.0.123/8"],"notAfter":"0001-01-01T00:00:00Z","notBefore":"0001-01-01T00:00:00Z","publicKey":"`+pk+`","unsafeNetworks":[]},"fingerprint":"`+fp+`","signature":"`+sig+`","version":1}]
`,
		ob.String(),
	)
	assert.Empty(t, eb.String())
}

// NewTestCaCert will generate a CA cert
func NewTestCaCert(name string, pubKey, privKey []byte, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (cert.Certificate, []byte) {
	var err error
	if pubKey == nil || privKey == nil {
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
	}

	t := &cert.TBSCertificate{
		Version:        cert.Version1,
		Name:           name,
		NotBefore:      time.Unix(before.Unix(), 0),
		NotAfter:       time.Unix(after.Unix(), 0),
		PublicKey:      pubKey,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		IsCA:           true,
	}

	c, err := t.Sign(nil, cert.Curve_CURVE25519, privKey)
	if err != nil {
		panic(err)
	}

	return c, privKey
}

func NewTestCert(ca cert.Certificate, signerKey []byte, name string, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (cert.Certificate, []byte) {
	if before.IsZero() {
		before = ca.NotBefore()
	}

	if after.IsZero() {
		after = ca.NotAfter()
	}

	if len(networks) == 0 {
		networks = []netip.Prefix{netip.MustParsePrefix("10.0.0.123/8")}
	}

	pub, rawPriv := x25519Keypair()
	nc := &cert.TBSCertificate{
		Version:        cert.Version1,
		Name:           name,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		NotBefore:      time.Unix(before.Unix(), 0),
		NotAfter:       time.Unix(after.Unix(), 0),
		PublicKey:      pub,
		IsCA:           false,
	}

	c, err := nc.Sign(ca, ca.Curve(), signerKey)
	if err != nil {
		panic(err)
	}

	return c, rawPriv
}
