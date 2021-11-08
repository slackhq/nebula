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
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	assertHelpError(t, err, "-path is required")

	// no cert at path
	ob.Reset()
	eb.Reset()
	err = printCert([]string{"-path", "does_not_exist"}, ob, eb)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	assert.EqualError(t, err, "unable to read cert; open does_not_exist: "+NoSuchFileError)

	// invalid cert at path
	ob.Reset()
	eb.Reset()
	tf, err := ioutil.TempFile("", "print-cert")
	assert.Nil(t, err)
	defer os.Remove(tf.Name())

	tf.WriteString("-----BEGIN NOPE-----")
	err = printCert([]string{"-path", tf.Name()}, ob, eb)
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	assert.EqualError(t, err, "error while unmarshaling cert: input did not contain a valid PEM encoded block")

	// test multiple certs
	ob.Reset()
	eb.Reset()
	tf.Truncate(0)
	tf.Seek(0, 0)
	c := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      "test",
			Groups:    []string{"hi"},
			PublicKey: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2},
		},
		Signature: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2},
	}

	p, _ := c.MarshalToPEM()
	tf.Write(p)
	tf.Write(p)
	tf.Write(p)

	err = printCert([]string{"-path", tf.Name()}, ob, eb)
	assert.Nil(t, err)
	assert.Equal(
		t,
		"NebulaCertificate {\n\tDetails {\n\t\tName: test\n\t\tIps: []\n\t\tSubnets: []\n\t\tGroups: [\n\t\t\t\"hi\"\n\t\t]\n\t\tNot before: 0001-01-01 00:00:00 +0000 UTC\n\t\tNot After: 0001-01-01 00:00:00 +0000 UTC\n\t\tIs CA: false\n\t\tIssuer: \n\t\tPublic key: 0102030405060708090001020304050607080900010203040506070809000102\n\t}\n\tFingerprint: cc3492c0e9c48f17547f5987ea807462ebb3451e622590a10bb3763c344c82bd\n\tSignature: 0102030405060708090001020304050607080900010203040506070809000102\n}\nNebulaCertificate {\n\tDetails {\n\t\tName: test\n\t\tIps: []\n\t\tSubnets: []\n\t\tGroups: [\n\t\t\t\"hi\"\n\t\t]\n\t\tNot before: 0001-01-01 00:00:00 +0000 UTC\n\t\tNot After: 0001-01-01 00:00:00 +0000 UTC\n\t\tIs CA: false\n\t\tIssuer: \n\t\tPublic key: 0102030405060708090001020304050607080900010203040506070809000102\n\t}\n\tFingerprint: cc3492c0e9c48f17547f5987ea807462ebb3451e622590a10bb3763c344c82bd\n\tSignature: 0102030405060708090001020304050607080900010203040506070809000102\n}\nNebulaCertificate {\n\tDetails {\n\t\tName: test\n\t\tIps: []\n\t\tSubnets: []\n\t\tGroups: [\n\t\t\t\"hi\"\n\t\t]\n\t\tNot before: 0001-01-01 00:00:00 +0000 UTC\n\t\tNot After: 0001-01-01 00:00:00 +0000 UTC\n\t\tIs CA: false\n\t\tIssuer: \n\t\tPublic key: 0102030405060708090001020304050607080900010203040506070809000102\n\t}\n\tFingerprint: cc3492c0e9c48f17547f5987ea807462ebb3451e622590a10bb3763c344c82bd\n\tSignature: 0102030405060708090001020304050607080900010203040506070809000102\n}\n",
		ob.String(),
	)
	assert.Equal(t, "", eb.String())

	// test json
	ob.Reset()
	eb.Reset()
	tf.Truncate(0)
	tf.Seek(0, 0)
	c = cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      "test",
			Groups:    []string{"hi"},
			PublicKey: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2},
		},
		Signature: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2},
	}

	p, _ = c.MarshalToPEM()
	tf.Write(p)
	tf.Write(p)
	tf.Write(p)

	err = printCert([]string{"-json", "-path", tf.Name()}, ob, eb)
	assert.Nil(t, err)
	assert.Equal(
		t,
		"{\"details\":{\"groups\":[\"hi\"],\"ips\":[],\"isCa\":false,\"issuer\":\"\",\"name\":\"test\",\"notAfter\":\"0001-01-01T00:00:00Z\",\"notBefore\":\"0001-01-01T00:00:00Z\",\"publicKey\":\"0102030405060708090001020304050607080900010203040506070809000102\",\"subnets\":[]},\"fingerprint\":\"cc3492c0e9c48f17547f5987ea807462ebb3451e622590a10bb3763c344c82bd\",\"signature\":\"0102030405060708090001020304050607080900010203040506070809000102\"}\n{\"details\":{\"groups\":[\"hi\"],\"ips\":[],\"isCa\":false,\"issuer\":\"\",\"name\":\"test\",\"notAfter\":\"0001-01-01T00:00:00Z\",\"notBefore\":\"0001-01-01T00:00:00Z\",\"publicKey\":\"0102030405060708090001020304050607080900010203040506070809000102\",\"subnets\":[]},\"fingerprint\":\"cc3492c0e9c48f17547f5987ea807462ebb3451e622590a10bb3763c344c82bd\",\"signature\":\"0102030405060708090001020304050607080900010203040506070809000102\"}\n{\"details\":{\"groups\":[\"hi\"],\"ips\":[],\"isCa\":false,\"issuer\":\"\",\"name\":\"test\",\"notAfter\":\"0001-01-01T00:00:00Z\",\"notBefore\":\"0001-01-01T00:00:00Z\",\"publicKey\":\"0102030405060708090001020304050607080900010203040506070809000102\",\"subnets\":[]},\"fingerprint\":\"cc3492c0e9c48f17547f5987ea807462ebb3451e622590a10bb3763c344c82bd\",\"signature\":\"0102030405060708090001020304050607080900010203040506070809000102\"}\n",
		ob.String(),
	)
	assert.Equal(t, "", eb.String())
}
