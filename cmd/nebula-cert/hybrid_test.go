package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skipWithoutHybrid(t *testing.T) {
	t.Helper()
	if err := cert.HybridAvailable(); err != nil {
		t.Skip(err)
	}
}

// A hybrid CA signs hybrid host certificates, made here or from a keygen public key, and they verify against it.
func Test_hybridCurve(t *testing.T) {
	skipWithoutHybrid(t)
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	ob, eb := &bytes.Buffer{}, &bytes.Buffer{}
	nopw := &StubPasswordReader{}

	require.NoError(t, ca([]string{"-name", "hybrid ca", "-curve", hybridCurveFlag, "-duration", "1h", "-groups", "a,b", "-out-crt", p("ca.crt"), "-out-key", p("ca.key")}, ob, eb, nopw))
	rb, err := os.ReadFile(p("ca.key"))
	require.NoError(t, err)
	caKey, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(rb)
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_P384_MLKEM1024_MLDSA87, curve)
	assert.Len(t, caKey, cert.HybridSigningPrivateKeySize)
	rb, err = os.ReadFile(p("ca.crt"))
	require.NoError(t, err)
	caCrt, _, err := cert.UnmarshalCertificateFromPEM(rb)
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_P384_MLKEM1024_MLDSA87, caCrt.Curve())
	assert.Equal(t, cert.Version2, caCrt.Version())
	require.NoError(t, caCrt.VerifyPrivateKey(curve, caKey))
	pool := cert.NewCAPool()
	require.NoError(t, pool.AddCA(caCrt))

	// Signing makes a hybrid host key.
	require.NoError(t, signCert([]string{"-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "host", "-networks", "10.1.0.1/16", "-groups", "a", "-out-crt", p("host.crt"), "-out-key", p("host.key")}, ob, eb, nopw))
	rb, err = os.ReadFile(p("host.key"))
	require.NoError(t, err)
	hostKey, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(rb)
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_P384_MLKEM1024_MLDSA87, curve)
	rb, err = os.ReadFile(p("host.crt"))
	require.NoError(t, err)
	host, _, err := cert.UnmarshalCertificateFromPEM(rb)
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_P384_MLKEM1024_MLDSA87, host.Curve())
	require.NoError(t, host.VerifyPrivateKey(curve, hostKey))
	_, err = pool.VerifyCertificate(time.Now(), host)
	require.NoError(t, err)

	// keygen and sign -in-pub.
	require.NoError(t, keygen([]string{"-curve", hybridCurveFlag, "-out-key", p("kg.key"), "-out-pub", p("kg.pub")}, ob, eb))
	require.NoError(t, signCert([]string{"-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "kg", "-networks", "10.1.0.2/16", "-in-pub", p("kg.pub"), "-out-crt", p("kg.crt")}, ob, eb, nopw))
	rb, err = os.ReadFile(p("kg.crt"))
	require.NoError(t, err)
	kg, _, err := cert.UnmarshalCertificateFromPEM(rb)
	require.NoError(t, err)
	rb, err = os.ReadFile(p("kg.key"))
	require.NoError(t, err)
	kgKey, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(rb)
	require.NoError(t, err)
	require.NoError(t, kg.VerifyPrivateKey(curve, kgKey))
	_, err = pool.VerifyCertificate(time.Now(), kg)
	require.NoError(t, err)

	// A classical public key does not go under a hybrid CA.
	require.NoError(t, keygen([]string{"-out-key", p("x.key"), "-out-pub", p("x.pub")}, ob, eb))
	require.EqualError(t, signCert([]string{"-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "x", "-networks", "10.1.0.3/16", "-in-pub", p("x.pub"), "-out-crt", p("x.crt")}, ob, eb, nopw), "curve of in-pub does not match ca")

	// The hybrid curve is v2 only.
	assertHelpError(t, signCert([]string{"-version", "1", "-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "v1", "-networks", "10.1.0.4/16", "-out-crt", p("v1.crt"), "-out-key", p("v1.key")}, ob, eb, nopw), "a "+hybridCurveFlag+" CA signs version 2 certificates only")
	assertHelpError(t, ca([]string{"-version", "1", "-name", "v1", "-curve", hybridCurveFlag, "-out-crt", p("v1ca.crt"), "-out-key", p("v1ca.key")}, ob, eb, nopw), "-curve "+hybridCurveFlag+" needs -version 2")
}

// An encrypted hybrid CA key signs once decrypted.
func Test_hybridCurveEncrypted(t *testing.T) {
	skipWithoutHybrid(t)
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	ob, eb := &bytes.Buffer{}, &bytes.Buffer{}
	pw := &StubPasswordReader{password: []byte("DO NOT USE THIS KEY")}

	require.NoError(t, ca([]string{"-name", "hybrid ca", "-curve", hybridCurveFlag, "-duration", "1h", "-encrypt", "-argon-memory", "1024", "-out-crt", p("ca.crt"), "-out-key", p("ca.key")}, ob, eb, pw))
	rb, err := os.ReadFile(p("ca.key"))
	require.NoError(t, err)
	_, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(rb)
	require.ErrorIs(t, err, cert.ErrPrivateKeyEncrypted)
	assert.Equal(t, cert.Curve_P384_MLKEM1024_MLDSA87, curve)

	require.NoError(t, signCert([]string{"-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "host", "-networks", "10.1.0.1/16", "-out-crt", p("host.crt"), "-out-key", p("host.key")}, ob, eb, pw))
	rb, err = os.ReadFile(p("host.crt"))
	require.NoError(t, err)
	host, _, err := cert.UnmarshalCertificateFromPEM(rb)
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_P384_MLKEM1024_MLDSA87, host.Curve())
}
