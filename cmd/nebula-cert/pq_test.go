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

func readCert(t *testing.T, path string) cert.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	c, _, err := cert.UnmarshalCertificateFromPEM(b)
	require.NoError(t, err)
	return c
}

func readSigningKeyFile(t *testing.T, path string) (cert.Curve, []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	k, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(b)
	require.NoError(t, err)
	return curve, k
}

func readKeyFile(t *testing.T, path string) (cert.Curve, []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	k, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(b)
	require.NoError(t, err)
	return curve, k
}

func verifiedBy(t *testing.T, c cert.Certificate, cas ...cert.Certificate) error {
	t.Helper()
	pool := cert.NewCAPool()
	for _, ca := range cas {
		require.NoError(t, pool.AddCA(ca))
	}
	_, err := pool.VerifyCertificate(time.Now(), c)
	return err
}

func TestPQ_CAAndSign(t *testing.T) {
	for _, curve := range []string{"25519", "P256"} {
		t.Run(curve, func(t *testing.T) {
			dir := t.TempDir()
			ob, eb := &bytes.Buffer{}, &bytes.Buffer{}
			nopw := &StubPasswordReader{}
			p := func(n string) string { return filepath.Join(dir, n) }

			require.NoError(t, ca([]string{"-version", "3", "-curve", curve, "-name", "pq ca", "-out-crt", p("ca.crt"), "-out-key", p("ca.key")}, ob, eb, nopw))
			caCrt := readCert(t, p("ca.crt"))
			assert.Equal(t, cert.Version3, caCrt.Version())
			caCurve, caKey := readSigningKeyFile(t, p("ca.key"))
			require.NoError(t, caCrt.VerifyPrivateKey(caCurve, caKey))

			// A v3 CA signs v3 by default.
			require.NoError(t, signCert([]string{"-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "host", "-networks", "10.1.0.1/16", "-out-crt", p("host.crt"), "-out-key", p("host.key")}, ob, eb, nopw))
			host := readCert(t, p("host.crt"))
			assert.Equal(t, cert.Version3, host.Version())
			hostCurve, hostKey := readKeyFile(t, p("host.key"))
			require.NoError(t, host.VerifyPrivateKey(hostCurve, hostKey))
			require.NoError(t, verifiedBy(t, host, caCrt))

			// And v2 as its v2 form.
			require.NoError(t, signCert([]string{"-version", "2", "-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "old", "-networks", "10.1.0.2/16", "-out-crt", p("old.crt"), "-out-key", p("old.key")}, ob, eb, nopw))
			old := readCert(t, p("old.crt"))
			assert.Equal(t, cert.Version2, old.Version())
			require.NoError(t, verifiedBy(t, old, cert.V2Form(caCrt)))

			// keygen -version 3 makes keys for v3 certificates, and only those.
			require.NoError(t, keygen([]string{"-version", "3", "-curve", curve, "-out-key", p("k3.key"), "-out-pub", p("k3.pub")}, ob, eb))
			require.NoError(t, signCert([]string{"-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "k3", "-networks", "10.1.0.3/16", "-in-pub", p("k3.pub"), "-out-crt", p("k3.crt")}, ob, eb, nopw))
			_, k3 := readKeyFile(t, p("k3.key"))
			require.NoError(t, readCert(t, p("k3.crt")).VerifyPrivateKey(hostCurve, k3))
			require.ErrorContains(t, signCert([]string{"-version", "2", "-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "x", "-networks", "10.1.0.4/16", "-in-pub", p("k3.pub"), "-out-crt", p("x.crt")}, ob, eb, nopw), "only version 3 certificates carry")
		})
	}
}

func TestPQ_SignErrors(t *testing.T) {
	dir := t.TempDir()
	ob, eb := &bytes.Buffer{}, &bytes.Buffer{}
	nopw := &StubPasswordReader{}
	p := func(n string) string { return filepath.Join(dir, n) }

	require.NoError(t, ca([]string{"-name", "v2 ca", "-out-crt", p("ca.crt"), "-out-key", p("ca.key")}, ob, eb, nopw))
	require.ErrorContains(t, signCert([]string{"-version", "3", "-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "h", "-networks", "10.1.0.1/16", "-out-crt", p("h.crt"), "-out-key", p("h.key")}, ob, eb, nopw), "must be signed by a version 3 CA")

	require.NoError(t, keygen([]string{"-out-key", p("k.key"), "-out-pub", p("k.pub")}, ob, eb))
	require.NoError(t, ca([]string{"-version", "3", "-name", "v3 ca", "-out-crt", p("ca3.crt"), "-out-key", p("ca3.key")}, ob, eb, nopw))
	require.ErrorContains(t, signCert([]string{"-ca-crt", p("ca3.crt"), "-ca-key", p("ca3.key"), "-name", "h", "-networks", "10.1.0.1/16", "-in-pub", p("k.pub"), "-out-crt", p("h3.crt")}, ob, eb, nopw), "need an in-pub from keygen -version 3")

	// keygen -in-key refuses a key that already has a post-quantum key.
	require.NoError(t, keygen([]string{"-version", "3", "-out-key", p("k3.key"), "-out-pub", p("k3.pub")}, ob, eb))
	require.ErrorContains(t, keygen([]string{"-in-key", p("k3.key"), "-out-key", p("k33.key"), "-out-pub", p("k33.pub")}, ob, eb), "already have a post-quantum key")
}

func TestPQ_SuiteFlag(t *testing.T) {
	dir := t.TempDir()
	ob, eb := &bytes.Buffer{}, &bytes.Buffer{}
	nopw := &StubPasswordReader{}
	p := func(n string) string { return filepath.Join(dir, n) }

	// The suite can be named, case aside, and the certificates a CA signs share its suite.
	require.NoError(t, ca([]string{"-version", "3", "-pq-suite", "mlkem1024_mldsa87", "-name", "ca", "-out-crt", p("ca.crt"), "-out-key", p("ca.key")}, ob, eb, nopw))
	assert.Equal(t, cert.PQSuite_MLKEM1024_MLDSA87, cert.PQSuiteOf(readCert(t, p("ca.crt"))))
	require.NoError(t, keygen([]string{"-version", "3", "-pq-suite", "MLKEM1024_MLDSA87", "-out-key", p("k.key"), "-out-pub", p("k.pub")}, ob, eb))
	require.NoError(t, signCert([]string{"-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "h", "-networks", "10.1.0.1/16", "-in-pub", p("k.pub"), "-out-crt", p("h.crt")}, ob, eb, nopw))
	assert.Equal(t, cert.PQSuite_MLKEM1024_MLDSA87, cert.PQSuiteOf(readCert(t, p("h.crt"))))

	// Printing shows it.
	ob.Reset()
	require.NoError(t, printCert([]string{"-json", "-path", p("h.crt")}, ob, eb))
	assert.Contains(t, ob.String(), `"pqSuite":"MLKEM1024_MLDSA87"`)

	// Unknown suites, and suites where there is no post-quantum key, are refused.
	require.ErrorContains(t, ca([]string{"-version", "3", "-pq-suite", "mlkem768_mldsa65", "-name", "x", "-out-crt", p("x.crt"), "-out-key", p("x.key")}, ob, eb, nopw), "unknown post-quantum suite")
	require.ErrorContains(t, ca([]string{"-pq-suite", "MLKEM1024_MLDSA87", "-name", "x", "-out-crt", p("x.crt"), "-out-key", p("x.key")}, ob, eb, nopw), "only for -version 3")
	require.ErrorContains(t, keygen([]string{"-pq-suite", "MLKEM1024_MLDSA87", "-out-key", p("x.key"), "-out-pub", p("x.pub")}, ob, eb), "only for -version 3")

	// A host takes its CA's suite when extended.
	require.NoError(t, ca([]string{"-name", "ca2", "-out-crt", p("ca2.crt"), "-out-key", p("ca2.key")}, ob, eb, nopw))
	require.NoError(t, signCert([]string{"-ca-crt", p("ca2.crt"), "-ca-key", p("ca2.key"), "-name", "h2", "-networks", "10.1.0.2/16", "-out-crt", p("h2.crt"), "-out-key", p("h2.key")}, ob, eb, nopw))
	require.NoError(t, pqExtend([]string{"-in-crt", p("ca2.crt"), "-ca-key", p("ca2.key"), "-pq-suite", "MLKEM1024_MLDSA87", "-out-crt", p("ca23.crt"), "-out-key", p("ca23.key")}, ob, eb, nopw))
	require.NoError(t, keygen([]string{"-in-key", p("h2.key"), "-out-key", p("h23.key"), "-out-pub", p("h23.pub")}, ob, eb))
	require.ErrorContains(t, pqExtend([]string{"-in-crt", p("h2.crt"), "-in-pub", p("h23.pub"), "-ca-crt", p("ca23.crt"), "-ca-key", p("ca23.key"), "-pq-suite", "MLKEM1024_MLDSA87", "-out-crt", p("h23.crt")}, ob, eb, nopw), "a host takes its CA's suite")
}

// TestPQ_Extend upgrades a v2 CA and a host in place, the way a running network migrates.
func TestPQ_Extend(t *testing.T) {
	for _, encrypt := range []bool{false, true} {
		name := "plain"
		if encrypt {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			ob, eb := &bytes.Buffer{}, &bytes.Buffer{}
			pw := &StubPasswordReader{}
			if encrypt {
				t.Setenv("NEBULA_CA_PASSPHRASE", "hunter2")
			}
			p := func(n string) string { return filepath.Join(dir, n) }

			caArgs := []string{"-name", "ca", "-out-crt", p("ca.crt"), "-out-key", p("ca.key"), "-argon-memory", "1024"}
			if encrypt {
				caArgs = append(caArgs, "-encrypt")
			}
			require.NoError(t, ca(caArgs, ob, eb, pw))
			require.NoError(t, signCert([]string{"-ca-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-name", "host", "-networks", "10.1.0.1/16", "-out-crt", p("host.crt"), "-out-key", p("host.key")}, ob, eb, pw))
			ca2 := readCert(t, p("ca.crt"))
			host2 := readCert(t, p("host.crt"))

			// The CA extends itself.
			require.NoError(t, pqExtend([]string{"-in-crt", p("ca.crt"), "-ca-key", p("ca.key"), "-out-crt", p("ca3.crt"), "-out-key", p("ca3.key")}, ob, eb, pw))
			ca3 := readCert(t, p("ca3.crt"))
			assert.Equal(t, cert.Version3, ca3.Version())
			assertSameCert(t, ca2, cert.V2Form(ca3))
			raw, err := os.ReadFile(p("ca3.key"))
			require.NoError(t, err)
			curve, ca3Key, _, err := readSigningKey(raw, eb, pw)
			require.NoError(t, err)
			require.NoError(t, ca3.VerifyPrivateKey(curve, ca3Key))
			if encrypt {
				_, _, _, err = cert.UnmarshalSigningPrivateKeyFromPEM(raw)
				require.ErrorIs(t, err, cert.ErrPrivateKeyEncrypted, "an encrypted ca-key stays encrypted")
			}

			// The host gets a post-quantum key on top of the one it has, and the CA signs it.
			require.NoError(t, keygen([]string{"-in-key", p("host.key"), "-out-key", p("host3.key"), "-out-pub", p("host3.pub")}, ob, eb))
			require.NoError(t, pqExtend([]string{"-in-crt", p("host.crt"), "-in-pub", p("host3.pub"), "-ca-crt", p("ca3.crt"), "-ca-key", p("ca3.key"), "-out-crt", p("host3.crt")}, ob, eb, pw))
			host3 := readCert(t, p("host3.crt"))
			assert.Equal(t, cert.Version3, host3.Version())
			assertSameCert(t, host2, cert.V2Form(host3))
			hostCurve, host3Key := readKeyFile(t, p("host3.key"))
			require.NoError(t, host3.VerifyPrivateKey(hostCurve, host3Key))
			require.NoError(t, verifiedBy(t, host3, ca3))
			require.NoError(t, verifiedBy(t, host2, ca2), "existing trust is untouched")

			// print leads a version 3 certificate with both fingerprints and says which one blocks both forms.
			ob.Reset()
			require.NoError(t, printCert([]string{"-path", p("host3.crt")}, ob, eb))
			fp3, err := host3.Fingerprint()
			require.NoError(t, err)
			fp2, err := host2.Fingerprint()
			require.NoError(t, err)
			printed := ob.String()
			lead := "Fingerprint:    " + fp3 + "\nv2 fingerprint: " + fp2 + "  (block this one in pki.blocklist, it covers both forms)\n"
			require.Greater(t, len(printed), len(lead))
			assert.Equal(t, lead, printed[:len(lead)])

			// Someone else's key does not extend this host.
			require.NoError(t, keygen([]string{"-version", "3", "-out-key", p("other.key"), "-out-pub", p("other.pub")}, ob, eb))
			require.ErrorContains(t, pqExtend([]string{"-in-crt", p("host.crt"), "-in-pub", p("other.pub"), "-ca-crt", p("ca3.crt"), "-ca-key", p("ca3.key"), "-out-crt", p("bad.crt")}, ob, eb, pw), "does not extend the key")

			// Nor does the v2 CA key, or a v3 certificate.
			require.ErrorContains(t, pqExtend([]string{"-in-crt", p("host.crt"), "-in-pub", p("host3.pub"), "-ca-crt", p("ca3.crt"), "-ca-key", p("ca.key"), "-out-crt", p("bad.crt")}, ob, eb, pw), "does not match ca-key")
			require.ErrorContains(t, pqExtend([]string{"-in-crt", p("host3.crt"), "-in-pub", p("host3.pub"), "-ca-crt", p("ca3.crt"), "-ca-key", p("ca3.key"), "-out-crt", p("bad.crt")}, ob, eb, pw), "only version 2 certificates")
		})
	}
}

func assertSameCert(t *testing.T, want, got cert.Certificate) {
	t.Helper()
	wb, err := want.Marshal()
	require.NoError(t, err)
	gb, err := got.Marshal()
	require.NoError(t, err)
	assert.Equal(t, wb, gb)
}
