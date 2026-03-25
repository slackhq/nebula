package nebula

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	cert_test "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/require"
)

func BenchmarkReloadConfigWithCAs(b *testing.B) {
	prevProcs := runtime.GOMAXPROCS(1)
	b.Cleanup(func() { runtime.GOMAXPROCS(prevProcs) })

	for _, size := range []int{100, 250, 500, 1000, 5000} {
		b.Run(fmt.Sprintf("%dCAs", size), func(b *testing.B) {
			l := test.NewLogger()
			dir := b.TempDir()

			ca, caKey, caBundle := buildCABundle(b, size)
			caPath, certPath, keyPath := writePKIFiles(b, dir, ca, caKey, caBundle)

			configBody := fmt.Sprintf(`pki:
  ca: %s
  cert: %s
  key: %s
`, caPath, certPath, keyPath)

			configPath := filepath.Join(dir, "config.yml")
			require.NoError(b, os.WriteFile(configPath, []byte(configBody), 0o600))

			c := config.NewC(l)
			require.NoError(b, c.Load(dir))

			_, err := NewPKIFromConfig(l, c)
			require.NoError(b, err)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				c.ReloadConfig()
			}
		})
	}
}

func buildCABundle(b *testing.B, count int) (cert.Certificate, []byte, []byte) {
	b.Helper()
	require.GreaterOrEqual(b, count, 1)

	before := time.Now().Add(-24 * time.Hour)
	after := time.Now().Add(24 * time.Hour)

	ca, _, caKey, pem := cert_test.NewTestCaCert(
		cert.Version2,
		cert.Curve_CURVE25519,
		before,
		after,
		nil,
		nil,
		nil,
	)

	buf := bytes.NewBuffer(pem)

	for i := 1; i < count; i++ {
		_, _, _, extraPEM := cert_test.NewTestCaCert(
			cert.Version2,
			cert.Curve_CURVE25519,
			time.Now(),
			time.Now().Add(time.Hour),
			nil,
			nil,
			nil,
		)

		buf.Write(extraPEM)
	}

	return ca, caKey, buf.Bytes()
}

func writePKIFiles(b *testing.B, dir string, ca cert.Certificate, caKey []byte, caBundle []byte) (string, string, string) {
	b.Helper()

	networks := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}

	_, _, keyPEM, certPEM := cert_test.NewTestCert(
		cert.Version2,
		cert.Curve_CURVE25519,
		ca,
		caKey,
		"reload-benchmark",
		time.Now(),
		time.Now().Add(time.Hour),
		networks,
		nil,
		nil,
	)

	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	require.NoError(b, os.WriteFile(caPath, caBundle, 0o600))
	require.NoError(b, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(b, os.WriteFile(keyPath, keyPEM, 0o600))

	return caPath, certPath, keyPath
}
