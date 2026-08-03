package nebula

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	cert_test "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestMain_ConfigTestReleasesItsGoroutines pins the rule that Main only leaves goroutines running
// when it hands back a Control to stop them with.
//
// A config test gets no Control, so anything it started had nothing to stop it: the lighthouse
// query worker, and a hostname resolver per dns named static host, ran for the life of the
// process. That matters to every embedder that validates a config in process rather than by
// exec'ing, dnclient and the apple clients included, because they do it on each config load and
// the leak accumulates.
func TestMain_ConfigTestReleasesItsGoroutines(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	l := test.NewLogger()
	dir := t.TempDir()

	before := time.Now().Add(-time.Hour)
	after := time.Now().Add(time.Hour)
	ca, _, caKey, caPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, before, after, nil, nil, nil)
	networks := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
	_, _, keyPEM, certPEM := cert_test.NewTestCert(
		cert.Version2, cert.Curve_CURVE25519, ca, caKey, "config-test", before, after, networks, nil, nil)

	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	// A static host by address, not by name: the query worker is the goroutine under test and a
	// hostname would drag a real dns lookup into a unit test.
	configBody := fmt.Sprintf(`
pki:
  ca: %s
  cert: %s
  key: %s
static_host_map:
  "10.0.0.2": ["192.0.2.1:4242"]
lighthouse:
  hosts:
    - "10.0.0.2"
listen:
  host: 127.0.0.1
  port: 0
tun:
  disabled: true
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
`, caPath, certPath, keyPath)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte(configBody), 0o600))

	c := config.NewC(l)
	require.NoError(t, c.Load(dir))

	ctrl, err := Main(c, true, "config-test", l, nil)
	require.NoError(t, err)
	require.Nil(t, ctrl, "a config test hands back nothing to stop, so it must stop itself")
}
