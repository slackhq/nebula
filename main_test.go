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
	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestParseCpuAffinity(t *testing.T) {
	l := test.NewLogger()

	// newConfig returns a config.C with tun.cpu_affinity set to v. A nil v
	// leaves the key unset.
	newConfig := func(v any) *config.C {
		c := config.NewC(l)
		if v != nil {
			c.Settings["tun"] = map[string]any{"cpu_affinity": v}
		}
		return c
	}

	// unset -> nil (listenIn falls back to spreading across the allowed set)
	assert.Nil(t, parseCpuAffinity(newConfig(nil), l, 1))

	// Pick a CPU we're actually allowed to run on so a valid list survives
	// validation regardless of the host's affinity mask.
	allowed, _ := util.AllowedCPUs()
	validCPU := 0
	if len(allowed) > 0 {
		validCPU = allowed[0]
	}

	// valid list -> parsed through unchanged
	assert.Equal(t, []int{validCPU, validCPU}, parseCpuAffinity(newConfig([]any{validCPU, validCPU}), l, 2))

	// a negative entry is out of range on every platform -> disables the override
	assert.Nil(t, parseCpuAffinity(newConfig([]any{validCPU, -1}), l, 2))

	// a non-integer entry -> disables the override
	assert.Nil(t, parseCpuAffinity(newConfig([]any{validCPU, "not-a-cpu"}), l, 2))

	// a CPU id outside the allowed set -> disables the override. Only assertable
	// where we can enumerate the allowed set (e.g. linux); 1<<20 is far beyond
	// any representable CPU id so it can never be in the mask.
	if len(allowed) > 0 {
		assert.Nil(t, parseCpuAffinity(newConfig([]any{1 << 20}), l, 1))
	}
}

func TestConfigureAvoidCPUs(t *testing.T) {
	l := test.NewLogger()
	for _, tc := range []struct {
		value any
		valid bool
	}{
		{nil, true}, {[]any{}, true}, {"auto", false}, {"1,2", false}, {[]any{-1}, false}, {[]any{1.5}, false},
		{[]any{"2"}, false},
	} {
		c := config.NewC(l)
		if tc.value != nil {
			c.Settings["tun"] = map[string]any{"avoid_cpus": tc.value}
		}
		if err := configureAvoidCPUs(c, l, true); tc.valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err, "%v", tc.value)
		}
	}
}

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
	caPath, certPath, keyPath := writeTestPKI(t, dir)

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

// TestMain_configTestRejectsABadDNSStanza pins that a dns stanza that does not load stops Main, in a config test
// as at startup. That makes the config test the place an operator hears about it before deploying it.
func TestMain_configTestRejectsABadDNSStanza(t *testing.T) {
	l := test.NewLogger()
	caPath, certPath, keyPath := writeTestPKI(t, t.TempDir())

	c := config.NewC(l)
	require.NoError(t, c.LoadString(fmt.Sprintf(`
pki:
  ca: %s
  cert: %s
  key: %s
dns:
  enabled: true
  nameservers: [nope]
  search_domains: [mesh.example.com]
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
`, caPath, certPath, keyPath)))

	ctrl, err := Main(c, true, "config-test", l, nil)
	require.ErrorContains(t, err, "entry 1 in dns.nameservers is not an IP address")
	assert.Nil(t, ctrl)
}

// writeTestPKI writes a CA and a cert signed by it to dir, and returns their paths for a pki stanza.
func writeTestPKI(t *testing.T, dir string) (caPath, certPath, keyPath string) {
	t.Helper()
	before := time.Now().Add(-time.Hour)
	after := time.Now().Add(time.Hour)
	ca, _, caKey, caPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, before, after, nil, nil, nil)
	networks := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
	_, _, keyPEM, certPEM := cert_test.NewTestCert(
		cert.Version2, cert.Curve_CURVE25519, ca, caKey, "config-test", before, after, networks, nil, nil)

	caPath = filepath.Join(dir, "ca.pem")
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	return caPath, certPath, keyPath
}

func TestRedactSettings(t *testing.T) {
	pem := "-----BEGIN NEBULA X25519 PRIVATE KEY-----\nAAAA\n-----END NEBULA X25519 PRIVATE KEY-----\n"
	settings := map[string]any{
		"pki":    map[string]any{"key": pem, "cert": "/etc/nebula/host.crt"},
		"sshd":   map[string]any{"host_key": pem, "listen": "127.0.0.1:2222"},
		"punchy": map[string]any{"punch": true},
	}

	got := redactSettings(settings)
	assert.Equal(t, map[string]any{"key": "<inline>", "cert": "/etc/nebula/host.crt"}, got["pki"])
	assert.Equal(t, map[string]any{"host_key": "<inline>", "listen": "127.0.0.1:2222"}, got["sshd"])
	assert.Equal(t, settings["punchy"], got["punchy"])
	assert.Equal(t, pem, settings["pki"].(map[string]any)["key"], "the live config must not be modified")
	assert.Equal(t, pem, settings["sshd"].(map[string]any)["host_key"], "the live config must not be modified")

	paths := map[string]any{"pki": map[string]any{"key": "/etc/nebula/host.key"}, "sshd": map[string]any{"host_key": "/etc/nebula/ssh_host_ed25519_key"}}
	assert.Equal(t, paths, redactSettings(paths))
}

func TestMain_configTestRejectsZeroTimers(t *testing.T) {
	l := test.NewLogger()
	caPath, certPath, keyPath := writeTestPKI(t, t.TempDir())

	for stanza, want := range map[string]string{
		"handshakes:\n  try_interval: 0s":          "handshakes.try_interval must be greater than 0",
		"timers:\n  connection_alive_interval: 0":  "timers.connection_alive_interval must be greater than 0",
		"timers:\n  pending_deletion_interval: -1": "timers.pending_deletion_interval must be greater than 0",
	} {
		c := config.NewC(l)
		require.NoError(t, c.LoadString(fmt.Sprintf("pki:\n  ca: %s\n  cert: %s\n  key: %s\n%s\n", caPath, certPath, keyPath, stanza)))

		ctrl, err := Main(c, true, "config-test", l, nil)
		require.ErrorContains(t, err, want)
		assert.Nil(t, ctrl)
	}
}
