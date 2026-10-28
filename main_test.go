package nebula

import (
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/slackhq/nebula/udp"
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

func TestListenHostFromConfig(t *testing.T) {
	l := test.NewLogger()

	unset := netip.IPv6Unspecified()
	if runtime.GOOS == "openbsd" {
		unset = netip.IPv4Unspecified()
	}

	for _, tc := range []struct {
		host any
		want netip.Addr
	}{
		{nil, unset},
		{"", unset},
		{"::", netip.IPv6Unspecified()},
		{"[::]", netip.IPv6Unspecified()},
		{"0.0.0.0", netip.IPv4Unspecified()},
		{"127.0.0.1", netip.MustParseAddr("127.0.0.1")},
		{"::ffff:192.0.2.1", netip.MustParseAddr("192.0.2.1")},
		{"2001:db8::1", netip.MustParseAddr("2001:db8::1")},
	} {
		t.Run(fmt.Sprint(tc.host), func(t *testing.T) {
			c := config.NewC(l)
			if tc.host != nil {
				c.Settings["listen"] = map[string]any{"host": tc.host}
			}
			got, err := listenHostFromConfig(c)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestListenWithIPv4Fallback(t *testing.T) {
	l := test.NewLogger()
	errNoV6 := errors.New("address family not supported")
	errNoV4 := errors.New("address in use")

	for _, tc := range []struct {
		name   string
		listen string
		fail   map[netip.Addr]error
		tried  []string
		want   string
		err    error
	}{
		{name: "ipv6 wildcard works", listen: "[::]:4242", tried: []string{"[::]:4242"}, want: "[::]:4242"},
		{
			name: "ipv6 wildcard falls back", listen: "[::]:4242", fail: map[netip.Addr]error{netip.IPv6Unspecified(): errNoV6},
			tried: []string{"[::]:4242", "0.0.0.0:4242"}, want: "0.0.0.0:4242",
		},
		{
			name: "fallback fails too", listen: "[::]:0",
			fail:  map[netip.Addr]error{netip.IPv6Unspecified(): errNoV6, netip.IPv4Unspecified(): errNoV4},
			tried: []string{"[::]:0", "0.0.0.0:0"}, want: "0.0.0.0:0", err: errNoV4,
		},
		{
			name: "ipv4 wildcard does not retry", listen: "0.0.0.0:4242", fail: map[netip.Addr]error{netip.IPv4Unspecified(): errNoV4},
			tried: []string{"0.0.0.0:4242"}, want: "0.0.0.0:4242", err: errNoV4,
		},
		{
			name: "specific ipv6 address does not retry", listen: "[2001:db8::1]:4242",
			fail:  map[netip.Addr]error{netip.MustParseAddr("2001:db8::1"): errNoV6},
			tried: []string{"[2001:db8::1]:4242"}, want: "[2001:db8::1]:4242", err: errNoV6,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tried []string
			newListener := func(_ *slog.Logger, s udp.Settings) (udp.Conn, error) {
				tried = append(tried, s.Listen.String())
				return nil, tc.fail[s.Listen.Addr()]
			}

			s := udp.Settings{Listen: netip.MustParseAddrPort(tc.listen)}
			_, err := listenWithIPv4Fallback(l, &s, newListener)
			require.ErrorIs(t, err, tc.err)
			assert.Equal(t, tc.tried, tried)
			assert.Equal(t, tc.want, s.Listen.String())
		})
	}
}
