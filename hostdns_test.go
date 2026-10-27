package nebula

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/DefinedNet/dnsconfig"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newHostDNSTestConfig(t *testing.T, raw string) *config.C {
	t.Helper()
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(raw))
	return c
}

const hostDNSEnabledYAML = `
dns:
  enabled: true
  nameservers:
    - 192.168.100.1
  search_domains:
    - mesh.example.com
`

func TestLoadHostDNSConfig_disabled(t *testing.T) {
	cfg, err := loadHostDNSConfig(newHostDNSTestConfig(t, `lighthouse: {}`), false)
	require.NoError(t, err)
	assert.False(t, cfg.enabled)
	assert.Equal(t, defaultHostDNSIdentity, cfg.Identity, "a disabled stanza still names its identity")

	// The resolver keys are not even looked at while disabled.
	cfg, err = loadHostDNSConfig(newHostDNSTestConfig(t, "dns:\n  enabled: false\n  nameservers: [not an ip]\n"), false)
	require.NoError(t, err)
	assert.False(t, cfg.enabled)
	assert.True(t, cfg.dns.IsZero())
}

func TestLoadHostDNSConfig_split(t *testing.T) {
	cfg, err := loadHostDNSConfig(newHostDNSTestConfig(t, `
dns:
  enabled: true
  nameservers: [192.168.100.1, "fd00::1"]
  match_domains: [mesh.example.com, 100.168.192.in-addr.arpa]
  search_domains: [mesh.example.com]
tun:
  dev: utun7
`), false)
	require.NoError(t, err)
	assert.True(t, cfg.enabled)
	assert.Equal(t, "utun7", cfg.Interface)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.100.1"), netip.MustParseAddr("fd00::1")}, cfg.dns.Nameservers)
	assert.Equal(t, []string{"mesh.example.com", "100.168.192.in-addr.arpa"}, cfg.dns.MatchDomains)
	assert.Equal(t, []string{"mesh.example.com"}, cfg.dns.SearchDomains)
	assert.True(t, cfg.dns.IsSplit())
}

func TestLoadHostDNSConfig_catchAll(t *testing.T) {
	cfg, err := loadHostDNSConfig(newHostDNSTestConfig(t, `
dns:
  enabled: true
  nameservers: [192.168.100.1]
  match_domains: []
`), false)
	require.NoError(t, err)
	assert.Empty(t, cfg.dns.MatchDomains)
	assert.False(t, cfg.dns.IsSplit())
}

func TestLoadHostDNSConfig_matchDomainsDefaultToSearchDomains(t *testing.T) {
	cfg, err := loadHostDNSConfig(newHostDNSTestConfig(t, hostDNSEnabledYAML), false)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.100.1")}, cfg.dns.Nameservers)
	assert.Equal(t, []string{"mesh.example.com"}, cfg.dns.SearchDomains)
	assert.Equal(t, []string{"mesh.example.com"}, cfg.dns.MatchDomains)
}

func TestLoadHostDNSConfig_identity(t *testing.T) {
	cfg, err := loadHostDNSConfig(newHostDNSTestConfig(t, "dns:\n  identity: nebula-two\n"), false)
	require.NoError(t, err)
	assert.Equal(t, "nebula-two", cfg.Identity)

	_, err = loadHostDNSConfig(newHostDNSTestConfig(t, "dns:\n  identity: Nebula\n"), false)
	require.ErrorContains(t, err, "dns.identity is not usable")
}

func TestLoadHostDNSConfig_errors(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want string
	}{
		"no nameservers": {"dns:\n  enabled: true\n  search_domains: [a.example]\n", "dns.nameservers must have at least one entry"},
		"bad nameserver": {"dns:\n  enabled: true\n  nameservers: [lighthouse.example]\n  search_domains: [a.example]\n",
			"entry 1 in dns.nameservers is not an IP address"},
		"no domains at all": {"dns:\n  enabled: true\n  nameservers: [192.168.100.1]\n",
			"dns requires search_domains or match_domains"},
		"search outside match": {"dns:\n  enabled: true\n  nameservers: [192.168.100.1]\n  match_domains: [a.example]\n  search_domains: [b.example]\n",
			"not under any MatchDomains"},
		"root match domain": {"dns:\n  enabled: true\n  nameservers: [192.168.100.1]\n  match_domains: [\".\"]\n",
			"root domain"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadHostDNSConfig(newHostDNSTestConfig(t, tc.raw), false)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// TestLoadHostDNSConfig_joinsErrors checks that loading keeps going after a key fails, so one bad stanza reports
// every problem at once, and that a lone error reaches the caller unwrapped.
func TestLoadHostDNSConfig_joinsErrors(t *testing.T) {
	_, err := loadHostDNSConfig(newHostDNSTestConfig(t, `
dns:
  enabled: true
  nameservers: [192.168.100.1, nope, 192.168.100.1:53]
  search_domains: ["", a.example]
  match_domains: ["."]
`), true)
	require.Error(t, err)
	for _, want := range []string{
		"dns.enabled requires a tun device, but tun.disabled is true",
		"entry 2 in dns.nameservers is not an IP address",
		"entry 3 in dns.nameservers is not an IP address",
		"entry 1 in dns.search_domains is empty",
		"entry 1 in dns.match_domains is the root domain",
	} {
		require.ErrorContains(t, err, want)
	}

	// A broken search_domains is the thing to fix; the fallback rule is not mentioned
	_, err = loadHostDNSConfig(newHostDNSTestConfig(t, "dns:\n  enabled: true\n  nameservers: [192.168.100.1]\n  search_domains: [\"\"]\n"), false)
	require.ErrorContains(t, err, "entry 1 in dns.search_domains is empty")
	assert.NotContains(t, err.Error(), "dns requires search_domains or match_domains")

	// A lone error is not wrapped in a join, so the caller's type switch still sees it
	_, err = loadHostDNSConfig(newHostDNSTestConfig(t, "dns:\n  enabled: true\n  nameservers: [nope]\n  match_domains: [a.example]\n"), false)
	ce, ok := err.(*util.ContextualError) //nolint:errorlint // the caller's type switch does not unwrap either
	require.True(t, ok, "a lone error must reach the caller unwrapped")
	assert.Equal(t, "entry 1 in dns.nameservers is not an IP address", ce.Context)
	assert.Equal(t, m{"addr": "nope"}, ce.Fields)

	// Names themselves are dnsconfig's to judge, once the stanza is otherwise whole
	_, err = loadHostDNSConfig(newHostDNSTestConfig(t, "dns:\n  enabled: true\n  nameservers: [192.168.100.1]\n  search_domains: [-nope.example]\n"), false)
	require.ErrorContains(t, err, "dns is not a valid DNS configuration")
	assert.ErrorContains(t, err, `SearchDomains[0] ("-nope.example") is not a valid domain`)
}

func TestLoadHostDNSConfig_listWrittenAsAScalar(t *testing.T) {
	_, err := loadHostDNSConfig(newHostDNSTestConfig(t, "dns:\n  enabled: true\n  nameservers: 192.168.100.1\n  search_domains: [a.example]\n"), false)
	require.ErrorContains(t, err, "dns.nameservers must be a list")

	// A one entry match_domains missing its dash must not read as the catch-all
	_, err = loadHostDNSConfig(newHostDNSTestConfig(t, "dns:\n  enabled: true\n  nameservers: [192.168.100.1]\n  match_domains: a.example\n"), false)
	require.ErrorContains(t, err, "dns.match_domains must be a list")
}

// newTestHostDNS builds a hostDNS over the no-op dnsconfig backend, which records goals without touching the host
// and so counts as usable whatever this one is.
func newTestHostDNS(t *testing.T, c *config.C) *hostDNS {
	t.Helper()
	s, err := newHostDNSFromConfig(context.Background(), test.NewLogger(), c)
	require.NoError(t, err)
	s.force = dnsconfig.BackendNoop
	t.Cleanup(s.Restore)
	return s
}

func TestHostDNS_tunDisabledIsFixedAtStart(t *testing.T) {
	c := newHostDNSTestConfig(t, hostDNSEnabledYAML+"tun:\n  disabled: true\n")
	_, err := newHostDNSFromConfig(context.Background(), test.NewLogger(), c)
	require.ErrorContains(t, err, "requires a tun device")

	// A disabled stanza loads, and tun.disabled only takes effect on restart, so flipping it on a reload does not
	// make a device appear
	c = newHostDNSTestConfig(t, "dns:\n  enabled: false\ntun:\n  disabled: true\n")
	s := newTestHostDNS(t, c)
	s.Start()
	res := c.ReloadConfigString(hostDNSEnabledYAML + "tun:\n  disabled: false\n")
	assert.True(t, res.Failed)
	assert.False(t, s.runCfg.enabled)
}

func TestHostDNS_recoverThenStart(t *testing.T) {
	c := newHostDNSTestConfig(t, hostDNSEnabledYAML)
	s := newTestHostDNS(t, c)

	// Recovery clears under the identity before anything else happens
	s.Recover()
	require.NotNil(t, s.mgr)
	assert.Equal(t, dnsconfig.GoalClear, s.mgr.Status().Goal)
	recovering := s.mgr

	// Start states the real goal on the same Manager
	s.Start()
	assert.Same(t, recovering, s.mgr)
	st := s.mgr.Status()
	assert.Equal(t, dnsconfig.GoalSet, st.Goal)
	assert.Equal(t, []string{"mesh.example.com."}, st.Desired.MatchDomains)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.100.1")}, st.Desired.Nameservers)
}

func TestHostDNS_recoverWithoutAStanza(t *testing.T) {
	c := newHostDNSTestConfig(t, "lighthouse: {}\n")
	s := newTestHostDNS(t, c)

	s.Recover()
	require.NotNil(t, s.mgr)
	assert.Equal(t, defaultHostDNSIdentity, s.mgrOpts.Identity)
	assert.Equal(t, dnsconfig.GoalClear, s.mgr.Status().Goal)

	// Start without a stanza keeps clearing
	s.Start()
	assert.Equal(t, dnsconfig.GoalClear, s.mgr.Status().Goal)
}

func TestHostDNS_recoverOnlyBeforeStart(t *testing.T) {
	c := newHostDNSTestConfig(t, hostDNSEnabledYAML)
	s := newTestHostDNS(t, c)

	s.Start()
	require.NotNil(t, s.mgr)
	assert.Equal(t, dnsconfig.GoalSet, s.mgr.Status().Goal)

	s.Recover()
	assert.Equal(t, dnsconfig.GoalSet, s.mgr.Status().Goal)
}

func TestHostDNS_startWaitsForTheTunDevice(t *testing.T) {
	c := newHostDNSTestConfig(t, hostDNSEnabledYAML)
	s := newTestHostDNS(t, c)

	// A reload before start only loads its configuration
	res := c.ReloadConfigString(hostDNSEnabledYAML)
	assert.False(t, res.Failed)
	assert.Nil(t, s.mgr)

	s.Start()
	require.NotNil(t, s.mgr)
	assert.Equal(t, dnsconfig.GoalSet, s.mgr.Status().Goal)
}

func TestHostDNS_reload(t *testing.T) {
	c := newHostDNSTestConfig(t, hostDNSEnabledYAML)
	s := newTestHostDNS(t, c)
	s.Start()
	require.NotNil(t, s.mgr)

	// Disabling clears on the same Manager
	res := c.ReloadConfigString("dns:\n  enabled: false\n")
	assert.False(t, res.Failed)
	assert.Empty(t, res.RestartKeys)
	assert.Equal(t, dnsconfig.GoalClear, s.mgr.Status().Goal)

	// Re-enabling with a different config is a new goal
	res = c.ReloadConfigString("dns:\n  enabled: true\n  nameservers: [192.168.100.2]\n  match_domains: []\n")
	assert.False(t, res.Failed)
	st := s.mgr.Status()
	assert.Equal(t, dnsconfig.GoalSet, st.Goal)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.100.2")}, st.Desired.Nameservers)
	assert.Empty(t, st.Desired.MatchDomains)

	// Removing the stanza entirely is a disable
	res = c.ReloadConfigString("lighthouse: {}\n")
	assert.False(t, res.Failed)
	assert.Equal(t, dnsconfig.GoalClear, s.mgr.Status().Goal)
}

func TestHostDNS_reload_failureKeepsTheRunningConfig(t *testing.T) {
	c := newHostDNSTestConfig(t, hostDNSEnabledYAML)
	s := newTestHostDNS(t, c)
	s.Start()

	res := c.ReloadConfigString("dns:\n  enabled: true\n  nameservers: [bogus]\n  match_domains: []\n")
	assert.True(t, res.Failed)
	st := s.mgr.Status()
	assert.Equal(t, dnsconfig.GoalSet, st.Goal)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.100.1")}, st.Desired.Nameservers)
}

func TestHostDNS_reload_identityChangeNeedsARestart(t *testing.T) {
	c := newHostDNSTestConfig(t, hostDNSEnabledYAML)
	s := newTestHostDNS(t, c)
	s.Start()

	res := c.ReloadConfigString("dns:\n  identity: other\n")
	assert.False(t, res.Failed)
	assert.Equal(t, []string{"dns.identity"}, res.RestartKeys)
	assert.Equal(t, defaultHostDNSIdentity, s.mgrOpts.Identity)
	assert.Equal(t, dnsconfig.GoalClear, s.mgr.Status().Goal)
}

func TestHostDNS_restoreIsFinal(t *testing.T) {
	c := newHostDNSTestConfig(t, hostDNSEnabledYAML)
	s := newTestHostDNS(t, c)
	s.Start()
	require.NotNil(t, s.mgr)

	s.Restore()
	assert.Nil(t, s.mgr)

	// Nothing is created after Restore, by a reload or a late Start
	res := c.ReloadConfigString(hostDNSEnabledYAML)
	assert.False(t, res.Failed)
	assert.Nil(t, s.mgr)
	s.Start()
	assert.Nil(t, s.mgr)
}

func TestHostDNS_restoreBeforeStart(t *testing.T) {
	c := newHostDNSTestConfig(t, hostDNSEnabledYAML)
	s := newTestHostDNS(t, c)
	s.Restore()
	assert.Nil(t, s.mgr)
	s.Start()
	assert.Nil(t, s.mgr)
}

// TestHostDNS_unusableHostCreatesNothing runs against the native backend on a host dnsconfig can't configure, which
// is any OS but macOS and Windows, or macOS without root. Elsewhere it would touch the host, so it is skipped.
func TestHostDNS_unusableHostCreatesNothing(t *testing.T) {
	c := newHostDNSTestConfig(t, "dns:\n  enabled: false\n")
	var logs bytes.Buffer
	s, err := newHostDNSFromConfig(context.Background(), test.NewLoggerWithOutput(&logs), c)
	require.NoError(t, err)
	reason := s.unusable()
	if reason == nil {
		t.Skip("this host can be configured, so the test would touch it")
	}
	t.Cleanup(s.Restore)

	// Recovery and a disabled start are quiet: nothing was asked for, so there is nothing to complain about
	s.Recover()
	assert.Nil(t, s.mgr)
	s.Start()
	assert.Nil(t, s.mgr)
	assert.NotContains(t, logs.String(), "level=ERROR")
	assert.NotContains(t, logs.String(), "level=WARN")

	// Asking for it is a warning, once, and not a failed reload: the stanza is shared with hosts it works on
	res := c.ReloadConfigString(hostDNSEnabledYAML)
	assert.False(t, res.Failed)
	assert.Nil(t, s.mgr)
	assert.Equal(t, 1, strings.Count(logs.String(), "leaving host DNS unmanaged"))
	assert.Contains(t, logs.String(), reason.Error())
	res = c.ReloadConfigString(hostDNSEnabledYAML + "  identity: nebula\n")
	assert.False(t, res.Failed)
	assert.Equal(t, 1, strings.Count(logs.String(), "leaving host DNS unmanaged"))
}

func TestHostDNS_nilIsSafe(t *testing.T) {
	var s *hostDNS
	s.Recover()
	s.Start()
	s.Restore()
}
