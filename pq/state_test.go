package pq

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rcrowley/go-metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_PersistAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pq-state.json")
	s, err := NewStore(path)
	require.NoError(t, err)

	cert := []byte("fake-cert-bytes")
	pub := bytes32(0xAB)
	require.NoError(t, s.MarkUpgraded("aa11", cert, pub, []string{"192.168.200.5"}, nil))

	// Reopen and confirm the entry survived.
	s2, err := NewStore(path)
	require.NoError(t, err)

	a := s2.Get("aa11")
	assert.Equal(t, cert, a.PeerCert)
	assert.Equal(t, pub, a.StaticPubKey)
	assert.Equal(t, []string{"192.168.200.5"}, a.VpnAddrs)
}

func TestStore_LookupByVpnAddr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pq-state.json")
	s, err := NewStore(path)
	require.NoError(t, err)

	cert := []byte("cert")
	pub := bytes32(0xCD)
	require.NoError(t, s.MarkUpgraded("ff77", cert, pub, []string{"10.0.0.1", "10.0.0.2"}, nil))

	// Reopen to confirm the secondary index is rebuilt from disk.
	s2, err := NewStore(path)
	require.NoError(t, err)

	for _, vpn := range []string{"10.0.0.1", "10.0.0.2"} {
		h, fp, ok := s2.LookupByVpnAddr(vpn)
		require.True(t, ok, "lookup %s", vpn)
		assert.Equal(t, "ff77", fp)
		assert.Equal(t, pub, h.StaticPubKey)
	}

	_, _, ok := s2.LookupByVpnAddr("10.0.0.99")
	assert.False(t, ok, "unknown vpn must miss")
}

func TestStore_RejectsBadInputs(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "s.json"))
	require.NoError(t, err)

	require.Error(t, s.MarkUpgraded("fp", nil, bytes32(0xAA), nil, nil), "empty cert rejected")
	require.Error(t, s.MarkUpgraded("fp", []byte("c"), []byte("short"), nil, nil), "wrong-size pubkey rejected")
}

func TestStore_IncompleteEntryDroppedOnLoad(t *testing.T) {
	// Write a state file that's missing the identity material the
	// loader needs (PeerCert + StaticPubKey). Such entries cannot
	// satisfy LookupByVpnAddr usefully and are dropped at load.
	path := filepath.Join(t.TempDir(), "pq-state.json")
	bad := `{"fp1":{"vpn_addrs":["10.0.0.5"]}}`
	require.NoError(t, os.WriteFile(path, []byte(bad), 0o600))

	s, err := NewStore(path)
	require.NoError(t, err)
	h := s.Get("fp1")
	assert.Empty(t, h.PeerCert, "loader must drop entries missing identity material")
	_, _, ok := s.LookupByVpnAddr("10.0.0.5")
	assert.False(t, ok, "dropped entries must not show up in the vpn index")
}

func TestStore_IncompleteEntryLogsWarning(t *testing.T) {
	// Operators need a signal when stale entries get evicted from the
	// state file — silent drops mean a peer that used to resolve by
	// VPN addr suddenly stops working with no log to point at.
	//
	// Two malformed entries: one missing cert, one with a wrong-size
	// pubkey. Both must show up as Warn-level log lines naming the
	// fingerprint of the evicted entry.
	path := filepath.Join(t.TempDir(), "pq-state.json")
	bad := `{
		"fpMissingCert": {"static_pubkey":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","vpn_addrs":["10.0.0.5"]},
		"fpShortPubKey": {"peer_cert":"Y2VydA==","static_pubkey":"AAA=","vpn_addrs":["10.0.0.6"]}
	}`
	require.NoError(t, os.WriteFile(path, []byte(bad), 0o600))

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	s, err := NewStore(path, WithLogger(logger))
	require.NoError(t, err)

	// Both entries must be evicted.
	assert.Empty(t, s.Get("fpMissingCert").PeerCert)
	assert.Empty(t, s.Get("fpShortPubKey").PeerCert)

	out := buf.String()
	assert.True(t, strings.Contains(out, "fpMissingCert"),
		"warning must name the fingerprint of the evicted no-cert entry; got %q", out)
	assert.True(t, strings.Contains(out, "fpShortPubKey"),
		"warning must name the fingerprint of the evicted short-pubkey entry; got %q", out)
	// Two evictions => two warn lines.
	assert.Equal(t, 2, strings.Count(out, "level=WARN"),
		"expected two Warn-level log lines, got %q", out)
}

func TestStore_LegacyFieldsIgnoredOnLoad(t *testing.T) {
	// State files written by the pre-Simp-3 TOFU code carry extra
	// JSON keys (ever_upgraded, last_upgrade, rp_pubkey_sha256, etc.).
	// json.Unmarshal silently ignores unknown fields, so the loader
	// must not crash and must keep the identity-cache columns it
	// recognises.
	path := filepath.Join(t.TempDir(), "pq-state.json")
	legacy := `{
		"fpLegacy": {
			"ever_upgraded": true,
			"last_upgrade": "2025-01-01T00:00:00Z",
			"failure_count": 7,
			"rp_pubkey_sha256": "abc123",
			"peer_cert": "Y2VydA==",
			"static_pubkey": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
			"vpn_addrs": ["10.0.0.5"],
			"groups": ["legacy"]
		}
	}`
	require.NoError(t, os.WriteFile(path, []byte(legacy), 0o600))

	s, err := NewStore(path)
	require.NoError(t, err)
	h := s.Get("fpLegacy")
	assert.Equal(t, []byte("cert"), h.PeerCert, "PeerCert must round-trip via base64")
	assert.Equal(t, []string{"10.0.0.5"}, h.VpnAddrs)
	assert.Equal(t, []string{"legacy"}, h.Groups)
}

func TestStore_GetAbsent(t *testing.T) {
	s, err := NewStore("")
	require.NoError(t, err)
	got := s.Get("missing")
	assert.Equal(t, PeerHistory{}, got)
}

func TestStore_CorruptFileStartsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pq-state.json")
	require.NoError(t, writeFile(t, path, "not-json"))
	s, err := NewStore(path)
	require.NoError(t, err)
	assert.Equal(t, PeerHistory{}, s.Get("anything"))
}

// D2: a corrupt (unparseable) state file must start empty AND be logged
// (the struct doc comment promises "a corrupt file is logged") AND bump
// the pq.state.load_failed metric.
func TestStore_CorruptFileLogsAndMeters(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"garbage", "not-json"},
		{"truncated", `{"fp":{"peer_cert":"Y2Vy`}, // truncated mid-write
		{"wrong-type", `[1,2,3]`},                 // valid JSON, wrong shape
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pq-state.json")
			require.NoError(t, writeFile(t, path, tc.content))

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

			before := metrics.GetOrRegisterCounter(MetricStateLoadFailed, nil).Count()
			s, err := NewStore(path, WithLogger(logger))
			require.NoError(t, err, "corrupt file must not be fatal")
			assert.Equal(t, PeerHistory{}, s.Get("anything"), "store starts empty")

			out := buf.String()
			assert.Contains(t, out, "level=WARN", "corrupt load must log a Warn; got %q", out)
			assert.Contains(t, out, "corrupt state file", "warn must explain the corruption; got %q", out)
			assert.Contains(t, out, path, "warn must name the offending path; got %q", out)

			after := metrics.GetOrRegisterCounter(MetricStateLoadFailed, nil).Count()
			assert.Equal(t, before+1, after, "pq.state.load_failed must increment once")
		})
	}
}

// D3: concurrent MarkUpgraded calls must not race (run under -race) and
// the persisted file must remain internally consistent (a single valid
// JSON object reflecting some committed snapshot, never a torn write).
func TestStore_ConcurrentMarkUpgradedNoRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pq-state.json")
	s, err := NewStore(path)
	require.NoError(t, err)

	const writers = 16
	const iters = 50
	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(w int) {
			defer wg.Done()
			fp := "fp" + string(rune('A'+w))
			pub := bytes32(byte(w))
			cert := []byte("cert-" + fp)
			for i := 0; i < iters; i++ {
				// MarkUpgraded persists on every call; concurrent calls
				// exercise the serialized persist path.
				_ = s.MarkUpgraded(fp, cert, pub, []string{"10.0.0." + string(rune('1'+w))}, nil)
			}
		}(w)
	}
	wg.Wait()

	// The on-disk file must be parseable as a single coherent snapshot.
	// A torn rename (the bug D3 guards against) would leave invalid JSON
	// or a partial object.
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var on map[string]*PeerHistory
	require.NoError(t, json.Unmarshal(raw, &on), "persisted file must be valid JSON, not a torn write")

	// Reloading must yield a fully-consistent store: every persisted
	// entry has its identity material intact (no half-written records).
	s2, err := NewStore(path)
	require.NoError(t, err)
	for w := 0; w < writers; w++ {
		fp := "fp" + string(rune('A'+w))
		h := s2.Get(fp)
		require.NotEmpty(t, h.PeerCert, "entry %s must have survived intact", fp)
		assert.Equal(t, "cert-"+fp, string(h.PeerCert))
		assert.Len(t, h.StaticPubKey, 32)
	}
}

func writeFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestStore_GroupsRoundTrip(t *testing.T) {
	// The Groups field captured at MarkUpgraded time must persist
	// across reopens so the boot-path DefaultPolicy.Overrides can
	// re-apply per-group mode overrides without waiting for a fresh
	// handshake.
	path := filepath.Join(t.TempDir(), "pq-state.json")
	s, err := NewStore(path)
	require.NoError(t, err)

	cert := []byte("cert")
	pub := bytes32(0x55)
	groups := []string{"lighthouses", "dc-east"}
	require.NoError(t, s.MarkUpgraded("fp_groups", cert, pub,
		[]string{"10.0.0.50"}, groups))

	// In-memory: groups are present.
	h := s.Get("fp_groups")
	assert.Equal(t, groups, h.Groups)

	// On reopen: groups survive the JSON round-trip.
	s2, err := NewStore(path)
	require.NoError(t, err)
	h2 := s2.Get("fp_groups")
	assert.Equal(t, groups, h2.Groups)

	// Secondary index lookup also exposes Groups.
	h3, fp, ok := s2.LookupByVpnAddr("10.0.0.50")
	require.True(t, ok)
	assert.Equal(t, "fp_groups", fp)
	assert.Equal(t, groups, h3.Groups)
}
