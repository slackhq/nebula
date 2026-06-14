package pq

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProvider lets each test inject a deterministic Lookup map.
type fakeProvider struct {
	psks map[string][]byte // hex of static pubkey -> psk
}

func (f *fakeProvider) Lookup(peerStaticPubKey []byte) []byte {
	if f == nil {
		return nil
	}
	key := hexOf(peerStaticPubKey)
	return f.psks[key]
}
func (f *fakeProvider) Subscribe() <-chan struct{} { return nil }
func (f *fakeProvider) Close() error               { return nil }
func (f *fakeProvider) LookupRPHash([]byte) string { return "" }
func (f *fakeProvider) LookupWithBinding(peerStaticPubKey []byte) (psk []byte, rpHash string, ok bool) {
	v := f.Lookup(peerStaticPubKey)
	return v, "", v != nil
}

func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0xf]
	}
	return string(out)
}

func newPolicyForTest(t *testing.T, mode Mode, knownPSK bool) (*DefaultPolicy, []byte) {
	t.Helper()
	pub := bytes32(0xAB)
	prov := &fakeProvider{psks: map[string][]byte{}}
	if knownPSK {
		prov.psks[hexOf(pub)] = bytes32(0x77)
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "pq-state.json"))
	require.NoError(t, err)
	return NewDefaultPolicy(mode, prov, store), pub
}

// newPolicyWithOverridesForTest builds a DefaultPolicy preloaded with
// per-cert-group overrides. Mirrors the historical newGPForTest helper
// so existing test cases translate verbatim.
func newPolicyWithOverridesForTest(t *testing.T, defaultMode Mode, knownPSK bool, overrides map[string]Mode, order []string) (*DefaultPolicy, []byte) {
	t.Helper()
	dp, pub := newPolicyForTest(t, defaultMode, knownPSK)
	dp.WithOverrides(overrides, order)
	return dp, pub
}

func TestPolicy_Opportunistic(t *testing.T) {
	t.Run("psk available -> per-peer", func(t *testing.T) {
		p, pub := newPolicyForTest(t, ModeOpportunistic, true)
		s, err := p.InitiatorSubtype(PeerInfo{StaticPubKey: pub})
		require.NoError(t, err)
		assert.Equal(t, SubtypePerPeer, s)
	})
	t.Run("no psk -> no-psk", func(t *testing.T) {
		p, pub := newPolicyForTest(t, ModeOpportunistic, false)
		s, err := p.InitiatorSubtype(PeerInfo{StaticPubKey: pub})
		require.NoError(t, err)
		assert.Equal(t, SubtypeNoPSK, s)
	})
	t.Run("responder accepts both", func(t *testing.T) {
		p, _ := newPolicyForTest(t, ModeOpportunistic, true)
		assert.NoError(t, p.AcceptResponderSubtype(PeerInfo{Fingerprint: "deadbeef"}, SubtypeNoPSK))
		assert.NoError(t, p.AcceptResponderSubtype(PeerInfo{Fingerprint: "deadbeef"}, SubtypePerPeer))
	})
}

// D1 (policy layer): when a peer's PSK disappears mid-life, the
// opportunistic policy must DEGRADE the desired subtype to IXPSK0 (so
// the ConnectionManager re-handshakes down, keeping the tunnel) and
// must NOT surface an error. The required policy, by contrast, must
// surface ErrPolicyDenied so the ConnectionManager can enforce the
// operator's choice (gated by its own hysteresis). This is the
// decision the connection_manager degradation logic keys off of.
func TestPolicy_PSKLossDegradesOpportunisticButDeniesRequired(t *testing.T) {
	t.Run("opportunistic degrades to no-psk on PSK loss", func(t *testing.T) {
		pub := bytes32(0xAB)
		prov := &fakeProvider{psks: map[string][]byte{hexOf(pub): bytes32(0x77)}}
		dp := NewDefaultPolicy(ModeOpportunistic, prov, nil)

		// Initially the PSK is present -> IXPSK2.
		s, err := dp.InitiatorSubtype(PeerInfo{StaticPubKey: pub})
		require.NoError(t, err)
		require.Equal(t, SubtypePerPeer, s)

		// PSK vanishes (file deleted / empty successful rescan).
		delete(prov.psks, hexOf(pub))

		s, err = dp.InitiatorSubtype(PeerInfo{StaticPubKey: pub})
		require.NoError(t, err, "opportunistic PSK loss must never error")
		assert.Equal(t, SubtypeNoPSK, s, "opportunistic must degrade to IXPSK0, not tear down")
	})

	t.Run("required denies on PSK loss", func(t *testing.T) {
		pub := bytes32(0xAB)
		prov := &fakeProvider{psks: map[string][]byte{hexOf(pub): bytes32(0x77)}}
		dp := NewDefaultPolicy(ModeRequired, prov, nil)

		s, err := dp.InitiatorSubtype(PeerInfo{StaticPubKey: pub})
		require.NoError(t, err)
		require.Equal(t, SubtypePerPeer, s)

		delete(prov.psks, hexOf(pub))

		_, err = dp.InitiatorSubtype(PeerInfo{StaticPubKey: pub})
		require.Error(t, err, "required PSK loss must deny (operator enforces)")
		assert.True(t, errors.Is(err, ErrPolicyDenied))
	})
}

func TestPolicy_OnHandshakeComplete_IdentityCache(t *testing.T) {
	t.Run("incomplete identity material does not populate cache", func(t *testing.T) {
		// OnHandshakeComplete with no CertBytes is a no-op so a future
		// LookupByVpnAddr / LookupBootIdentity returns nothing.
		p, pub := newPolicyForTest(t, ModeOpportunistic, true)
		p.OnHandshakeComplete(PeerInfo{StaticPubKey: pub, Fingerprint: "fp_incomplete"}, SubtypePerPeer)
		assert.Empty(t, p.Store.Get("fp_incomplete").PeerCert,
			"missing cert bytes must not be recorded in the identity cache")
	})

	t.Run("LookupBootIdentity resolves a previously-upgraded peer by VPN addr", func(t *testing.T) {
		p, pub := newPolicyForTest(t, ModeOpportunistic, true)
		p.OnHandshakeComplete(PeerInfo{
			StaticPubKey: pub,
			Fingerprint:  "fp_boot",
			CertBytes:    []byte("cert-fp_boot"),
			VpnAddrs:     []string{"10.0.0.7"},
		}, SubtypePerPeer)

		got, ok := p.LookupBootIdentity("10.0.0.7")
		require.True(t, ok)
		assert.Equal(t, "fp_boot", got.Fingerprint)
		assert.Equal(t, pub, got.StaticPubKey)
		assert.Equal(t, []byte("cert-fp_boot"), got.CertBytes)
	})

	t.Run("subtype no-psk does not populate cache", func(t *testing.T) {
		p, pub := newPolicyForTest(t, ModeOpportunistic, true)
		p.OnHandshakeComplete(PeerInfo{
			StaticPubKey: pub,
			Fingerprint:  "fp_no_psk",
			CertBytes:    []byte("cert"),
			VpnAddrs:     []string{"10.0.0.8"},
		}, SubtypeNoPSK)
		_, ok := p.LookupBootIdentity("10.0.0.8")
		assert.False(t, ok, "no-psk handshakes do not feed the identity cache")
	})
}

func TestPolicy_Required(t *testing.T) {
	t.Run("psk available -> per-peer", func(t *testing.T) {
		p, pub := newPolicyForTest(t, ModeRequired, true)
		s, err := p.InitiatorSubtype(PeerInfo{StaticPubKey: pub})
		require.NoError(t, err)
		assert.Equal(t, SubtypePerPeer, s)
	})

	t.Run("no psk -> initiator refuses", func(t *testing.T) {
		p, pub := newPolicyForTest(t, ModeRequired, false)
		_, err := p.InitiatorSubtype(PeerInfo{StaticPubKey: pub})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPolicyDenied))
	})

	t.Run("responder rejects no-psk if it has psk for caller", func(t *testing.T) {
		p, pub := newPolicyForTest(t, ModeRequired, true)
		err := p.AcceptResponderSubtype(PeerInfo{StaticPubKey: pub}, SubtypeNoPSK)
		require.Error(t, err)
	})

	t.Run("responder accepts no-psk if it has no psk for caller (peer outside required scope)", func(t *testing.T) {
		p, _ := newPolicyForTest(t, ModeRequired, false)
		err := p.AcceptResponderSubtype(PeerInfo{StaticPubKey: bytes32(0xAB)}, SubtypeNoPSK)
		assert.NoError(t, err, "required-mode responder still talks to unconfigured peers as IXPSK0")
	})

	t.Run("responder rejects per-peer (IXPSK2) when it has no psk for caller", func(t *testing.T) {
		// Without this policy-layer rejection, the responder would
		// accept the IXPSK2 packet and only fail later inside
		// injectResponderPSK with a cryptographic error. Surface the
		// denial up-front so the operator sees an ErrPolicyDenied
		// rather than a confusing "psk material missing" crypto fault.
		p, _ := newPolicyForTest(t, ModeRequired, false)
		err := p.AcceptResponderSubtype(PeerInfo{StaticPubKey: bytes32(0xAB)}, SubtypePerPeer)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPolicyDenied),
			"required-mode responder must refuse IXPSK2 from a peer with no configured PSK at policy layer")
	})
}

func TestAcceptResponderSubtypeRequiredRejectsEmptyStaticPubKey(t *testing.T) {
	p := NewDefaultPolicy(ModeRequired, NoProvider{}, nil)
	err := p.AcceptResponderSubtype(PeerInfo{Fingerprint: "fp"}, SubtypeNoPSK)
	require.ErrorIs(t, err, ErrPolicyDenied,
		"required-mode responder must not accept IXPSK0 when peer static pubkey is unknown")
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{
		"":              ModeOpportunistic,
		"opportunistic": ModeOpportunistic,
		"required":      ModeRequired,
		"REQUIRED":      ModeRequired,
	} {
		got, err := ParseMode(in)
		require.NoError(t, err, "input %q", in)
		assert.Equal(t, want, got, "input %q", in)
	}
	_, err := ParseMode("nonsense")
	require.Error(t, err)
}

// TestParseMode_TOFURejected pins the operator-facing contract that
// the removed TOFU mode surfaces a loud error (with a remediation
// hint) rather than silently falling through to opportunistic.
func TestParseMode_TOFURejected(t *testing.T) {
	for _, in := range []string{"tofu", "TOFU", "trust-on-first-use"} {
		_, err := ParseMode(in)
		require.Error(t, err, "input %q must be rejected", in)
		assert.Contains(t, err.Error(), "removed",
			"error should signal that the mode was removed (input %q)", in)
	}
}

// --- Per-cert-group overrides (formerly GroupPolicy) -----------------

func TestDefaultPolicyWithOverrides_NoGroupsFallsThroughToDefault(t *testing.T) {
	dp, pub := newPolicyWithOverridesForTest(t, ModeOpportunistic, true,
		map[string]Mode{"lighthouses": ModeRequired},
		[]string{"lighthouses"},
	)
	s, err := dp.InitiatorSubtype(PeerInfo{StaticPubKey: pub, Groups: nil})
	require.NoError(t, err)
	assert.Equal(t, SubtypePerPeer, s, "psk available -> per-peer under opportunistic default")
}

func TestDefaultPolicyWithOverrides_PeerInOverriddenGroup(t *testing.T) {
	dp, pub := newPolicyWithOverridesForTest(t, ModeOpportunistic, false,
		map[string]Mode{"lighthouses": ModeRequired},
		[]string{"lighthouses"},
	)
	// Peer is in "lighthouses" -> required, no PSK -> denied.
	_, err := dp.InitiatorSubtype(PeerInfo{
		StaticPubKey: pub,
		Groups:       []string{"lighthouses", "dc-east"},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyDenied))
}

func TestDefaultPolicyWithOverrides_DisabledGroupBypassesPQ(t *testing.T) {
	dp, pub := newPolicyWithOverridesForTest(t, ModeRequired, true,
		map[string]Mode{"legacy": ModeDisabled},
		nil,
	)
	// Without override, required mode + psk available -> per-peer.
	// With "legacy" matching, mode collapses to disabled -> no-psk
	// regardless of provider state. Both initiator and responder
	// behave as if PQ isn't configured for this peer.
	s, err := dp.InitiatorSubtype(PeerInfo{StaticPubKey: pub, Groups: []string{"legacy"}})
	require.NoError(t, err)
	assert.Equal(t, SubtypeNoPSK, s)

	require.NoError(t, dp.AcceptResponderSubtype(
		PeerInfo{StaticPubKey: pub, Groups: []string{"legacy"}}, SubtypeNoPSK))
}

func TestDefaultPolicyWithOverrides_PriorityOrderPicksFirstMatch(t *testing.T) {
	dp, pub := newPolicyWithOverridesForTest(t, ModeOpportunistic, true,
		map[string]Mode{
			"lighthouses": ModeRequired,
			"legacy":      ModeDisabled,
		},
		[]string{"lighthouses", "legacy"}, // lighthouses wins
	)
	// Peer is in BOTH groups; with the operator's stated order,
	// "lighthouses" comes first => required.
	_, err := dp.InitiatorSubtype(PeerInfo{
		StaticPubKey: pub,
		Groups:       []string{"legacy", "lighthouses"},
	})
	require.NoError(t, err) // required + psk known -> per-peer (no error)
}

func TestDefaultPolicyWithOverrides_SortedFallbackWhenNoOrder(t *testing.T) {
	// No GroupOrder: deterministic alphabetical walk. "admins" < "lighthouses",
	// so admins wins.
	dp, pub := newPolicyWithOverridesForTest(t, ModeOpportunistic, false,
		map[string]Mode{
			"admins":      ModeRequired,      // would deny (no psk)
			"lighthouses": ModeOpportunistic, // would allow IXPSK0
		},
		nil,
	)
	_, err := dp.InitiatorSubtype(PeerInfo{
		StaticPubKey: pub,
		Groups:       []string{"lighthouses", "admins"},
	})
	require.Error(t, err, "alphabetical walk picks admins first which denies")
	assert.True(t, errors.Is(err, ErrPolicyDenied))
}

func TestDefaultPolicyWithOverrides_OnHandshakeCompleteRespectsGroup(t *testing.T) {
	// A "disabled" peer that somehow completed an IXPSK2 handshake
	// (e.g. operator just flipped them out of the disabled group)
	// should not be cached, because we're told not to track them.
	dp, pub := newPolicyWithOverridesForTest(t, ModeOpportunistic, true,
		map[string]Mode{"legacy": ModeDisabled},
		nil,
	)
	dp.OnHandshakeComplete(PeerInfo{
		StaticPubKey: pub,
		Fingerprint:  "fp_legacy",
		CertBytes:    []byte("cert-fp_legacy"),
		VpnAddrs:     []string{"10.0.0.99"},
		Groups:       []string{"legacy"},
	}, SubtypePerPeer)
	assert.Empty(t, dp.Store.Get("fp_legacy").PeerCert,
		"disabled-group peer must not be cached in the identity store")
}

func TestDefaultPolicyWithOverrides_LookupBootIdentityRespectsModeDisabled(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	mem := NewMemoryProvider()
	dp := NewDefaultPolicy(ModeOpportunistic, mem, store)
	dp.WithOverrides(map[string]Mode{"legacy": ModeDisabled}, nil)

	// Simulate that a previous handshake recorded this peer in the
	// "legacy" group and pinned its identity in the Store.
	pub := bytes32(0x11)
	require.NoError(t, store.MarkUpgraded(
		"fp-legacy",
		[]byte("cert"),
		pub,
		[]string{"10.0.0.7"},
		[]string{"legacy"},
	))

	pi, ok := dp.LookupBootIdentity("10.0.0.7")
	require.True(t, ok)
	require.Equal(t, []string{"legacy"}, pi.Groups,
		"boot-path PeerInfo must carry stored groups so disabled-mode override applies")

	st, err := dp.InitiatorSubtype(pi)
	require.NoError(t, err)
	require.Equal(t, SubtypeNoPSK, st,
		"legacy group is disabled; boot initiator must not pick PSK subtype")
}

func TestParseGroupMode(t *testing.T) {
	cases := map[string]Mode{
		"":              ModeOpportunistic,
		"opportunistic": ModeOpportunistic,
		"required":      ModeRequired,
		"disabled":      ModeDisabled,
		"OFF":           ModeDisabled,
	}
	for in, want := range cases {
		got, err := ParseGroupMode(in)
		require.NoError(t, err, "input %q", in)
		assert.Equal(t, want, got, "input %q", in)
	}
	_, err := ParseGroupMode("rubbish")
	require.Error(t, err)
	_, err = ParseGroupMode("tofu")
	require.Error(t, err, "tofu must remain rejected via ParseGroupMode too")
}

// TestParseGroupMode_StripsCarriageReturn pins the contract that
// ParseGroupMode and ParseMode treat CRLF-terminated YAML values
// (common on Windows-edited config) identically to plain LF input.
// Previously ParseGroupMode's normalizer stripped only ' ', '\t', '\n'
// — but ParseMode used strings.TrimSpace, which also strips '\r'. The
// inconsistency meant "required\r" round-tripped through one path but
// not the other.
func TestParseGroupMode_StripsCarriageReturn(t *testing.T) {
	for _, in := range []string{"required\r", " required \r\n", "\rdisabled\r"} {
		got, err := ParseGroupMode(in)
		require.NoError(t, err, "input %q must parse cleanly", in)
		if in == "\rdisabled\r" {
			assert.Equal(t, ModeDisabled, got, "input %q", in)
		} else {
			assert.Equal(t, ModeRequired, got, "input %q", in)
		}
	}
}
