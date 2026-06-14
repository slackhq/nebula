package pq

import (
	"errors"
	"fmt"
	"strings"
)

// Subtype is the PQ-relevant classification of a handshake. It maps
// 1:1 onto the wire-level subtypes: SubtypeNoPSK == IXPSK0 (and any
// future non-PSK pattern), SubtypePerPeer == IXPSK2. Kept separate
// from header.MessageSubType so the pq package stays free of nebula
// internals.
type Subtype uint8

const (
	// SubtypeNoPSK means the handshake will not mix per-peer PQ PSK
	// material. This includes legacy IXPSK0 with no PSK as well as
	// IXPSK0 with a mesh-wide PSK; from a per-peer-isolation point of
	// view, both are equivalent — no peer-specific PSK was used.
	SubtypeNoPSK Subtype = 0
	// SubtypePerPeer means the handshake mixed a per-peer PSK at psk2
	// placement (IXPSK2). This is the goal state for peers that have
	// PSK material configured.
	SubtypePerPeer Subtype = 2
)

func (s Subtype) String() string {
	switch s {
	case SubtypeNoPSK:
		return "no-psk"
	case SubtypePerPeer:
		return "per-peer"
	default:
		return fmt.Sprintf("subtype(%d)", uint8(s))
	}
}

// Mode controls how strict the policy is about per-peer PQ protection.
type Mode int

const (
	// ModeOpportunistic is the loosest setting and matches the v1
	// behaviour shipped with the per-peer PSK plumbing: use IXPSK2 if a
	// PSK is resolvable for the destination peer, otherwise fall back
	// to IXPSK0. Failure of an upgrade leaves the existing IXPSK0
	// session in place.
	ModeOpportunistic Mode = iota
	// ModeRequired is the strictest setting: a peer with PSK material
	// configured must use IXPSK2. Initiation refuses IXPSK0 if a PSK
	// is configured for the destination; responder rejects IXPSK0 if
	// it has a PSK for the calling peer's static. Use this when you
	// have already distributed PSK material to every peer in the mesh.
	ModeRequired
)

// ModeDisabled is an extra mode value usable only via group
// overrides (or a future per-peer config). It maps to "do not run
// PQ for this peer" — initiator stays IXPSK0, responder accepts
// IXPSK0 unconditionally. Treated as out-of-bounds by ParseMode for
// the mesh-wide pq.mode setting because disabling PQ globally is
// what omitting the whole pq stanza already does.
//
// Kept at a negative iota so the default zero-value of DefaultPolicy
// (Mode: 0) remains ModeOpportunistic, not ModeDisabled.
const ModeDisabled Mode = -1

// ParseMode resolves a YAML/CLI string into a Mode value. Unknown
// strings return an error; empty defaults to ModeOpportunistic.
//
// "disabled"/"off" are not accepted here because the mesh-wide
// pq.mode field has no reason to globally disable PQ — omit the
// whole pq stanza for that. Use ParseGroupMode for per-cert-group
// overrides where ModeDisabled is meaningful.
//
// "tofu"/"trust-on-first-use" used to map to a now-removed sticky-
// downgrade mode; it is rejected explicitly with a remediation hint
// so operators upgrading from a config that referenced it see a
// loud error rather than silently falling through to opportunistic.
func ParseMode(s string) (Mode, error) {
	norm := strings.ToLower(strings.TrimSpace(s))
	switch norm {
	case "", "opportunistic":
		return ModeOpportunistic, nil
	case "required", "strict":
		return ModeRequired, nil
	case "tofu", "trust-on-first-use":
		return 0, fmt.Errorf("pq: mode %q removed; use opportunistic + cert extension trust binding (the cert-v2 PQ-PSK binding extension)", s)
	}
	return 0, fmt.Errorf("pq: unknown mode %q (expected: opportunistic|required)", s)
}

// ParseGroupMode is like ParseMode but additionally accepts
// "disabled" / "off" as valid values, since per-group overrides can
// legitimately exempt peers from PQ.
func ParseGroupMode(s string) (Mode, error) {
	switch normalizeMode(s) {
	case "disabled", "off":
		return ModeDisabled, nil
	}
	return ParseMode(s)
}

// normalizeMode trims surrounding whitespace and lowercases s. Matches
// ParseMode's strings.TrimSpace + ToLower exactly so CRLF-terminated
// YAML values ("required\r\n") and Windows-edited configs round-trip
// the same through both ParseGroupMode and ParseMode.
func normalizeMode(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func (m Mode) String() string {
	switch m {
	case ModeOpportunistic:
		return "opportunistic"
	case ModeRequired:
		return "required"
	case ModeDisabled:
		return "disabled"
	default:
		return fmt.Sprintf("mode(%d)", int(m))
	}
}

// PeerInfo carries the peer-identity bits the policy needs to make a
// decision. Defined as a small struct so the policy doesn't depend on
// nebula's HostInfo type.
//
// At initiation time the caller may know StaticPubKey from a cached
// cert (rekey upgrades, or boot from pq.Store cache) or have it nil
// (first contact, no cache hit). Fingerprint becomes available only
// after the cert is verified, so it can be empty during initiator
// path decisions.
//
// CertBytes and VpnAddrs are populated only at handshake completion
// time, when nebula has the verified peer cert in hand. They feed the
// pq.Store identity cache so a subsequent boot can resolve this peer
// without needing a fresh handshake.
//
// Groups carries the cert group claims (CA-signed) used by
// DefaultPolicy.Overrides to apply per-peer mode overrides. Always
// safe to leave nil; an empty Groups slice falls through to the
// mesh-wide default.
type PeerInfo struct {
	StaticPubKey []byte // 32 bytes for X25519 identities
	Fingerprint  string // hex SHA-256 of cert; empty before cert verification

	// CertBytes is the marshaled-for-handshakes peer certificate.
	// Populated at OnHandshakeComplete time; ignored elsewhere.
	CertBytes []byte
	// VpnAddrs are the nebula overlay addresses asserted by the
	// peer's cert (string form, e.g. "192.168.200.2"). Populated at
	// OnHandshakeComplete time; used for the Store's secondary index.
	VpnAddrs []string
	// Groups are the cert.groups asserted by the peer's nebula
	// certificate. Used by DefaultPolicy.Overrides to resolve
	// per-peer mode overrides; ignored by other policy implementations.
	Groups []string
}

// ErrPolicyDenied is returned by the policy when a handshake or rekey
// is refused. Callers treat this as "drop the handshake" without
// failing fatally.
var ErrPolicyDenied = errors.New("pq: policy denied")

// Policy makes the security decisions: which subtype to initiate
// with, whether to accept a peer's chosen subtype, and what
// bookkeeping to do as handshakes complete or fail. The handshake
// machinery just calls into Policy and obeys its answers.
type Policy interface {
	// InitiatorSubtype is consulted by the initiator before a new
	// handshake is sent. It returns the subtype that should be put on
	// the wire, or ErrPolicyDenied if the policy refuses to handshake
	// with this peer at all (e.g. ModeRequired with no PSK known).
	InitiatorSubtype(peer PeerInfo) (Subtype, error)

	// AcceptResponderSubtype is called by the responder once it has
	// verified the calling peer's cert and seen which subtype the
	// initiator chose. Returning a non-nil error rejects the in-flight
	// handshake.
	AcceptResponderSubtype(peer PeerInfo, incoming Subtype) error

	// OnHandshakeComplete records that a handshake of the given
	// subtype just succeeded with peer. DefaultPolicy uses this to
	// refresh the on-disk identity cache (cert + pubkey + vpn addrs +
	// groups) so a subsequent cold boot can resolve the peer's
	// per-group overrides without a fresh handshake first.
	OnHandshakeComplete(peer PeerInfo, subtype Subtype)

	// OnHandshakeFailed records a failed handshake attempt. Kept on
	// the interface for observability hooks; DefaultPolicy currently
	// treats it as a no-op (no fail-closed logic feeds off the count).
	OnHandshakeFailed(peer PeerInfo, subtype Subtype, err error)
}

// DefaultPolicy combines a Provider (PSK availability) and a Store
// (per-peer history) to implement the available modes. It is the
// only Policy implementation nebula ships; tests can substitute a
// custom Policy if they need narrower behaviour.
//
// Per-cert-group overrides are first-class via the Overrides field:
// the peer's CA-signed group claims (PeerInfo.Groups) are consulted
// on every decision, with the first matching group's mode winning.
// Peers with no matching group fall through to dp.Mode.
//
// Worked example. With:
//
//	Mode:      ModeOpportunistic
//	Overrides: {"lighthouses": ModeRequired, "legacy": ModeDisabled}
//	GroupOrder: ["lighthouses", "legacy"]
//
// A peer whose cert lists groups ["dc-east","lighthouses"] gets
// "lighthouses" → ModeRequired. A peer with groups ["dc-east"] gets
// the default (ModeOpportunistic). A peer with groups
// ["legacy","lighthouses"] gets "lighthouses" because GroupOrder
// lists it first.
type DefaultPolicy struct {
	Mode     Mode
	Provider Provider
	Store    *Store

	// Overrides maps cert-group name to Mode. If a peer's CA-signed
	// Groups list contains any key here, the corresponding Mode applies
	// for that peer instead of dp.Mode. Empty/nil disables per-group
	// overrides.
	Overrides map[string]Mode

	// GroupOrder lists groups in priority order, most-specific first.
	// The first group from this list that the peer also asserts wins
	// the decision. If empty, falls back to a sorted-by-name walk for
	// determinism. Operators usually want to set this explicitly (e.g.
	// ["lighthouses","admins","legacy"]) so a peer in multiple
	// overridden groups gets a predictable answer.
	GroupOrder []string
}

// NewDefaultPolicy is a convenience constructor that validates inputs.
func NewDefaultPolicy(mode Mode, p Provider, store *Store) *DefaultPolicy {
	if p == nil {
		p = NoProvider{}
	}
	return &DefaultPolicy{Mode: mode, Provider: p, Store: store}
}

// WithOverrides sets per-cert-group mode overrides on dp and returns
// dp for chaining. The overrides map and groupOrder slice are copied
// so the caller can mutate the originals after the call. Passing a
// nil/empty overrides map clears any previously-set overrides.
func (dp *DefaultPolicy) WithOverrides(overrides map[string]Mode, groupOrder []string) *DefaultPolicy {
	if len(overrides) == 0 {
		dp.Overrides = nil
		dp.GroupOrder = nil
		return dp
	}
	cp := make(map[string]Mode, len(overrides))
	for k, v := range overrides {
		cp[k] = v
	}
	dp.Overrides = cp
	dp.GroupOrder = append([]string(nil), groupOrder...)
	return dp
}

// resolveMode picks the effective Mode for a peer. Walks GroupOrder
// first (operator's stated priority), then any remaining overridden
// groups not in GroupOrder (sorted by name for determinism). Falls
// through to dp.Mode when nothing matches.
// ResolvedMode exposes the effective mode for a peer (after group
// overrides). Used by the handshake manager to decide whether an
// IXPSK0 opportunistic degrade is permitted (never under required).
func (dp *DefaultPolicy) ResolvedMode(peer PeerInfo) Mode { return dp.resolveMode(peer) }

func (dp *DefaultPolicy) resolveMode(peer PeerInfo) Mode {
	if len(dp.Overrides) == 0 || len(peer.Groups) == 0 {
		return dp.Mode
	}
	peerSet := make(map[string]struct{}, len(peer.Groups))
	for _, g := range peer.Groups {
		peerSet[g] = struct{}{}
	}
	// Prioritised walk first.
	for _, g := range dp.GroupOrder {
		if _, isPeer := peerSet[g]; !isPeer {
			continue
		}
		if m, ok := dp.Overrides[g]; ok {
			return m
		}
	}
	// Anything operator didn't put in GroupOrder: sorted-by-name walk
	// for determinism without depending on map iteration order.
	rest := make([]string, 0, len(dp.Overrides))
	seen := map[string]bool{}
	for _, g := range dp.GroupOrder {
		seen[g] = true
	}
	for g := range dp.Overrides {
		if !seen[g] {
			rest = append(rest, g)
		}
	}
	sortStrings(rest)
	for _, g := range rest {
		if _, isPeer := peerSet[g]; !isPeer {
			continue
		}
		return dp.Overrides[g]
	}
	return dp.Mode
}

// sortStrings is a stdlib-free sort to avoid pulling in "sort" just
// for the override resolver. Bubble sort is fine for the tiny
// override sets we expect (handful of groups at most).
func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

func (dp *DefaultPolicy) hasPSKFor(peer PeerInfo) bool {
	if dp == nil || dp.Provider == nil || len(peer.StaticPubKey) == 0 {
		return false
	}
	return dp.Provider.Lookup(peer.StaticPubKey) != nil
}

// InitiatorSubtype implements Policy.
func (dp *DefaultPolicy) InitiatorSubtype(peer PeerInfo) (Subtype, error) {
	switch dp.resolveMode(peer) {
	case ModeDisabled:
		// Per-group "off": always bootstrap as IXPSK0 regardless of
		// provider state.
		return SubtypeNoPSK, nil

	case ModeOpportunistic:
		if dp.hasPSKFor(peer) {
			return SubtypePerPeer, nil
		}
		return SubtypeNoPSK, nil

	case ModeRequired:
		if !dp.hasPSKFor(peer) {
			return 0, fmt.Errorf("%w: required mode but no PSK for peer", ErrPolicyDenied)
		}
		return SubtypePerPeer, nil
	}
	return SubtypeNoPSK, nil
}

// AcceptResponderSubtype implements Policy.
func (dp *DefaultPolicy) AcceptResponderSubtype(peer PeerInfo, incoming Subtype) error {
	switch dp.resolveMode(peer) {
	case ModeDisabled:
		return nil

	case ModeOpportunistic:
		return nil

	case ModeRequired:
		if len(peer.StaticPubKey) == 0 {
			// Required mode cannot make a sound accept/deny decision
			// without the peer's static pubkey: hasPSKFor returns false
			// on empty input, which would silently let an IXPSK0
			// through. Fail closed.
			return fmt.Errorf("%w: required mode responder needs peer static pubkey", ErrPolicyDenied)
		}
		if incoming == SubtypeNoPSK && dp.hasPSKFor(peer) {
			return fmt.Errorf("%w: required mode rejects no-psk handshake (psk is configured for this peer)",
				ErrPolicyDenied)
		}
		if incoming == SubtypePerPeer && !dp.hasPSKFor(peer) {
			// Defense-in-depth. At the current call site
			// (beginHandshake runs the policy gate only after
			// Machine.ProcessPacket succeeded) injectResponderPSK has
			// already failed with ErrResponderPSKMissing whenever this
			// condition holds, so this branch is unreachable there. It
			// stays so the policy remains a self-contained decision
			// surface for any caller that consults it before driving
			// the Machine.
			return fmt.Errorf("%w: required mode rejects psk2 handshake from peer with no configured PSK",
				ErrPolicyDenied)
		}
		return nil
	}
	return nil
}

// OnHandshakeComplete implements Policy. For IXPSK2 outcomes we
// capture the peer's identity (cert + pubkey + vpn addrs + groups)
// into the Store so a later cold-boot initiator can resolve this
// peer's per-group overrides without needing a fresh handshake.
//
// Peers resolved to ModeDisabled (per-group override) do not get
// cached — there's nothing the policy ever needs to look up for them
// since disabled-mode decisions don't consult the Store.
func (dp *DefaultPolicy) OnHandshakeComplete(peer PeerInfo, subtype Subtype) {
	if dp.resolveMode(peer) == ModeDisabled {
		return
	}
	if subtype != SubtypePerPeer || dp.Store == nil || peer.Fingerprint == "" {
		return
	}
	if len(peer.CertBytes) == 0 || len(peer.StaticPubKey) != 32 {
		// Caller didn't supply the identity material we need to
		// resolve this peer on a future cold boot; nothing to cache.
		return
	}
	_ = dp.Store.MarkUpgraded(peer.Fingerprint, peer.CertBytes, peer.StaticPubKey, peer.VpnAddrs, peer.Groups)
}

// LookupBootIdentity is a thin shim over Store.LookupByVpnAddr that
// returns a PeerInfo populated from the on-disk cache. Used by the
// initiator path on a fresh boot to apply per-group mode overrides
// before any handshake has happened in this process.
func (dp *DefaultPolicy) LookupBootIdentity(vpnAddr string) (PeerInfo, bool) {
	if dp == nil || dp.Store == nil || vpnAddr == "" {
		return PeerInfo{}, false
	}
	h, fp, ok := dp.Store.LookupByVpnAddr(vpnAddr)
	if !ok {
		return PeerInfo{}, false
	}
	return PeerInfo{
		StaticPubKey: h.StaticPubKey,
		Fingerprint:  fp,
		CertBytes:    h.PeerCert,
		VpnAddrs:     h.VpnAddrs,
		Groups:       h.Groups,
	}, true
}

// OnHandshakeFailed implements Policy. Currently a no-op — kept so
// the Policy interface remains stable for future fail-closed hooks
// without churning every call site.
func (dp *DefaultPolicy) OnHandshakeFailed(peer PeerInfo, subtype Subtype, err error) {
}
