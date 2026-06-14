package pq

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// PeerHistory is the per-peer identity cache persisted across
// restarts. After the TOFU mode was removed (cert-v2 binds the
// PQ-PSK binding hash so per-peer pinning is redundant), this
// struct holds only the bits the boot-path initiator needs to apply
// per-group mode overrides before any handshake has happened in
// this process: the cert, the static pubkey, the VPN addrs, and the
// CA-signed group claims.
//
// Keyed by peer cert fingerprint (hex). Fingerprint is stable across
// cert rotations only if the public key is reused; in nebula's PKI a
// new cert with the same key keeps the same fingerprint.
type PeerHistory struct {
	// PeerCert is the marshaled-for-handshakes bytes of the peer's
	// nebula certificate at the moment IXPSK2 last succeeded. Used
	// by the initiator at boot to resolve the peer's identity before
	// any handshake has happened in this process.
	PeerCert []byte `json:"peer_cert,omitempty"`

	// StaticPubKey is the peer's noise static public key (32 bytes
	// for curve25519). Cached as a hot path so we don't reparse the
	// cert on every Lookup decision.
	StaticPubKey []byte `json:"static_pubkey,omitempty"`

	// VpnAddrs lists the nebula overlay addresses asserted by the
	// peer's cert. Used to build the secondary index allowing
	// initiator-side lookups by destination VPN addr.
	VpnAddrs []string `json:"vpn_addrs,omitempty"`

	// Groups are the cert group claims (CA-signed) at the moment
	// the peer last upgraded. Cached so the boot-path initiator's
	// DefaultPolicy.Overrides can apply per-group mode overrides
	// without needing a fresh cert handshake first.
	Groups []string `json:"groups,omitempty"`
}

// Store keeps PeerHistory keyed by cert fingerprint, persists to disk
// atomically (tempfile + rename), and is safe for concurrent access.
//
// Persistence is best-effort: a write failure is logged but does not
// fail the caller. The in-memory map is always authoritative for the
// current process; the file is a recovery aid for restarts.
//
// Legacy fields (ever_upgraded, last_upgrade, last_failure,
// failure_count, rp_pubkey_sha256) from pre-cert-extension state
// files are silently dropped at load time — the JSON decoder ignores
// unknown fields and the loader keeps only the identity-cache
// columns above.
type Store struct {
	path string
	mu   sync.RWMutex
	data map[string]*PeerHistory

	// persistMu serializes persist() so that two concurrent callers
	// (e.g. overlapping MarkUpgraded invocations) cannot interleave
	// their marshal+CreateTemp+rename sequences and leave the on-disk
	// file reflecting an older in-memory snapshot. It is deliberately
	// separate from mu: mu guards the in-memory map (and must NOT be
	// held across file I/O), while persistMu only orders the file
	// writes. Lock order is always mu (released) → persistMu, never
	// the reverse, so the two can't deadlock.
	persistMu sync.Mutex

	// vpnIndex maps a peer's nebula VPN address (string form) to the
	// fingerprint we have on file. Rebuilt from data on load and
	// maintained in lockstep on MarkUpgraded.
	vpnIndex map[string]string

	// logger is used for low-frequency observability events (currently
	// just malformed-entry evictions at load time). Defaults to
	// slog.Default() when not configured via WithLogger so existing
	// callers don't have to plumb a logger through.
	logger *slog.Logger
}

// StoreOption configures optional Store behaviour at construction
// time. Use the With* helpers (e.g. WithLogger) rather than
// constructing StoreOption values directly.
type StoreOption func(*Store)

// WithLogger plumbs a slog.Logger into the Store so observability
// events (currently only malformed-entry evictions during load) are
// emitted to the operator's chosen sink. If never set, the Store uses
// slog.Default(), matching the global handler.
func WithLogger(l *slog.Logger) StoreOption {
	return func(s *Store) {
		if l != nil {
			s.logger = l
		}
	}
}

// NewStore opens (or creates) a persistence file at path. If the file
// does not exist, the store starts empty. Loader rejects entries that
// fail to decode; a corrupt file is logged and the store starts empty
// so the daemon can boot.
//
// Optional StoreOptions (e.g. WithLogger) configure observability
// hooks. Without any options the Store is fully functional and uses
// slog.Default() for the small number of warn-level events it emits.
func NewStore(path string, opts ...StoreOption) (*Store, error) {
	s := &Store{
		path:     path,
		data:     map[string]*PeerHistory{},
		vpnIndex: map[string]string{},
		logger:   slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	if path == "" {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("pq state: mkdir: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("pq state: open %q: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("pq state: read %q: %w", path, err)
	}
	if len(raw) == 0 {
		return s, nil
	}
	var on map[string]*PeerHistory
	if err := json.Unmarshal(raw, &on); err != nil {
		// Corrupt file is not fatal — start empty (warm-start cache
		// only; a fresh handshake re-populates it). But surface it
		// LOUDLY so the operator notices a truncated write / manual
		// edit / schema drift, matching the struct doc comment that
		// promises "a corrupt file is logged" and the per-entry
		// eviction logging in rebuildIndex.
		l := s.logger
		if l == nil {
			l = slog.Default()
		}
		l.Warn("pq state: corrupt state file, starting with empty cache",
			"path", path,
			"bytes", len(raw),
			"err", err)
		incCounter(MetricStateLoadFailed)
		return s, nil
	}
	if on != nil {
		s.data = on
		s.rebuildIndex()
	}
	return s, nil
}

func (s *Store) rebuildIndex() {
	s.vpnIndex = make(map[string]string, len(s.data))
	for fp, h := range s.data {
		if h == nil {
			s.logEviction(fp, "nil entry")
			delete(s.data, fp)
			continue
		}
		// Drop entries that lack the identity material we need to
		// resolve the peer on a future cold boot — a partial record
		// would only confuse LookupByVpnAddr. Surface the eviction so
		// the operator gets a signal when a previously-cached peer
		// vanishes from the index after a restart.
		if len(h.PeerCert) == 0 {
			s.logEviction(fp, "missing peer cert")
			delete(s.data, fp)
			continue
		}
		if len(h.StaticPubKey) != 32 {
			s.logEviction(fp, fmt.Sprintf("static pubkey wrong length (%d bytes, want 32)", len(h.StaticPubKey)))
			delete(s.data, fp)
			continue
		}
		for _, vpn := range h.VpnAddrs {
			s.vpnIndex[vpn] = fp
		}
	}
}

// logEviction emits a Warn-level log line for an entry that the
// loader had to drop from the in-memory store. Operators rely on this
// to notice malformed state files (truncated writes, manual edits, or
// schema drift across nebula versions). Falls back to slog.Default()
// if the Store was constructed without WithLogger.
func (s *Store) logEviction(fp, reason string) {
	l := s.logger
	if l == nil {
		l = slog.Default()
	}
	l.Warn("pq state: dropping malformed entry from state file",
		"fingerprint", fp,
		"reason", reason,
		"path", s.path)
}

// Get returns a copy of the entry for fp, or zero PeerHistory if absent.
func (s *Store) Get(fp string) PeerHistory {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if h, ok := s.data[fp]; ok && h != nil {
		return *h
	}
	return PeerHistory{}
}

// LookupByVpnAddr returns the cached identity for a peer reachable at
// vpnAddr. Boolean reports whether anything was found. Caller can use
// the returned PeerHistory to drive an initiator-side per-group mode
// override decision before the first handshake completes.
func (s *Store) LookupByVpnAddr(vpnAddr string) (PeerHistory, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fp, ok := s.vpnIndex[vpnAddr]
	if !ok {
		return PeerHistory{}, "", false
	}
	h, ok := s.data[fp]
	if !ok || h == nil {
		return PeerHistory{}, "", false
	}
	return *h, fp, true
}

// MarkUpgraded records that an IXPSK2 handshake has just succeeded
// with the peer identified by fp, capturing identity material so the
// store has enough information to resolve the peer on a future cold
// boot.
//
// Returns the persistence error (if any) for caller logging; does not
// fail the handshake itself.
func (s *Store) MarkUpgraded(fp string, certBytes, staticPubKey []byte, vpnAddrs, groups []string) error {
	if fp == "" {
		return nil
	}
	if len(staticPubKey) != 32 {
		return fmt.Errorf("pq state: static pubkey must be 32 bytes, got %d", len(staticPubKey))
	}
	if len(certBytes) == 0 {
		return fmt.Errorf("pq state: cert bytes required for identity cache")
	}

	s.mu.Lock()
	h, ok := s.data[fp]
	if !ok || h == nil {
		h = &PeerHistory{}
		s.data[fp] = h
	}
	// Drop stale VPN-addr entries from the index that pointed to this
	// fp; about to rebuild from the new VpnAddrs.
	for _, oldVpn := range h.VpnAddrs {
		if s.vpnIndex[oldVpn] == fp {
			delete(s.vpnIndex, oldVpn)
		}
	}
	h.PeerCert = append([]byte(nil), certBytes...)
	h.StaticPubKey = append([]byte(nil), staticPubKey...)
	h.VpnAddrs = append([]string(nil), vpnAddrs...)
	h.Groups = append([]string(nil), groups...)
	for _, vpn := range vpnAddrs {
		s.vpnIndex[vpn] = fp
	}
	s.mu.Unlock()

	return s.persist()
}

// persist writes the store to disk atomically (tempfile + rename in
// the same directory). Caller must not hold s.mu.
func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	// Serialize the whole marshal+write+rename so two concurrent
	// persists can't reorder their renames and leave an older snapshot
	// on disk. We snapshot s.data under the in-memory RLock (released
	// before any file I/O) and hold persistMu across the I/O; the
	// last caller to acquire persistMu marshals the latest map, so the
	// on-disk file always converges to a state at least as new as the
	// in-memory map at that caller's marshal time.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	s.mu.RLock()
	raw, err := json.MarshalIndent(s.data, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".pq-state-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		// best-effort: if rename succeeded the file is gone already
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.path)
}

// fingerprintHex is exposed primarily for tests that need to make a
// well-formed key without importing nebula's cert package. Callers in
// production should use the cert's existing fingerprint directly.
func fingerprintHex(b []byte) string {
	return hex.EncodeToString(b)
}
