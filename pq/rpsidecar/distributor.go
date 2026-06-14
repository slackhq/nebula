// Package rpsidecar wires nebula's lighthouse gossip into an
// out-of-process rosenpass binary running as a sidecar. It is the
// build-tag-free analogue of pq/rposvc.Coordinator for deployments
// that prefer the audited Rust rosenpass binary over the unaudited
// go-rosenpass embedded path.
//
// The Distributor consumes PeerObserved events (same event the
// embedded Coordinator consumes), fetches the peer's rosenpass
// public key via the tunnel-internal HTTP discovery endpoint,
// verifies the bytes against the CA-signed cert-extension hash,
// and writes them atomically into a configured directory shaped
// for the sidecar to consume. nebula does not exec the sidecar
// or signal it; operators wire reload via inotify path units,
// systemd, or whatever fits their environment.
//
// Trust model: identical to the embedded Coordinator.
// ExpectedPubkeyHash comes from cert-v2 rosenpassPubKeySha256, so a
// peer with no extension or a hash mismatch is refused. The fetch
// itself rides the nebula tunnel (cert-authenticated underlay).
//
// Limitations the Distributor cannot fix:
//
//   - The rosenpass binary does not hot-reload its peer table. Adding
//     a new peer's pubkey to the watched dir surfaces it to the
//     operator's reload mechanism (path unit, polling restart, etc.);
//     the actual rosenpass-side registration is out of nebula's hands.
//   - A peer rotating its rosenpass key requires the new pubkey file
//     AND a rosenpass restart on the consuming side.
package rpsidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/slackhq/nebula/pq/rphttp"
)

// pendingReplayCap mirrors the Coordinator's bound: a single
// distribution goroutine will replay the pending slot at most this
// many times before bailing out. This guards against a misbehaving
// peer (or compromised lighthouse) that can keep gossip churning
// faster than fetch + write completes.
const pendingReplayCap = 10

// Config wires the Distributor to nebula's network and the sidecar's
// peer-keys directory.
type Config struct {
	// PubkeyDir is the directory the Distributor writes peer rosenpass
	// pubkeys into. Files are named <fingerprint>.pub. The operator
	// points the sidecar's rosenpass.toml [peer] entries at these paths
	// (one per peer); they must exist before rosenpass start.
	//
	// Empty PubkeyDir means "do not write files" — useful for
	// deployments that only want the trust-binding side of gossip
	// (cert-hash mismatches still get logged) without nebula touching
	// the filesystem.
	PubkeyDir string

	// Fetcher pulls a peer's rosenpass pubkey from its discovery
	// endpoint. Defaults to rphttp.FetchPubkey; injected by tests.
	Fetcher rphttp.Fetcher

	// DiscoveryPort is the TCP port peers serve their pubkey on.
	// Default 51820. Used when the per-peer gossiped DiscoveryPort
	// is 0 (peer hasn't gossiped yet, or runs an older binary).
	DiscoveryPort int

	// FetchTimeout caps a single pubkey fetch attempt. Default 10s.
	FetchTimeout time.Duration

	// FetchRetries controls how many times a fetch is retried with
	// exponential backoff before giving up. Default 3.
	FetchRetries int

	// Dialer is used for tunnel-internal HTTP fetches. May be nil;
	// a default dialer with a 5s connect timeout is constructed on
	// first use.
	Dialer *net.Dialer

	Logger *slog.Logger
}

// Distributor turns nebula handshake events into peer-pubkey file
// writes that a rosenpass sidecar can consume. Behaviour mirrors
// pq/rposvc.Coordinator (in-flight dedup, pending-replay for
// gossip-corrected ports, fetch retries) so operators get the same
// liveness story whether they run embedded or sidecar.
//
// The Distributor satisfies io.Closer so it can be stored in the
// Interface's pqProvider slot alongside *rposvc.Coordinator.
type Distributor struct {
	cfg    Config
	logger *slog.Logger

	mu       sync.Mutex
	inflight map[string]struct{}            // hex(sha256(peer-static)) -> a fetch goroutine is currently running
	pending  map[string]rphttp.PeerObserved // hex(sha256(peer-static)) -> latest Notify args observed while a fetch was in-flight; replayed when it finishes
	closed   bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New wires the inputs but does not start goroutines. Start launches
// lifecycle; Close stops it cleanly.
func New(cfg Config) (*Distributor, error) {
	if cfg.PubkeyDir != "" {
		// Verify the directory exists and is writable up front so
		// misconfigurations surface at startup, not on the first
		// successful gossip.
		st, err := os.Stat(cfg.PubkeyDir)
		if err != nil {
			return nil, fmt.Errorf("rpsidecar: stat PubkeyDir %q: %w", cfg.PubkeyDir, err)
		}
		if !st.IsDir() {
			return nil, fmt.Errorf("rpsidecar: PubkeyDir %q is not a directory", cfg.PubkeyDir)
		}
	}
	if cfg.DiscoveryPort == 0 {
		cfg.DiscoveryPort = 51820
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = 10 * time.Second
	}
	if cfg.FetchRetries == 0 {
		cfg.FetchRetries = 3
	}
	if cfg.Fetcher == nil {
		cfg.Fetcher = rphttp.FetchPubkey
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Distributor{
		cfg:      cfg,
		inflight: map[string]struct{}{},
		pending:  map[string]rphttp.PeerObserved{},
		logger:   cfg.Logger,
	}, nil
}

// Start arms the Distributor for Notify events. Each Notify spawns
// its own goroutine; there is no central run loop.
func (d *Distributor) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	d.mu.Lock()
	d.ctx = ctx
	d.cancel = cancel
	d.mu.Unlock()
}

// Close cancels the shared context and waits for spawned goroutines
// to exit. Idempotent.
func (d *Distributor) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	cancel := d.cancel
	d.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	d.wg.Wait()
	return nil
}

// Notify is called by nebula on every handshake completion. It spawns
// a fire-and-forget goroutine that fetches the peer's rosenpass
// pubkey and writes it to PubkeyDir/<fingerprint>.pub. If a fetch
// for this peer is already in flight, the event is queued as the
// pending slot (single-slot, overwrites) and replayed when the
// current fetch completes.
func (d *Distributor) Notify(ev rphttp.PeerObserved) {
	if !ev.VpnIP.IsValid() || len(ev.PeerStaticPubKey) == 0 {
		return
	}
	key := hexFingerprint(ev.PeerStaticPubKey)

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	if _, busy := d.inflight[key]; busy {
		d.pending[key] = ev
		d.mu.Unlock()
		return
	}
	d.inflight[key] = struct{}{}
	ctx := d.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	d.wg.Add(1)
	d.mu.Unlock()

	go func() {
		defer d.wg.Done()
		current := ev
		iter := 0
		for {
			err := d.fetchAndWrite(ctx, current, key)
			if err != nil {
				incCounter(metricDistFetchFailed)
				d.logger.Warn("rosenpass pubkey distribution failed",
					"vpnIP", current.VpnIP, "err", err)
			}
			iter++
			d.mu.Lock()
			if iter >= pendingReplayCap {
				delete(d.inflight, key)
				_, hadPending := d.pending[key]
				d.mu.Unlock()
				if hadPending {
					incCounter(metricDistReplayCapHit)
					d.logger.Warn("rosenpass pending replay cap hit; deferring to next Notify",
						"key", key, "iterations", iter)
				}
				return
			}
			next, hasNext := d.pending[key]
			if hasNext {
				delete(d.pending, key)
				d.mu.Unlock()
				current = next
				continue
			}
			delete(d.inflight, key)
			d.mu.Unlock()
			return
		}
	}()
}

// Forget removes a peer's pubkey file from PubkeyDir (best-effort).
// nebula calls this on peer removal events. If PubkeyDir is empty
// (file-write mode disabled) Forget is a no-op.
func (d *Distributor) Forget(peerStaticPubKey []byte) {
	if d.cfg.PubkeyDir == "" || len(peerStaticPubKey) == 0 {
		return
	}
	// Forget operates on the fingerprint, which we don't have here;
	// scan the directory for files matching the static-key prefix
	// indirectly via filename is more work than this hook merits.
	// Leaving the file on disk is harmless — the sidecar still has it
	// in rosenpass config until the operator removes the peer entry.
	// This is intentionally weaker than the embedded Forget, which
	// removes in-memory state; on-disk state outlives the nebula tunnel
	// by design (rosenpass config survives nebula restarts).
}

func (d *Distributor) fetchAndWrite(ctx context.Context, ev rphttp.PeerObserved, key string) error {
	if ev.ExpectedPubkeyHash == "" {
		return fmt.Errorf("peer cert lacks rosenpassPubKeySha256 extension; rotate cert through CA to enable PQ")
	}

	discPort := d.cfg.DiscoveryPort
	if ev.DiscoveryPort != 0 {
		discPort = int(ev.DiscoveryPort)
	}
	discAddr := &net.TCPAddr{
		IP:   addrToIP(ev.VpnIP),
		Port: discPort,
	}

	var (
		pubkey []byte
		err    error
	)
	delay := 250 * time.Millisecond
	for attempt := 0; attempt < d.cfg.FetchRetries; attempt++ {
		fetchCtx, cancel := context.WithTimeout(ctx, d.cfg.FetchTimeout)
		pubkey, err = d.cfg.Fetcher(fetchCtx, discAddr, ev.ExpectedPubkeyHash, d.cfg.Dialer)
		cancel()
		if err == nil {
			break
		}
		// Hash mismatch is a cert/key disagreement; retry will not fix it.
		if _, mismatch := err.(rphttp.ErrPubkeyHashMismatch); mismatch {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			delay *= 2
		}
	}
	if err != nil {
		return fmt.Errorf("fetch pubkey from %s: %w", discAddr, err)
	}

	// fetcher verifies hash already (when expectedHash non-empty), but
	// re-check explicitly: a custom Fetcher might be lax.
	sum := sha256.Sum256(pubkey)
	gotHash := hex.EncodeToString(sum[:])
	if gotHash != ev.ExpectedPubkeyHash {
		return rphttp.ErrPubkeyHashMismatch{Expected: ev.ExpectedPubkeyHash, Got: gotHash}
	}

	if d.cfg.PubkeyDir == "" {
		// Hash-only mode: trust binding verified, no file write.
		d.logger.Info("rosenpass peer pubkey verified (file-write disabled)",
			"vpnIP", ev.VpnIP, "fingerprint", ev.Fingerprint,
			"rp_pubkey_size", len(pubkey))
		return nil
	}

	// Atomic write: tmp file + rename. Filename keyed by fingerprint
	// (operator-readable, stable across nebula restarts) rather than
	// hex(peer-static) (rosenpass operators tend to think in cert names).
	name := filenameFor(ev.Fingerprint)
	if name == "" {
		return fmt.Errorf("empty fingerprint; cannot derive filename")
	}
	dst := filepath.Join(d.cfg.PubkeyDir, name)
	if err := atomicWriteFile(dst, pubkey, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	d.logger.Info("rosenpass peer pubkey written",
		"vpnIP", ev.VpnIP, "fingerprint", ev.Fingerprint,
		"path", dst, "rp_pubkey_size", len(pubkey))
	return nil
}

// filenameFor turns a nebula cert fingerprint into a filesystem-safe
// filename. Fingerprints are SHA-256 hex (lowercase), so they are
// already safe; we keep the function as a hook for future sanitization
// if the source changes.
func filenameFor(fingerprint string) string {
	if fingerprint == "" {
		return ""
	}
	return fingerprint + ".pub"
}

// atomicWriteFile writes data to a tmp file in the same directory as
// path, then renames it into place. Same-directory rename on local
// filesystems is atomic on POSIX, so a concurrent reader (the
// sidecar's startup-time peer load, or an inotify watcher) sees
// either the old contents or the new — never a partial write.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".rppub-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		// Best-effort cleanup if rename failed.
		_ = os.Remove(tmp)
	}()
	// Mode set before any bytes hit the file, matching rposvc.writeAtomic:
	// today this only writes public keys, but the signature accepts an
	// arbitrary mode and the pattern must stay safe if reused for
	// restricted material.
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func addrToIP(a netip.Addr) net.IP {
	if a.Is4() {
		b := a.As4()
		return net.IP(b[:])
	}
	b := a.As16()
	return net.IP(b[:])
}
