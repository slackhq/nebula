//go:build rosenpass_embedded

// Package rposvc embeds the go-rosenpass post-quantum key-exchange
// daemon directly inside nebula. The package owns:
//
//   - The local Rosenpass keypair (loaded from disk or generated).
//   - A go-rosenpass Server bound to a UDP socket on the node's
//     nebula tun IP, so Rosenpass packets ride the encrypted tunnel.
//   - A peer registry that mirrors nebula's known peers.
//   - A HandshakeCompletedHandler that writes derived 32-byte PSKs
//     into a pq.MemoryProvider, which nebula's IXPSK0 -> IXPSK2
//     upgrade path consumes via Subscribe / Lookup.
//
// This eliminates the Rosenpass sidecar binary, the on-disk PSK file,
// and the fsnotify watcher: PSKs flow memory-to-memory and the file
// system never touches the post-quantum key material.
package rposvc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	rp "cunicu.li/go-rosenpass"

	"github.com/slackhq/nebula/pq"
)

// udpAddrKey is a comparable, map-friendly snapshot of a *net.UDPAddr.
// Used to detect whether a re-AddPeer call carries a different
// endpoint than the cached one. We can't use *net.UDPAddr directly as
// a map value comparand because pointer identity is not meaningful
// (each AddPeer call typically constructs a fresh *net.UDPAddr).
// IP is stored as a 16-byte string (net.IP.To16 hex-equivalent) so
// IPv4 and IPv4-in-IPv6 representations of the same address compare
// equal — the embedded rosenpass server treats them as the same UDP
// destination, and we should too.
type udpAddrKey struct {
	ip   [16]byte
	port int
	zone string
}

func udpAddrKeyFromAddr(a *net.UDPAddr) udpAddrKey {
	if a == nil {
		return udpAddrKey{}
	}
	var k udpAddrKey
	ip := a.IP.To16()
	if ip != nil {
		copy(k.ip[:], ip)
	}
	k.port = a.Port
	k.zone = a.Zone
	return k
}

// Service is the embedded go-rosenpass instance plus glue.
//
// Lifecycle: New() loads or generates the local keypair and constructs
// the server. Start() launches the server's run loop in a goroutine.
// Close() terminates and unblocks any in-flight handshakes. The
// service is safe for concurrent peer registrations after Start.
type Service struct {
	cfg Config

	pub       rp.PublicKey
	sec       rp.SecretKey
	pubkeyHex string

	server *rp.Server
	mem    *pq.MemoryProvider

	mu       sync.Mutex
	peers    map[string]rp.PeerID     // hex(nebula peer static pubkey) -> rp peer id
	peerStat map[rp.PeerID][]byte     // rp peer id -> nebula peer static (for PSK callback routing)
	peerEnd  map[rp.PeerID]udpAddrKey // rp peer id -> last endpoint AddPeer was called with (for change detection)
	peerRP   map[rp.PeerID][]byte     // rp peer id -> last rosenpass pubkey registered (for change detection)

	cancel  context.CancelFunc
	started bool
	done    chan struct{}
	runErr  error // set once before done is closed; read after <-done
	logger  *slog.Logger
}

// Config bundles construction-time inputs.
type Config struct {
	// StateDir is where the persisted Rosenpass keypair lives.
	// Files: rp.pub, rp.sk. Created with mode 0700 if absent.
	StateDir string

	// ListenAddr is the UDP address Rosenpass binds to. In production
	// this is the node's nebula tun IP + a fixed port (default 51821);
	// inside-tunnel routing means Rosenpass traffic is naturally
	// reachable to peers without any host-firewall changes.
	ListenAddr *net.UDPAddr

	// MemoryProvider receives derived PSKs (one Set call per peer per
	// handshake). nebula's pq subsystem already owns this provider.
	MemoryProvider *pq.MemoryProvider

	// CertHasPqBinding reports whether this node's own cert already
	// carries a non-empty PqPskBinding. When true, the node was
	// provisioned WITH a PQ identity, so minting a brand-new keypair
	// (e.g. on a wiped/missing state_dir — issue #6) is the dangerous
	// regen that leaves peers rejecting us; loadOrGenerateKeypair
	// escalates that to an Error + metric rather than a quiet Info.
	CertHasPqBinding bool

	// StrictIdentity, when true, turns otherwise-degrade-gracefully PQ
	// identity problems (truncated keyfile, dangerous regen) into hard
	// errors from New so an operator who opted into required-style
	// guarantees gets a refusal instead of a silent fall to IXPSK0.
	// Default false: fresh nodes must still auto-generate, and any PQ
	// problem must degrade to classical Noise rather than break the
	// node. Wired from pq.embedded_rosenpass.strict_identity.
	StrictIdentity bool

	Logger *slog.Logger
}

// New constructs (but does not start) the service. Call Start() before
// adding peers; AddPeer is safe before Start but won't initiate
// handshakes until the run loop is up.
func New(cfg Config) (*Service, error) {
	if cfg.MemoryProvider == nil {
		return nil, errors.New("rposvc: MemoryProvider required")
	}
	if cfg.ListenAddr == nil {
		return nil, errors.New("rposvc: ListenAddr required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	pub, sec, err := loadOrGenerateKeypair(cfg.StateDir, cfg.Logger, cfg.CertHasPqBinding, cfg.StrictIdentity)
	if err != nil {
		return nil, fmt.Errorf("rposvc keypair: %w", err)
	}

	s := &Service{
		cfg:       cfg,
		pub:       pub,
		sec:       sec,
		pubkeyHex: pubkeyHex(pub),
		mem:       cfg.MemoryProvider,
		peers:     map[string]rp.PeerID{},
		peerStat:  map[rp.PeerID][]byte{},
		peerEnd:   map[rp.PeerID]udpAddrKey{},
		peerRP:    map[rp.PeerID][]byte{},
		done:      make(chan struct{}),
		logger:    cfg.Logger,
	}

	rpCfg := rp.Config{
		PublicKey:   pub,
		SecretKey:   sec,
		ListenAddrs: []*net.UDPAddr{cfg.ListenAddr},
		Logger:      cfg.Logger,
		Handlers:    []rp.Handler{(*completedHandler)(s)},
	}
	srv, err := rp.NewUDPServer(rpCfg)
	if err != nil {
		return nil, fmt.Errorf("rposvc server: %w", err)
	}
	s.server = srv
	return s, nil
}

// PublicKey returns the local Rosenpass static public key. Used by
// the discovery service that hands it out to peers over the nebula
// tunnel.
func (s *Service) PublicKey() []byte {
	return s.pub
}

// PublicKeyHex returns the hex-encoded SHA-256 of the local
// Rosenpass public key. Useful for logging and for binding into the
// nebula cert extension.
func (s *Service) PublicKeyHex() string {
	return s.pubkeyHex
}

// Start launches the rosenpass server's run loop. Errors from Run()
// after Start has returned propagate via the Done channel; the run
// loop exits cleanly when Close is called.
//
// Concurrency: writes s.cancel under s.mu so a concurrent Close
// cannot observe a torn pointer or skip cancellation.
func (s *Service) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancel = cancel
	s.started = true
	s.mu.Unlock()
	go func() {
		defer close(s.done)
		err := s.server.Run()
		// ctx.Err() != nil means Close cancelled us: a clean,
		// expected shutdown. Anything else is the silent-death case
		// (C1): the run loop is gone, so the service will never drive
		// another PQ handshake. Record the error (readable via Err()
		// after Done() fires), log LOUDLY, and bump a metric so the
		// embed-side watcher (and operators) can react. We do NOT
		// panic/exit — the node keeps running and degrades to IXPSK0.
		if ctx.Err() == nil {
			s.mu.Lock()
			s.runErr = err
			s.mu.Unlock()
			if err == nil {
				err = errors.New("rosenpass server run loop returned without error")
			}
			s.logger.Error("rosenpass server exited unexpectedly; PQ handshakes will not progress, peers degrade to IXPSK0",
				"err", err)
			incCounter(metricServerExited)
		}
	}()
}

// Done returns a channel that is closed when the rosenpass server run
// loop exits — whether from a clean Close or an unexpected death. The
// embed lifecycle goroutine selects on this to detect a dead server
// (C1) and surface/react rather than letting the Coordinator keep
// claiming "peer registered" against a server that no longer drives
// handshakes. Safe to call before Start (the channel just never
// closes until Start's goroutine runs and exits).
func (s *Service) Done() <-chan struct{} {
	return s.done
}

// Err returns the error the run loop exited with, or nil if it exited
// cleanly (via Close) or has not exited yet. Only meaningful to read
// after Done() has fired; reads under s.mu so it is race-free.
func (s *Service) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runErr
}

// Close stops the rosenpass server and waits for the run loop to exit.
// Safe to call multiple times, and safe to call before Start.
func (s *Service) Close() error {
	s.mu.Lock()
	cancel := s.cancel
	started := s.started
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if s.server != nil {
		_ = s.server.Close()
	}
	if started {
		<-s.done
	}
	return nil
}

// AddPeer registers a peer with the embedded server. peerStaticPubKey
// is the nebula peer's *nebula* static public key (used as the PSK
// lookup key); rosenpassPubKey is the peer's *rosenpass* static
// public key (Classic McEliece pubkey, ~524 KB). endpoint is the
// peer's reachable Rosenpass UDP address — typically
// <peer-nebula-ip>:51821 so traffic rides the nebula tunnel.
//
// Idempotence + endpoint refresh: if the peer is already known with
// the same rosenpass pubkey AND the same endpoint, the call is a
// no-op — that is the steady-state case where both ends of a tunnel
// observe handshake completion near-simultaneously and Notify into
// the Coordinator twice. If the endpoint (or pubkey) differs from
// the prior registration, the peer is de-registered and re-added so
// the embedded rosenpass server actually drives handshakes to the
// new destination. This is the gossip-arrival path: the first
// AddPeer happens at handshake-completion time using a placeholder
// or cfg-default port; once HostUpdate arrives carrying the peer's
// real RosenpassPort, the Coordinator re-Notifies and the
// re-registration here updates the cached endpoint. Without this,
// asymmetric-port deployments would stay pinned to whatever port
// the very-first registration guessed.
//
// AddPeer does not itself initiate a handshake; the underlying
// server initiates on its own schedule once the peer is registered.
func (s *Service) AddPeer(peerStaticPubKey, rosenpassPubKey []byte, endpoint *net.UDPAddr) error {
	if len(peerStaticPubKey) == 0 || len(rosenpassPubKey) == 0 {
		return errors.New("AddPeer: both peer keys required")
	}
	key := hexFingerprint(peerStaticPubKey)
	newEndKey := udpAddrKeyFromAddr(endpoint)

	pcfg := rp.PeerConfig{
		PublicKey: rp.PublicKey(rosenpassPubKey),
		Endpoint:  endpoint,
	}

	// Hold the mutex across the full check + server.AddPeer + map
	// insert so two concurrent calls for the same peer (which happen
	// routinely when both ends of a tunnel observe handshake
	// completion near-simultaneously) cannot both register a peer.
	// Without this, the second call would create a duplicate
	// rp.PeerID for the same logical peer; the HandshakeCompleted
	// callback then dispatches to whichever PeerID it was given,
	// which is sometimes the orphaned one whose peerStat entry got
	// overwritten — silently dropping the derived PSK and leaving
	// the pair on IXPSK0 forever.
	//
	// server.AddPeer is documented to be quick (no network I/O), so
	// holding the lock through it is acceptable.
	s.mu.Lock()
	defer s.mu.Unlock()
	if existingPid, exists := s.peers[key]; exists {
		// Steady state: identical endpoint + pubkey is a true no-op
		// (most common path — both ends re-Notify on every
		// completion). Anything else means a routing parameter
		// changed (gossip arrived with a new port, or the peer
		// rotated its rosenpass key) and we must re-register so the
		// underlying rosenpass server stops driving handshakes to
		// the stale destination.
		sameEnd := s.peerEnd[existingPid] == newEndKey
		samePub := bytes.Equal(s.peerRP[existingPid], rosenpassPubKey)
		if sameEnd && samePub {
			return nil
		}
		// Drop the stale registration. RemovePeer is best-effort:
		// even if it fails (e.g. server already lost track of the
		// id), we still want to clear our caches and re-add so the
		// next handshake uses the corrected endpoint.
		_ = s.server.RemovePeer(existingPid)
		delete(s.peers, key)
		delete(s.peerStat, existingPid)
		delete(s.peerEnd, existingPid)
		delete(s.peerRP, existingPid)
		s.logger.Info("rosenpass peer endpoint or pubkey changed; re-registering",
			"nebula_pubkey", key,
			"new_endpoint", endpoint.String(),
			"endpoint_changed", !sameEnd,
			"pubkey_changed", !samePub)
		// fall through to fresh registration below
	}
	pid, err := s.server.AddPeer(pcfg)
	if err != nil {
		return fmt.Errorf("AddPeer: %w", err)
	}
	s.peers[key] = pid
	s.peerStat[pid] = append([]byte(nil), peerStaticPubKey...)
	s.peerEnd[pid] = newEndKey
	s.peerRP[pid] = append([]byte(nil), rosenpassPubKey...)
	s.logger.Info("rosenpass peer registered",
		"nebula_pubkey", key, "endpoint", endpoint.String())
	return nil
}

// RemovePeer drops a peer registration and clears its derived PSK.
// Safe to call for unknown peers.
func (s *Service) RemovePeer(peerStaticPubKey []byte) {
	if len(peerStaticPubKey) == 0 {
		return
	}
	key := hexFingerprint(peerStaticPubKey)
	s.mu.Lock()
	pid, ok := s.peers[key]
	if ok {
		delete(s.peers, key)
		delete(s.peerStat, pid)
		delete(s.peerEnd, pid)
		delete(s.peerRP, pid)
	}
	s.mu.Unlock()
	if ok {
		_ = s.server.RemovePeer(pid)
	}
	s.mem.Delete(peerStaticPubKey)
}

// completedHandler implements rp.HandshakeCompletedHandler by
// forwarding (peer-id, derived-key) into the MemoryProvider keyed by
// the original nebula peer static pubkey.
type completedHandler Service

func (h *completedHandler) HandshakeCompleted(p rp.PeerID, k rp.Key) {
	s := (*Service)(h)
	// Hold s.mu across the peerStat read AND the mem.Set so a
	// concurrent RemovePeer (which deletes peerStat[pid] under
	// s.mu and then mem.Delete) cannot interleave between us
	// reading peerStat and writing the PSK. Without this guard
	// the sequence:
	//   completed: read peerStat (have nebPub)
	//   completed: <unlocked here>
	//   removePeer: delete peerStat, mem.Delete
	//   completed: mem.Set(nebPub, k)  <-- stale PSK survives
	// would re-write a PSK that was just supposed to be torn down,
	// undoing the rollback semantics that the Coordinator's
	// AddPeer-then-Pin path relies on.
	//
	// MemoryProvider.Set takes its own internal lock, but that
	// lock is independent of s.mu — so holding s.mu across
	// s.mem.Set introduces no lock-ordering conflict. Logging is
	// pulled out of the locked section to keep it short.
	s.mu.Lock()
	nebPub, ok := s.peerStat[p]
	if ok {
		s.mem.Set(nebPub, k[:])
	}
	s.mu.Unlock()
	if !ok {
		s.logger.Warn("rosenpass handshake completed for unknown peer id; dropping psk")
		incCounter(metricUnknownPeerPSKDropped)
		return
	}
	s.logger.Info("rosenpass PSK derived",
		"nebula_pubkey", hexFingerprint(nebPub))
	incCounter(metricCoordPSKDerived)
}

// go-rosenpass key sizes for the Classic McEliece 460896 static
// keypair. These mirror the (unexported) spkSize / sskSize constants in
// cunicu.li/go-rosenpass's types.go. sskSizeRound2 is the legacy
// round-2 secret-key length some older keyfiles may carry; both round-2
// and round-3 secret keys are accepted by the server, so we treat both
// as valid lengths. A keyfile whose length matches none of these was
// truncated mid-write (crash) or corrupted and must NOT be loaded as a
// "success" — doing so silently breaks PQ for this node (C3).
const (
	rpPublicKeySize   = 524160 // spkSize
	rpSecretKeySizeR3 = 13608  // sskSize (round 3)
	rpSecretKeySizeR2 = 13568  // sskSizeRound2 (round 2)
)

func validRPSecretKeyLen(n int) bool {
	return n == rpSecretKeySizeR3 || n == rpSecretKeySizeR2
}

// loadOrGenerateKeypair loads the persisted rosenpass keypair from
// stateDir, validating file lengths (C3), or generates a fresh one.
//
// certHasBinding tells us whether the node's own cert already binds a
// PQ identity. When it does, minting a NEW keypair is the dangerous
// regen of issue #6 (a wiped/missing state_dir): the fresh pubkey no
// longer matches the CA-signed PqPskBinding, so every peer rejects our
// PQ identity and tunnels silently stay on IXPSK0. We escalate that to
// an Error + metric. Under strict (StrictIdentity), the dangerous
// regen and a truncated keyfile become hard errors so an operator who
// opted into required-style guarantees gets a refusal; otherwise we
// keep auto-generating (fresh nodes need it) and rely on the loud
// log + metric + the identity-mismatch check at startup.
func loadOrGenerateKeypair(stateDir string, l *slog.Logger, certHasBinding, strict bool) (rp.PublicKey, rp.SecretKey, error) {
	if stateDir == "" {
		return nil, nil, errors.New("StateDir required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, nil, err
	}
	pubPath := filepath.Join(stateDir, "rp.pub")
	skPath := filepath.Join(stateDir, "rp.sk")

	pubBytes, errPub := os.ReadFile(pubPath)
	skBytes, errSk := os.ReadFile(skPath)
	if errPub == nil && errSk == nil {
		// Both files present. Validate lengths before declaring
		// success: a crash mid-write can leave a short rp.pub/rp.sk
		// that would otherwise load behind a misleading "loaded
		// existing keypair" Info and then fail every handshake (C3).
		if len(pubBytes) != rpPublicKeySize || !validRPSecretKeyLen(len(skBytes)) {
			l.Error("rosenpass keyfile length invalid; treating as no usable keypair (likely truncated mid-write)",
				"dir", stateDir,
				"pub_len", len(pubBytes), "want_pub_len", rpPublicKeySize,
				"sk_len", len(skBytes), "want_sk_len", rpSecretKeySizeR3,
				"remediation", "delete BOTH rp.pub and rp.sk in stateDir to regenerate; re-issue this node's nebula cert if its PqPskBinding was already distributed")
			incCounter(metricKeypairLoadFailed)
			if strict {
				return nil, nil, fmt.Errorf("rosenpass keyfile length invalid (pub=%d sk=%d); refusing under strict_identity", len(pubBytes), len(skBytes))
			}
			// Fall through to generation. Treat the corrupt keyfiles
			// like a missing-pair: the dangerous-regen escalation
			// below still fires if the cert binds an identity.
			return generateKeypair(pubPath, skPath, l, stateDir, certHasBinding, strict)
		}
		l.Info("loaded existing rosenpass keypair", "dir", stateDir)
		return rp.PublicKey(pubBytes), rp.SecretKey(skBytes), nil
	}
	if (errPub == nil) != (errSk == nil) {
		// Partial keypair on disk: previous start crashed between
		// the two writes, leaving rp.pub without rp.sk (or vice
		// versa). The orphan public key may already have been
		// signed into a peer's cert (cert-v2 rosenpassPubKeySha256
		// extension) and distributed across the mesh; if we
		// silently regenerated, peers would refuse to register us
		// after the new pubkey hash fails their cert-bound hash
		// check, causing a silent mesh-wide outage. Refuse to
		// start and emit a remediation message so the operator can
		// decide whether to delete the orphan + regenerate + re-
		// issue certs, or restore from a known-good backup.
		l.Error("rosenpass keypair partial on disk; refusing to overwrite",
			"dir", stateDir, "pub_err", errPub, "sk_err", errSk,
			"remediation", "delete BOTH rp.pub and rp.sk in stateDir to regenerate; re-issue this node's nebula cert (its rosenpassPubKeySha256 extension changes with the new pubkey)")
		return nil, nil, fmt.Errorf("rosenpass keypair partial: pub=%v sk=%v", errPub, errSk)
	}

	// Both files absent: this is the generate path.
	return generateKeypair(pubPath, skPath, l, stateDir, certHasBinding, strict)
}

// generateKeypair mints a fresh rosenpass keypair and persists it.
//
// certHasBinding gates the issue-#6 dangerous-regen escalation: if the
// node's cert already binds a PQ identity yet we are about to mint a
// NEW one (wiped/missing state_dir, or a corrupt keyfile we just
// rejected), the new pubkey will not match the CA-signed PqPskBinding
// and every peer will reject our PQ identity until the cert is re-
// issued. That is loud (Error + metric). Under strict we refuse rather
// than silently minting an identity peers will reject. With no cert
// binding (a genuinely fresh node) this is the expected one-time
// generation and stays at Info level.
func generateKeypair(pubPath, skPath string, l *slog.Logger, stateDir string, certHasBinding, strict bool) (rp.PublicKey, rp.SecretKey, error) {
	if certHasBinding {
		incCounter(metricKeypairRegenDanger)
		l.Error("regenerating rosenpass PQ identity though this node's cert binds an existing one; peers will reject PQ until the cert is re-provisioned (tunnels degrade to IXPSK0)",
			"dir", stateDir,
			"remediation", "restore the original rp.pub/rp.sk from backup, OR re-issue this node's nebula cert so its PqPskBinding matches the new identity")
		if strict {
			return nil, nil, errors.New("refusing to regenerate rosenpass identity under strict_identity: cert binds an existing PQ identity (restore the keypair from backup or re-issue the cert)")
		}
	}

	// Generation order matters: rp.sk is the secret half. Write it
	// first so a crash between the writes leaves a stale rp.sk
	// without rp.pub — easier to diagnose and recover from than
	// the inverse (orphan pub already pinned by remote peers).
	l.Info("generating rosenpass keypair (one-time)", "dir", stateDir)
	pub, sec, err := rp.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	if err := writeAtomic(skPath, sec, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write rp.sk: %w", err)
	}
	if err := writeAtomic(pubPath, pub, 0o644); err != nil {
		// Best-effort cleanup so the next start sees neither half
		// rather than an orphan rp.sk. Log on cleanup failure so an
		// operator hitting the partial-keypair guard on next boot
		// has the diagnostic trail.
		if rerr := os.Remove(skPath); rerr != nil && !os.IsNotExist(rerr) {
			l.Warn("rosenpass: failed to clean orphan rp.sk after rp.pub write failure",
				"path", skPath, "cleanup_err", rerr)
		}
		return nil, nil, fmt.Errorf("write rp.pub: %w", err)
	}
	incCounter(metricKeypairGenerated)
	return pub, sec, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".rp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	// Chmod BEFORE writing so the secret bytes never live on disk
	// at a wider mode than the caller requested, even on platforms
	// where CreateTemp does not default to 0600.
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
