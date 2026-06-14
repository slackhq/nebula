//go:build rosenpass_embedded

package rposvc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/slackhq/nebula/pq/rphttp"
)

// pendingReplayCap bounds how many times a single fetch goroutine
// will replay the queued `pending` slot before bailing out. Without a
// cap, a peer whose gossip churns faster than fetchAndRegister
// completes will keep the goroutine pinned indefinitely — a
// compromised lighthouse forwarding crafted gossip could pin one
// goroutine per peer with a valid cert extension. When the cap is
// hit, the goroutine exits without consuming `pending[key]` (so the
// next Notify picks the work back up via the normal entry path) and
// logs a Warn so operators see the churn signal. 10 is high enough to
// drain reasonable real-world replay storms (gossip catching up after
// a flapping link, etc.) but low enough that pathological churn is
// bounded.
const pendingReplayCap = 10

// CoordinatorConfig wires the embedded service to nebula's network.
type CoordinatorConfig struct {
	// Service is the running embedded Rosenpass server. Declared as
	// ServiceAPI (an interface satisfied by *Service) so tests can
	// inject a fake without keypair generation or a UDP listener.
	Service ServiceAPI

	// Discovery is the local pubkey-serving HTTP service.
	Discovery *rphttp.Discovery

	// Fetcher fetches a peer's Rosenpass pubkey. Defaults to
	// rphttp.FetchPubkey when nil; injected by tests.
	Fetcher rphttp.Fetcher

	// RosenpassPort is the UDP port peers will receive Rosenpass
	// handshake packets on (their own equivalent of our service's
	// ListenAddr port). Default 51821.
	RosenpassPort int

	// DiscoveryPort is the TCP port peers serve their pubkey on.
	// Default 51820.
	DiscoveryPort int

	// FetchTimeout caps a single pubkey fetch attempt.
	FetchTimeout time.Duration

	// FetchRetries controls how many times a fetch is retried with
	// exponential backoff before giving up.
	FetchRetries int

	// Dialer is used for tunnel-internal HTTP fetches. May be nil; a
	// default dialer is constructed on first use.
	Dialer *net.Dialer

	Logger *slog.Logger
}

// Coordinator turns nebula handshake events into Rosenpass peer
// registrations + PSK derivation. On every Notify, it spawns a
// fire-and-forget goroutine that fetches the peer's Rosenpass pubkey
// and calls Service.AddPeer (which is idempotent — see rposvc.go).
// On fetch failure, the next Notify retries. There is intentionally
// no cooldown/backoff/generation state: handshake events are the
// natural retry signal, and Service.AddPeer's own dedup guards
// against duplicate registrations.
//
// A small per-peer in-flight set prevents unbounded goroutine spawn
// when a peer fires Notify many times in quick succession: while a
// fetch is in flight for peer X, further Notify events for X are
// dropped. This is the only state the Coordinator tracks.
type Coordinator struct {
	cfg    CoordinatorConfig
	logger *slog.Logger

	mu       sync.Mutex
	inflight map[string]struct{}            // hex(peer-static) -> a fetch goroutine is currently running
	pending  map[string]rphttp.PeerObserved // hex(peer-static) -> latest Notify args observed while a fetch was in-flight; replayed when it finishes (so a gossip-driven re-Notify carrying corrected ports actually fires its own fetch instead of being silently dropped under inflight-dedup)
	closed   bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewCoordinator wires the inputs but does not start goroutines.
// Start launches lifecycle; Close stops it cleanly.
func NewCoordinator(cfg CoordinatorConfig) (*Coordinator, error) {
	if cfg.Service == nil {
		return nil, fmt.Errorf("Coordinator: Service required")
	}
	if cfg.Discovery == nil {
		return nil, fmt.Errorf("Coordinator: Discovery required")
	}
	if cfg.RosenpassPort == 0 {
		cfg.RosenpassPort = 51821
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
	return &Coordinator{
		cfg:      cfg,
		inflight: map[string]struct{}{},
		pending:  map[string]rphttp.PeerObserved{},
		logger:   cfg.Logger,
	}, nil
}

// Start arms the Coordinator for Notify events. Each Notify spawns
// its own goroutine; there is no central run loop to launch. Start
// only installs the cancellable context that fetch goroutines tie
// into, so Close can interrupt long-running fetches.
//
// Concurrency note: Start writes to c.cancel under c.mu so a
// concurrent Close cannot observe a nil cancel.
func (c *Coordinator) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.ctx = ctx
	c.cancel = cancel
	c.mu.Unlock()
}

// Close cancels the shared context (interrupting any in-flight
// fetches) and waits for all spawned goroutines to exit. Idempotent;
// safe to call before Start.
func (c *Coordinator) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.wg.Wait()
	return nil
}

// Notify is called by nebula on every handshake completion. It spawns
// a fire-and-forget goroutine that fetches the peer's Rosenpass
// pubkey and registers it with the embedded Service. If a fetch for
// this peer is already in flight, the event is dropped (the running
// fetch will register the peer; further Notify-driven retries are
// only needed on failure). Close-after-Notify also drops silently.
func (c *Coordinator) Notify(ev rphttp.PeerObserved) {
	if !ev.VpnIP.IsValid() || len(ev.PeerStaticPubKey) == 0 {
		return
	}
	key := hexFingerprint(ev.PeerStaticPubKey)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if _, busy := c.inflight[key]; busy {
		// Queue the latest args. When the in-flight fetch finishes,
		// the goroutine replays with these. Critical for the
		// gossip-driven re-Notify case: a HostUpdate arriving DURING
		// the initial wrong-port fetch carries the corrected ports
		// but would otherwise be silently dropped here, leaving the
		// Coordinator pinned to the cfg fallback for the lifetime of
		// the tunnel. A single-slot pending overwrites: only the
		// latest gossip matters for re-registration.
		c.pending[key] = ev
		c.mu.Unlock()
		return
	}
	c.inflight[key] = struct{}{}
	ctx := c.ctx
	if ctx == nil {
		// Start was never called. Use a background context so the
		// fetch can still complete; Close (if subsequently called)
		// will wait on the WaitGroup.
		ctx = context.Background()
	}
	c.wg.Add(1)
	c.mu.Unlock()

	go func() {
		defer c.wg.Done()
		current := ev
		iter := 0
		for {
			err := c.fetchAndRegister(ctx, current, key)
			if err != nil {
				c.logger.Warn("rosenpass peer setup failed",
					"vpnIP", current.VpnIP, "err", err)
				incCounter(metricCoordFetchFailed)
			}
			iter++
			c.mu.Lock()
			if iter >= pendingReplayCap {
				// Bail out without consuming the pending slot; the
				// next Notify will pick it up via the entry path. This
				// caps how long a single goroutine can be pinned by
				// gossip churn (e.g. a compromised lighthouse). Leaving
				// pending[key] in place is intentional: dropping it
				// would lose the latest gossiped port/fingerprint, and
				// the next Notify is guaranteed to either arrive (live
				// gossip path) or be triggered by the operator's next
				// handshake. inflight[key] must be cleared so the next
				// Notify is not silently deduped.
				delete(c.inflight, key)
				_, hadPending := c.pending[key]
				c.mu.Unlock()
				if hadPending {
					c.logger.Warn("rosenpass pending replay cap hit; deferring to next Notify",
						"key", key, "iterations", iter)
					incCounter(metricCoordReplayCapHit)
				}
				return
			}
			next, hasNext := c.pending[key]
			if hasNext {
				delete(c.pending, key)
				c.mu.Unlock()
				current = next
				continue
			}
			delete(c.inflight, key)
			c.mu.Unlock()
			return
		}
	}()
}

// Forget removes a peer registration from the embedded Service.
// nebula calls this on peer removal events.
//
// There is no in-flight cancellation: if a fetch is racing this call,
// it may complete and re-register the peer. That's harmless — the
// next Forget (or normal teardown) cleans up, and absent a follow-up
// Notify, the dangling registration never derives a PSK because the
// peer side never observes our re-registration. The previous
// generation-counter machinery existed to block this race in tests
// that no longer have an analogue in production.
func (c *Coordinator) Forget(peerStaticPubKey []byte) {
	if len(peerStaticPubKey) == 0 {
		return
	}
	c.cfg.Service.RemovePeer(peerStaticPubKey)
}

func (c *Coordinator) fetchAndRegister(ctx context.Context, ev rphttp.PeerObserved, key string) error {
	// Cert-v2's rosenpassPubKeySha256 extension is the sole trust
	// binding for the peer's Rosenpass identity since Simp 3. A peer
	// whose cert lacks the extension cannot be PQ-validated: refuse
	// to register so they fall through to non-PQ (IXPSK0) instead of
	// being silently trusted.
	if ev.ExpectedPubkeyHash == "" {
		return fmt.Errorf("peer cert lacks rosenpassPubKeySha256 extension; rotate cert through CA to enable PQ")
	}

	// Prefer the peer's gossiped rosenpass-discovery TCP port (if
	// any) so the HTTP pubkey fetch hits the port the peer actually
	// serves on; fall back to our own cfg.DiscoveryPort. Same
	// fallback semantics as the RosenpassPort handling below, just
	// for the TCP side of the heterogeneous-port story.
	discPort := c.cfg.DiscoveryPort
	if ev.DiscoveryPort != 0 {
		discPort = int(ev.DiscoveryPort)
	}
	discAddr := &net.TCPAddr{
		IP:   addrToIP(ev.VpnIP),
		Port: discPort,
	}
	// Prefer the peer's gossiped rosenpass UDP port (if any) so
	// heterogeneous-port deployments work — every node may
	// legitimately run with its own cfg.RosenpassPort. Fall back to
	// our local cfg port when the peer hasn't gossiped one yet
	// (pre-gossip binary, or first contact before any HostUpdate has
	// arrived). The fallback preserves pre-fix behaviour for
	// homogeneous fleets.
	rpPort := c.cfg.RosenpassPort
	if ev.RosenpassPort != 0 {
		rpPort = int(ev.RosenpassPort)
	}
	rpAddr := &net.UDPAddr{
		IP:   addrToIP(ev.VpnIP),
		Port: rpPort,
	}

	var (
		pubkey []byte
		err    error
	)
	delay := 250 * time.Millisecond
	for attempt := 0; attempt < c.cfg.FetchRetries; attempt++ {
		fetchCtx, cancel := context.WithTimeout(ctx, c.cfg.FetchTimeout)
		pubkey, err = c.cfg.Fetcher(fetchCtx, discAddr, ev.ExpectedPubkeyHash, c.cfg.Dialer)
		cancel()
		if err == nil {
			break
		}
		// Hash mismatch means the data is being lied about; do not
		// retry, that won't fix it.
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

	// The fetcher already validated the body's SHA-256 against
	// ExpectedPubkeyHash; if we reach here the cert-bound hash matched.
	if err := c.cfg.Service.AddPeer(ev.PeerStaticPubKey, pubkey, rpAddr); err != nil {
		return fmt.Errorf("AddPeer: %w", err)
	}
	c.logger.Info("rosenpass peer discovered + registered",
		"vpnIP", ev.VpnIP, "nebula_pubkey", key,
		"rp_pubkey_size", len(pubkey))
	return nil
}

// addrToIP converts a netip.Addr to net.IP. Used because go-rosenpass
// and net.TCPAddr/net.UDPAddr still take net.IP.
func addrToIP(a netip.Addr) net.IP {
	if a.Is4() {
		b := a.As4()
		return net.IP(b[:])
	}
	b := a.As16()
	return net.IP(b[:])
}
