package nebula

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/pq"
	"github.com/slackhq/nebula/util"
)

// pqProviderHolder + pqPolicyHolder wrap the interface values so we
// can store them in atomic.Pointer (which doesn't accept interface
// type parameters directly). Reload mutates the pointer; readers
// load the holder and dereference. Eliminates the torn-interface
// data race that bare assignment would create.
type pqProviderHolder struct{ p pq.Provider }
type pqPolicyHolder struct{ p pq.Policy }

type PKI struct {
	cs     atomic.Pointer[CertState]
	caPool atomic.Pointer[cert.CAPool]
	l      *slog.Logger

	// pqMemory is the in-process PSK sink. Always created (even when
	// no on-disk PQ material is configured) so an embedded PQ-PSK
	// provider can deposit derived PSKs without the PKI having to
	// know whether it'll ever exist. Layered into pqProvider via
	// pq.Compose so Lookup transparently sees both file-based +
	// embedded-derived PSKs.
	pqMemory *pq.MemoryProvider

	// pqProvider is the live PQ PSK source visible to the rest of
	// nebula: a Compose of pqMemory + pqSource. Replaced atomically
	// on reload. nil holder means no provider yet.
	pqProvider atomic.Pointer[pqProviderHolder]

	// pqComposed is the composed-provider wrapper that pqProvider
	// holds, kept separately so reload can Close only this wrapper
	// (stopping its single run goroutine) without cascading to the
	// long-lived MemoryProvider underneath. nil before first reload.
	pqComposed pq.Provider

	// pqSource is the filesystem-/static-backed underlying provider.
	// Tracked separately so reloads can Close only the underlying
	// source without disturbing the long-lived MemoryProvider.
	// Mutated only under reloadMu; reload itself is single-threaded
	// (config callback + initial bootstrap), so this does not need
	// to be atomic — but it is read by any code that needs to close
	// the previous source on reload, which only the reload path does.
	pqSource pq.Provider

	// pqStore is the boot-path identity cache: cert + pubkey + vpn
	// addrs + groups for peers we've completed at least one IXPSK2
	// handshake with. Powers DefaultPolicy.LookupBootIdentity so a
	// fresh boot can apply per-group mode overrides before any
	// handshake completes in this process. Always non-nil after
	// NewPKIFromConfig.
	pqStore *pq.Store

	// pqPolicy is the active security policy (opportunistic /
	// required, plus per-group disabled overrides). Always non-nil
	// after the first reload; replaced atomically on subsequent
	// reloads. The opportunistic policy preserves pre-policy
	// behaviour so existing deployments are unaffected unless they
	// opt in to a stricter mode.
	pqPolicy atomic.Pointer[pqPolicyHolder]

	// pqRotate is a stable, lifetime-bound notification channel
	// that connection_manager subscribes to once at startup. The
	// forwarder goroutine multiplexes events from whichever
	// composed provider is currently installed (replaced on each
	// reload) into this channel, so consumers don't need to
	// re-subscribe after reload. Buffered + coalescing.
	pqRotate chan struct{}

	// pqRotateWake nudges the forwarder goroutine to re-pick up the
	// current composed provider's Subscribe channel after a reload
	// has installed a new one.
	pqRotateWake chan struct{}

	// pqStop is closed by Close() to stop the rotation forwarder.
	pqStop chan struct{}

	// pqForwarderDone is closed by the forwarder goroutine on exit
	// so Close can wait for the goroutine to be fully gone before
	// returning. Avoids leaks in tests + any future caller that
	// recreates a PKI in the same process address space.
	pqForwarderDone chan struct{}

	// pqGossipedBindingHashLookup, if non-nil, returns the lowercase hex
	// PQ-PSK binding hash gossiped by the peer identified by the
	// given cert. Wired up post-PKI-construction by the main bootstrap
	// (LightHouse provides the per-peer table). Atomic so the binding
	// wrapper closure can read it without holding any PKI lock, and so
	// it can be cleared if the LightHouse ever goes away in a test.
	pqGossipedBindingHashLookup atomic.Pointer[GossipedPQBindingHashLookupFunc]

	// pqGossipedProviderPortLookup, if non-nil, returns the peer's most-
	// recently-gossiped provider UDP port for a given vpnAddr (or 0
	// if the peer has not gossiped a port). Wired up post-PKI-
	// construction by the main bootstrap from LightHouse.
	// LookupGossipedPQProviderPort. Consumed by the embedded PQ-PSK provider
	// to route peer endpoints at the port the peer actually listens
	// on — different from our local cfg port in heterogeneous
	// deployments. Atomic for the same reasons as
	// pqGossipedBindingHashLookup.
	pqGossipedProviderPortLookup atomic.Pointer[GossipedPQProviderPortLookupFunc]

	// pqGossipedDiscoveryPortLookup, if non-nil, returns the peer's
	// most-recently-gossiped provider discovery TCP port for a
	// given vpnAddr (or 0 if not yet gossiped). Wired up by main from
	// LightHouse.LookupGossipedDiscoveryPort. Consumed by the
	// embedded PQ-PSK provider's fetchAndRegister so the HTTP
	// pubkey fetch hits the right port in heterogeneous deployments
	// (peers running with different discovery_port values). Mirrors
	// pqGossipedProviderPortLookup exactly.
	pqGossipedDiscoveryPortLookup atomic.Pointer[GossipedDiscoveryPortLookupFunc]

	// pqGossipedBindingChangeCB, if non-nil, is invoked whenever the
	// lighthouse has just stored a fresh gossiped provider UDP port
	// for a peer (different from the prior cached value). The
	// embedded PQ-PSK build wires this to a handler that re-runs the
	// provider notify path for the peer so it can re-register it at
	// the corrected port — gossip arrival commonly races handshake
	// completion and the first registration would otherwise stay
	// pinned to the (wrong) fallback port for the lifetime of the
	// tunnel. Default build registers nothing (no-op). Atomic for the
	// same reasons as the other lookup pointers in this struct.
	pqGossipedBindingChangeCB atomic.Pointer[GossipedBindingChangeCallback]
}

// GossipedPQBindingHashLookupFunc returns the peer's most-recently-gossiped
// PQ-PSK binding hash (lowercase hex) given the peer's CA-verified
// certificate, or "" if no gossip claim has been observed.
// Implementations are expected to use the peer's primary VPN address
// (cert.Networks()[0].Addr()) to look up the LightHouse's per-peer
// RemoteList; the closure type isolates the binding wrapper from
// LightHouse internals.
type GossipedPQBindingHashLookupFunc func(peerCert cert.Certificate) string

// GossipedPQProviderPortLookupFunc returns the peer's most-recently-gossiped
// provider UDP port for vpnAddr, or 0 if no port has been gossiped.
// Implemented by LightHouse.LookupGossipedPQProviderPort and consumed by the
// embedded PQ-PSK provider (via the provider's PeerObserved event)
// to register peers at the port they actually listen on instead of
// blindly trusting our local cfg port. Indirected through a
// function type so the package boundary doesn't force every PKI
// consumer to import the LightHouse.
type GossipedPQProviderPortLookupFunc func(vpnAddr netip.Addr) uint16

// GossipedDiscoveryPortLookupFunc returns the peer's most-recently-
// gossiped provider discovery TCP port for vpnAddr, or 0 if no port
// has been gossiped. Implemented by LightHouse.
// LookupGossipedDiscoveryPort and consumed by the embedded
// provider's fetchAndRegister so the HTTP pubkey-fetch lands on
// the port the peer actually serves on. Mirrors
// GossipedPQProviderPortLookupFunc; the function-type indirection avoids
// dragging the LightHouse package across the PKI boundary.
type GossipedDiscoveryPortLookupFunc func(vpnAddr netip.Addr) uint16

// GossipedBindingChangeCallback is fired by the lighthouse on the
// HostUpdate receive path whenever a peer's gossiped provider UDP
// port just took a new value (different from the cached one).
// Invoked AFTER all lighthouse locks have been released (see
// LightHouse.SetGossipChangedCallback), so implementations may freely
// acquire other locks (HostMap, provider) without deadlock risk; the
// embedded build's handler does a HostMap query and a single
// non-blocking Notify into the provider. The vpnAddr
// is the peer identity nebula uses to key its own HostMap, so the
// handler can resolve the peer's static pubkey without re-deriving
// it from the gossip itself.
type GossipedBindingChangeCallback func(vpnAddr netip.Addr)

type CertState struct {
	v1Cert       cert.Certificate
	v1Credential *handshake.Credential

	v2Cert       cert.Certificate
	v2Credential *handshake.Credential

	initiatingVersion cert.Version
	privateKey        []byte
	pkcs11Backed      bool
	cipher            string

	// pqPSKLookup is the active per-peer (or mesh-wide) PSK lookup. nil
	// means no PSK is configured. Exposed via HasPQPSK / LookupPQPSK so
	// the handshake manager can pick between subtypes IXPSK0 / IXPSK2 at
	// initiation time.
	pqPSKLookup handshake.PSKLookupFunc
	// pqPSKLookupPrev is the previous-epoch PSK lookup. nil when no
	// rotation has been observed or the provider does not support epoch
	// retention. Exposed via LookupPQPSKPrev for epoch-skew healing.
	pqPSKLookupPrev handshake.PSKLookupFunc

	myVpnNetworks            []netip.Prefix
	myVpnNetworksTable       *bart.Lite
	myVpnAddrs               []netip.Addr
	myVpnAddrsTable          *bart.Lite
	myVpnBroadcastAddrsTable *bart.Lite
}

func NewPKIFromConfig(l *slog.Logger, c *config.C) (*PKI, error) {
	// pq.Store is process-wide and reload-stable; build it before the
	// first reloadCerts so the policy has a state target from the very
	// first handshake.
	statePath := c.GetString("pq.state_path", "")
	store, err := pq.NewStore(statePath, pq.WithLogger(l))
	if err != nil {
		return nil, fmt.Errorf("pq state: %w", err)
	}
	pki := &PKI{
		l:               l,
		pqStore:         store,
		pqMemory:        pq.NewMemoryProvider(),
		pqRotate:        make(chan struct{}, 1),
		pqRotateWake:    make(chan struct{}, 1),
		pqStop:          make(chan struct{}),
		pqForwarderDone: make(chan struct{}),
	}
	if err := pki.reload(c, true); err != nil {
		return nil, err
	}
	go func() {
		defer close(pki.pqForwarderDone)
		pki.pqRotateForwarder()
	}()

	c.RegisterReloadCallback(func(c *config.C) {
		rErr := pki.reload(c, false)
		if rErr != nil {
			util.LogWithContextIfNeeded("Failed to reload PKI from config", rErr, l)
		}
	})

	return pki, nil
}

func (p *PKI) GetCAPool() *cert.CAPool {
	return p.caPool.Load()
}

func (p *PKI) getCertState() *CertState {
	return p.cs.Load()
}

func (p *PKI) reload(c *config.C, initial bool) error {
	err := p.reloadCerts(c, initial)
	if err != nil {
		if initial {
			return err
		}
		err.Log(p.l)
	}

	err = p.reloadCAPool(c)
	if err != nil {
		if initial {
			return err
		}
		err.Log(p.l)
	}

	return nil
}

func (p *PKI) reloadCerts(c *config.C, initial bool) *util.ContextualError {
	var cipher string
	var currentState *CertState
	if initial {
		cipher = c.GetString("cipher", "aes")
		switch cipher {
		case "aes", "chachapoly":
			// Each post-handshake CipherState in noiseutil hardcodes its own
			// nonce endianness now, so there's nothing to set up here.
		default:
			return util.NewContextualError(
				"unknown cipher",
				m{"cipher": cipher},
				nil,
			)
		}
	} else {
		// Cipher cant be hot swapped so just leave it at what it was before
		currentState = p.cs.Load()
		cipher = currentState.cipher
	}

	// Build (or swap) the PQ Provider. We keep the old one alive across
	// the call to newCertStateFromConfig so any concurrent lookup mid-
	// reload still resolves; the old provider is closed only after the
	// CertState has been atomically swapped.
	newSource, err := buildPQProvider(c, p.l)
	if err != nil {
		return util.NewContextualError("Could not load PQ PSK material", nil, err)
	}
	// Always layer the in-process MemoryProvider in front so an
	// embedded PQ-PSK provider (registered after PKI construction)
	// can land PSKs without further reload. MemoryProvider takes
	// priority for any peer it knows about; falls through to the
	// file-/static-backed source for anything it doesn't.
	newProvider := pq.Compose(p.pqMemory, newSource)

	// Cert-extension binding mode. Wraps the provider lookup with a
	// PQ-PSK binding check (cert v2 extension vs per-PSK binding
	// hint). Default "warn" preserves pre-extension behaviour for
	// fleets that haven't yet re-issued certs.
	rpBindingMode, err := pq.ParsePqPskBindingMode(c.GetString("pq.psk_binding.mode", c.GetString("pq.rp_binding.mode", "")))
	if err != nil {
		return util.NewContextualError("invalid pq.psk_binding.mode", nil, err)
	}
	pqPSKLookup := pqLookupFromProviderWithBinding(newProvider, rpBindingMode, p, p.l)
	pqPSKLookupPrev := pqPrevLookupFromProviderWithBinding(newProvider, rpBindingMode, p, p.l)

	// Resolve the policy mode now so it lines up with the provider. A
	// bad mode is a config error, not a silent fallback.
	mode, err := pq.ParseMode(c.GetString("pq.mode", ""))
	if err != nil {
		return util.NewContextualError("invalid pq.mode", nil, err)
	}
	defaultPolicy := pq.NewDefaultPolicy(mode, newProvider, p.pqStore)

	// Optional per-cert-group mode overrides. Operators put their
	// stricter peers in named groups (cert.groups, CA-signed) and
	// list overrides here; everyone else falls through to pq.mode.
	groupOverrides, err := loadPQGroupOverrides(c)
	if err != nil {
		return util.NewContextualError("invalid pq.group_overrides", nil, err)
	}
	if len(groupOverrides) > 0 {
		groupOrder := c.GetStringSlice("pq.group_order", nil)
		defaultPolicy.WithOverrides(groupOverrides, groupOrder)
	}
	var newPolicy pq.Policy = defaultPolicy

	newState, err := newCertStateFromConfig(c, cipher, pqPSKLookup, pqPSKLookupPrev)
	if err != nil {
		return util.NewContextualError("Could not load client cert", nil, err)
	}

	if currentState != nil {
		if newState.v1Cert != nil {
			if currentState.v1Cert == nil {
				//adding certs is fine, actually. Networks-in-common confirmed in newCertState().
			} else {
				// did IP in cert change? if so, don't set
				if !slices.Equal(currentState.v1Cert.Networks(), newState.v1Cert.Networks()) {
					return util.NewContextualError(
						"Networks in new cert was different from old",
						m{"new_networks": newState.v1Cert.Networks(), "old_networks": currentState.v1Cert.Networks(), "cert_version": cert.Version1},
						nil,
					)
				}

				if currentState.v1Cert.Curve() != newState.v1Cert.Curve() {
					return util.NewContextualError(
						"Curve in new v1 cert was different from old",
						m{"new_curve": newState.v1Cert.Curve(), "old_curve": currentState.v1Cert.Curve(), "cert_version": cert.Version1},
						nil,
					)
				}
			}
		}

		if newState.v2Cert != nil {
			if currentState.v2Cert == nil {
				//adding certs is fine, actually
			} else {
				// did IP in cert change? if so, don't set
				if !slices.Equal(currentState.v2Cert.Networks(), newState.v2Cert.Networks()) {
					return util.NewContextualError(
						"Networks in new cert was different from old",
						m{"new_networks": newState.v2Cert.Networks(), "old_networks": currentState.v2Cert.Networks(), "cert_version": cert.Version2},
						nil,
					)
				}

				if currentState.v2Cert.Curve() != newState.v2Cert.Curve() {
					return util.NewContextualError(
						"Curve in new cert was different from old",
						m{"new_curve": newState.v2Cert.Curve(), "old_curve": currentState.v2Cert.Curve(), "cert_version": cert.Version2},
						nil,
					)
				}
			}

		} else if currentState.v2Cert != nil {
			//newState.v1Cert is non-nil bc empty certstates aren't permitted
			if newState.v1Cert == nil {
				return util.NewContextualError("v1 and v2 certs are nil, this should be impossible", nil, err)
			}
			//if we're going to v1-only, we need to make sure we didn't orphan any v2-cert vpnaddrs
			if !slices.Equal(currentState.v2Cert.Networks(), newState.v1Cert.Networks()) {
				return util.NewContextualError(
					"Removing a V2 cert is not permitted unless it has identical networks to the new V1 cert",
					m{"new_v1_networks": newState.v1Cert.Networks(), "old_v2_networks": currentState.v2Cert.Networks()},
					nil,
				)
			}
		}
	}

	p.cs.Store(newState)

	// Swap PQ provider + policy.
	//
	// Three resources to manage on reload:
	//   1. The composed wrapper itself (newProvider) — owns a single
	//      reflect.Select run goroutine (see composedProvider.run).
	//      Old wrapper must be Closed or we leak that goroutine per
	//      reload.
	//   2. The underlying source (file/static provider). Old source
	//      must be Closed (releases fsnotify watcher etc.).
	//   3. The long-lived MemoryProvider — never Closed on reload.
	//
	// composedProvider.Close() (post-fix) does NOT cascade to the
	// layers, so closing the old composed wrapper is safe even
	// though it referenced the still-live pqMemory.
	//
	// After the swap, wake the rotation forwarder so it switches
	// to the new composed's Subscribe channel — without this,
	// connection_manager would keep listening on the old (closed)
	// channel and miss every rotation event for the rest of the
	// process lifetime.
	oldComposed := p.pqComposed
	oldSource := p.pqSource
	p.pqProvider.Store(&pqProviderHolder{p: newProvider})
	p.pqComposed = newProvider
	p.pqSource = newSource
	p.pqPolicy.Store(&pqPolicyHolder{p: newPolicy})
	// Close the old composed wrapper FIRST, so the forwarder sees
	// the old Subscribe channel close before observing the wake
	// signal. The opposite ordering — wake then close — has a
	// narrow window where the forwarder consumes the wake (loops),
	// re-loads pqProvider (now the new one) and re-Subscribes to
	// the new composed; meanwhile the old composed's Close fires,
	// closing the old notify channel nobody is reading. That's
	// harmless on its own — composedProvider.Close stops its single
	// run goroutine via the stop/done handshake before closing
	// notify, so there is never a concurrent sender on a closed
	// channel — but closing before signalling keeps the forwarder's
	// view of the lifecycle linear (old channel closed, then wake).
	if oldComposed != nil && oldComposed != newProvider {
		_ = oldComposed.Close()
	}
	if oldSource != nil && oldSource != newSource {
		_ = oldSource.Close()
	}
	select {
	case p.pqRotateWake <- struct{}{}:
	default:
	}

	if initial {
		p.l.Debug("Client nebula certificate(s)", "cert", newState)
	} else {
		p.l.Info("Client certificate(s) refreshed from disk", "cert", newState)
	}
	return nil
}

// PQRotation returns a stable, lifetime-bound channel that fires
// whenever PQ PSK material may have changed. Subscribers register
// once at startup and continue to receive events across config
// reloads — the underlying composed provider is replaced on each
// reload, but this channel is constant. Buffered with size 1;
// notifications coalesce.
func (p *PKI) PQRotation() <-chan struct{} {
	return p.pqRotate
}

// pqRotateForwarder multiplexes Subscribe events from whichever
// composed provider is currently installed into the stable
// pqRotate channel. On reload, the reload code wakes us via
// pqRotateWake so we re-pick up the new provider's Subscribe.
func (p *PKI) pqRotateForwarder() {
	for {
		// Pick up the current source channel under fresh load —
		// the holder pointer is swapped on reload.
		var sub <-chan struct{}
		if h := p.pqProvider.Load(); h != nil && h.p != nil {
			sub = h.p.Subscribe()
		}
		select {
		case <-p.pqStop:
			return
		case <-p.pqRotateWake:
			// Reload happened; loop to re-pick up the new sub.
			continue
		case _, ok := <-sub:
			if !ok {
				// sub channel closed (provider shutting down);
				// wait for the wake to arrive with a fresh one,
				// or for stop. Avoid a tight loop.
				select {
				case <-p.pqStop:
					return
				case <-p.pqRotateWake:
					continue
				}
			}
			select {
			case p.pqRotate <- struct{}{}:
			default:
			}
		}
	}
}

// Close stops the PKI's background goroutines. Safe to call more than
// once; blocks until the forwarder has exited and the composed PQ
// provider's single run goroutine has exited so callers don't observe
// dangling goroutines after Close returns.
//
// Lifecycle ordering:
//  1. Signal the rotation forwarder via pqStop and wait for its
//     pqForwarderDone signal — otherwise the forwarder could still be
//     selecting on the composed provider's Subscribe channel when we
//     close it below.
//  2. Close the composed wrapper. composedProvider.Close (guarded by
//     sync.Once) signals its single reflect.Select run goroutine via
//     the stop channel and blocks on the done channel until that
//     goroutine has returned, then closes the notify channel. Safe to
//     call even though pqMemory remains live; composedProvider.Close is
//     deliberately non-cascading.
//  3. Close the underlying source (releases fsnotify watcher etc.).
//
// pqMemory is intentionally NOT closed here: it is process-lifetime
// and has no background goroutines of its own.
func (p *PKI) Close() {
	if p == nil {
		return
	}
	select {
	case <-p.pqStop:
		// already closed; still wait for forwarder
	default:
		close(p.pqStop)
	}
	<-p.pqForwarderDone

	// Stop the composed provider's single run goroutine (Close blocks
	// on its stop/done handshake). Read pqComposed
	// after the forwarder has exited so we don't race with the reload
	// path (which is the only writer); by Close-time the config
	// reload callback is unreachable.
	if p.pqComposed != nil {
		_ = p.pqComposed.Close()
		p.pqComposed = nil
	}
	if p.pqSource != nil {
		_ = p.pqSource.Close()
		p.pqSource = nil
	}
}

// PQProvider returns the active PQ PSK provider for this PKI. Used by
// the connection manager to subscribe to rotation events. Never nil
// after NewPKIFromConfig succeeds; returns NoProvider{} if no PQ
// material is configured.
func (p *PKI) PQProvider() pq.Provider {
	h := p.pqProvider.Load()
	if h == nil || h.p == nil {
		return pq.NoProvider{}
	}
	return h.p
}

// PQMemory returns the in-process MemoryProvider used as the sink
// for any embedded post-quantum daemon. Always non-nil after
// NewPKIFromConfig.
func (p *PKI) PQMemory() *pq.MemoryProvider {
	return p.pqMemory
}

// PQStore returns the boot-path identity cache. Used internally by
// DefaultPolicy to resolve a peer's cached cert + group claims when
// the initiator boots before any handshake has completed in this
// process. Always non-nil after NewPKIFromConfig.
func (p *PKI) PQStore() *pq.Store {
	return p.pqStore
}

// PQPolicy returns the active PQ security policy. Always non-nil after
// NewPKIFromConfig: defaults to opportunistic mode, matching pre-policy
// behaviour for deployments that haven't set pq.mode.
func (p *PKI) PQPolicy() pq.Policy {
	h := p.pqPolicy.Load()
	if h == nil || h.p == nil {
		// Construct an opportunistic fallback the same way reloadCerts
		// would. This branch only fires before the first successful
		// reload, which only matters in tests that bypass the normal
		// constructor.
		return pq.NewDefaultPolicy(pq.ModeOpportunistic, p.PQProvider(), p.pqStore)
	}
	return h.p
}

func (p *PKI) reloadCAPool(c *config.C) *util.ContextualError {
	caPool, err := loadCAPoolFromConfig(p.l, c)
	if err != nil {
		return util.NewContextualError("Failed to load ca from config", nil, err)
	}

	p.caPool.Store(caPool)
	p.l.Debug("Trusted CA fingerprints", "fingerprints", caPool.GetFingerprints())
	return nil
}

func (cs *CertState) GetDefaultCertificate() cert.Certificate {
	c := cs.getCertificate(cs.initiatingVersion)
	if c == nil {
		panic("No default certificate found")
	}
	return c
}

// DefaultVersion returns the preferred cert version for initiating handshakes.
func (cs *CertState) DefaultVersion() cert.Version { return cs.initiatingVersion }

// GetCredential returns the pre-computed handshake credential for the given version, or nil.
func (cs *CertState) GetCredential(v cert.Version) *handshake.Credential {
	switch v {
	case cert.Version1:
		return cs.v1Credential
	case cert.Version2:
		return cs.v2Credential
	}
	return nil
}

// HasPQPSK reports whether any PQ PSK material is configured. Used by the
// handshake manager to decide whether to ever attempt subtype IXPSK2.
func (cs *CertState) HasPQPSK() bool {
	return cs.pqPSKLookup != nil
}

// LookupPQPSK returns the PSK bytes (or nil) for the given peer's static
// public key. Exposed for the initiator path: the manager uses this at
// rekey time (after a blind subtype-0 handshake has provided the peer's
// cert) to decide whether the next handshake can upgrade to subtype 2.
//
// peerCert is the verified peer cert (when available) so the underlying
// lookup can run PQ-PSK binding checks before returning the PSK. Pass
// nil if no cert is in hand; binding mode "warn" then falls through to
// "no claim to verify" semantics. Under "enforce" mode, a nil cert +
// present binding hint also returns the PSK (the cert is what would
// trigger refusal, and there isn't one).
func (cs *CertState) LookupPQPSK(peerStaticPubKey []byte, peerCert cert.Certificate) []byte {
	if cs.pqPSKLookup == nil {
		return nil
	}
	return cs.pqPSKLookup(peerStaticPubKey, peerCert)
}

// LookupPQPSKPrev resolves the previous-epoch PSK for a peer, or nil.
// Used by the handshake manager's epoch-skew healing.
func (cs *CertState) LookupPQPSKPrev(peerStaticPubKey []byte, peerCert cert.Certificate) []byte {
	if cs.pqPSKLookupPrev == nil {
		return nil
	}
	return cs.pqPSKLookupPrev(peerStaticPubKey, peerCert)
}

func (cs *CertState) getCertificate(v cert.Version) cert.Certificate {
	switch v {
	case cert.Version1:
		return cs.v1Cert
	case cert.Version2:
		return cs.v2Cert
	}

	return nil
}

func newCipherSuite(curve cert.Curve, pkcs11backed bool, cipher string) (noise.CipherSuite, error) {
	var dhFunc noise.DHFunc
	switch curve {
	case cert.Curve_CURVE25519:
		dhFunc = noise.DH25519
	case cert.Curve_P256:
		if pkcs11backed {
			dhFunc = noiseutil.DHP256PKCS11
		} else {
			dhFunc = noiseutil.DHP256
		}
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	if cipher == "chachapoly" {
		return noise.NewCipherSuite(dhFunc, noise.CipherChaChaPoly, noise.HashSHA256), nil
	}
	return noise.NewCipherSuite(dhFunc, noiseutil.CipherAESGCM, noise.HashSHA256), nil
}

func (cs *CertState) String() string {
	b, err := cs.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("error marshaling certificate state: %v", err)
	}
	return string(b)
}

func (cs *CertState) MarshalJSON() ([]byte, error) {
	msg := []json.RawMessage{}
	if cs.v1Cert != nil {
		b, err := cs.v1Cert.MarshalJSON()
		if err != nil {
			return nil, err
		}
		msg = append(msg, b)
	}

	if cs.v2Cert != nil {
		b, err := cs.v2Cert.MarshalJSON()
		if err != nil {
			return nil, err
		}
		msg = append(msg, b)
	}

	return json.Marshal(msg)
}

// buildPQProvider constructs the active PQ Provider from config. The
// two config knobs are mutually exclusive:
//
//   - pki.pq_psk_path: legacy mesh-wide PSK. Backed by pq.StaticProvider.
//   - pki.pq_psk_dir:  per-peer PSKs in a directory. Backed by
//     pq.FileProvider, which auto-rotates via fsnotify.
//
// pki.pq_psk_stale_warn (duration, default off) arms the FileProvider's
// staleness warning: if the directory content stops changing for that
// long while PSKs are loaded, the provider logs a Warn — the
// nebula-side signal that a rotating sidecar died while its last files
// still look healthy on disk. Leave unset for statically-provisioned
// directories that never rotate.
//
// Returns pq.NoProvider{} if neither knob is set so handshake behaviour
// matches upstream nebula. Caller owns Close on the returned Provider.
func buildPQProvider(c *config.C, l *slog.Logger) (pq.Provider, error) {
	path := c.GetString("pki.pq_psk_path", "")
	dir := c.GetString("pki.pq_psk_dir", "")
	if path != "" && dir != "" {
		return nil, errors.New("pki.pq_psk_path and pki.pq_psk_dir are mutually exclusive")
	}
	switch {
	case path != "":
		return pq.NewStaticProviderFromFile(path)
	case dir != "":
		p, err := pq.NewFileProviderWithConfig(pq.FileProviderConfig{
			Dir:            dir,
			Logger:         l,
			StaleWarnAfter: c.GetDuration("pki.pq_psk_stale_warn", 0),
		})
		if err != nil {
			return nil, err
		}
		// Advisory only: PSK files on persistent media survive disk
		// imaging, which re-opens the harvest-now-decrypt-later window
		// the PQ PSKs exist to close. tmpfs is the recommended home.
		if volatile, ok := pq.DirIsVolatile(dir); ok && !volatile {
			l.Info("pki.pq_psk_dir is not on tmpfs/ramfs; PSK material will survive power-off. Consider a tmpfs mount — see the operator guide's disk-hygiene section",
				"dir", dir)
		}
		return p, nil
	}
	return pq.NoProvider{}, nil
}

// loadPQGroupOverrides parses the pq.group_overrides config block.
// The expected schema is a YAML map of cert-group-name -> mode-string,
// where mode is one of opportunistic | required | disabled.
//
//	pq:
//	  group_overrides:
//	    lighthouses: required
//	    legacy:      disabled
//
// Returns an empty map when the block is absent so the caller can
// short-circuit to plain DefaultPolicy without wrapping.
func loadPQGroupOverrides(c *config.C) (map[string]pq.Mode, error) {
	raw := c.Get("pq.group_overrides")
	if raw == nil {
		return nil, nil
	}
	asMap, ok := raw.(map[string]any)
	if !ok {
		// Some YAML parsers return map[interface{}]interface{}; coerce.
		alt, ok2 := raw.(map[any]any)
		if !ok2 {
			return nil, fmt.Errorf("pq.group_overrides must be a map of group->mode")
		}
		asMap = make(map[string]any, len(alt))
		for k, v := range alt {
			ks, _ := k.(string)
			asMap[ks] = v
		}
	}
	out := make(map[string]pq.Mode, len(asMap))
	for group, val := range asMap {
		modeStr, _ := val.(string)
		m, err := pq.ParseGroupMode(modeStr)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", group, err)
		}
		out[group] = m
	}
	return out, nil
}

// SetGossipedPQBindingHashLookup wires a gossiped-hash resolver into the PSK
// binding wrapper. Called from the main bootstrap once the LightHouse
// exists (it's the source of the per-peer gossip table) and PKI is
// already constructed. Passing nil clears the resolver — useful in
// tests that want to disable gossip-source trust without rebuilding the
// PKI. Subsequent calls atomically replace the prior resolver.
func (p *PKI) SetGossipedPQBindingHashLookup(fn GossipedPQBindingHashLookupFunc) {
	if fn == nil {
		p.pqGossipedBindingHashLookup.Store(nil)
		return
	}
	p.pqGossipedBindingHashLookup.Store(&fn)
}

// gossipedBindingHashFor returns the peer's gossiped PQ-PSK binding hash,
// or "" if no resolver is wired up / the peer has not been observed
// gossiping a claim. Safe to call before SetGossipedPQBindingHashLookup has
// fired (e.g. during early-boot handshakes before the LightHouse
// finishes constructing) — those handshakes simply fall through to
// "no gossip claim observed", same as if the peer were an old binary.
func (p *PKI) gossipedBindingHashFor(peerCert cert.Certificate) string {
	fnPtr := p.pqGossipedBindingHashLookup.Load()
	if fnPtr == nil {
		return ""
	}
	return (*fnPtr)(peerCert)
}

// SetGossipedPQProviderPortLookup wires the gossiped-provider-port resolver
// (LightHouse.LookupGossipedPQProviderPort, in production) into the PKI so
// downstream code — currently just the embedded PQ-PSK provider
// notify path — can resolve a peer's most-recently-gossiped UDP port
// without taking a dependency on the LightHouse package. Passing nil
// clears the resolver. Mirrors SetGossipedPQBindingHashLookup's lifecycle:
// wired up from main after PKI + LightHouse are both constructed; safe
// to call before/after any handshake.
func (p *PKI) SetGossipedPQProviderPortLookup(fn GossipedPQProviderPortLookupFunc) {
	if fn == nil {
		p.pqGossipedProviderPortLookup.Store(nil)
		return
	}
	p.pqGossipedProviderPortLookup.Store(&fn)
}

// GossipedPQProviderPortFor returns the peer's gossiped provider UDP port for
// vpnAddr, or 0 if no resolver is wired up / no port has been gossiped
// (e.g. peer is an older binary that doesn't emit the field, or has
// not yet sent a HostUpdate). Safe to call before
// SetGossipedPQProviderPortLookup has fired — the embedded PQ-PSK notify
// path treats 0 as "fall back to the local provider port", preserving
// pre-gossip behaviour for legacy peers.
//
// Exported (capital G) because the consumer lives in a
// build-tag-gated provider notify file and needs to reach across the
// package's API surface; the symmetric hash lookup stays unexported
// because its only consumer is in this same file.
func (p *PKI) GossipedPQProviderPortFor(vpnAddr netip.Addr) uint16 {
	fnPtr := p.pqGossipedProviderPortLookup.Load()
	if fnPtr == nil {
		return 0
	}
	return (*fnPtr)(vpnAddr)
}

// SetGossipedDiscoveryPortLookup wires the gossiped-provider-
// discovery-port resolver (LightHouse.LookupGossipedDiscoveryPort, in
// production) into the PKI so the embedded PQ-PSK provider's
// notify path can resolve a peer's most-recently-gossiped TCP port
// without depending on the LightHouse package. Passing nil clears
// the resolver. Mirrors SetGossipedPQProviderPortLookup's lifecycle.
func (p *PKI) SetGossipedDiscoveryPortLookup(fn GossipedDiscoveryPortLookupFunc) {
	if fn == nil {
		p.pqGossipedDiscoveryPortLookup.Store(nil)
		return
	}
	p.pqGossipedDiscoveryPortLookup.Store(&fn)
}

// GossipedDiscoveryPortFor returns the peer's gossiped provider
// discovery TCP port for vpnAddr, or 0 if no resolver is wired up /
// no port has been gossiped. 0 means "fall back to the local
// discovery port" in the provider, preserving pre-gossip behaviour
// for legacy peers / homogeneous fleets.
//
// Exported for the same reason as GossipedPQProviderPortFor: the consumer
// lives in a build-tag-gated provider notify file and reaches across
// the package's API surface.
func (p *PKI) GossipedDiscoveryPortFor(vpnAddr netip.Addr) uint16 {
	fnPtr := p.pqGossipedDiscoveryPortLookup.Load()
	if fnPtr == nil {
		return 0
	}
	return (*fnPtr)(vpnAddr)
}

// SetGossipedBindingChangeCallback installs a callback fired by the
// lighthouse whenever a peer's gossiped provider routing info just
// changed (new UDP port arrived for an already-cached peer). The
// embedded PQ-PSK build wires this from main() to a handler that
// re-runs the provider notify path for the affected peer; the default
// build leaves it unset (the no-op stub handler keeps the wire-up site
// build-tag agnostic). Passing nil clears any installed callback.
// Atomic store mirrors the other gossip-resolver setters.
func (p *PKI) SetGossipedBindingChangeCallback(cb GossipedBindingChangeCallback) {
	if cb == nil {
		p.pqGossipedBindingChangeCB.Store(nil)
		return
	}
	p.pqGossipedBindingChangeCB.Store(&cb)
}

// GossipedBindingChanged dispatches the most recent gossip-change
// notification to the installed callback (if any). Invoked by the
// lighthouse receive path under its own lock, so the callback must
// not block / acquire the lighthouse lock recursively. No-op when no
// callback has been installed (e.g. default build, or unit tests
// that don't exercise the embedded provider).
func (p *PKI) GossipedBindingChanged(vpnAddr netip.Addr) {
	if p == nil {
		return
	}
	cbPtr := p.pqGossipedBindingChangeCB.Load()
	if cbPtr == nil {
		return
	}
	(*cbPtr)(vpnAddr)
}

// pqLookupFromProviderWithBinding wraps the provider's PSK lookup with
// the PQ-PSK cert-extension binding check. The returned closure is nil
// only when no Provider is configured at all (nil or NoProvider); any
// real Provider gets the closure installed even if it happens to be
// empty at construction time, so PSKs that arrive at runtime —
// sidecar-derived FileProvider drop-ins, embedded-provider
// MemoryProvider Set — are visible to the handshake without a config
// reload. Inside the closure:
//
//  1. Calls Provider.LookupWithBinding for the PSK and its local origin
//     claim (rpHash) together; returns nil if no PSK. Resolving both
//     from the same provider layer is what prevents a composedProvider
//     from pairing one layer's PSK with another layer's rpHash.
//  2. If a gossipedBindingHashLookup is wired up, fetches the peer's
//     gossiped hash (or "" on first contact).
//  3. Hands all three sources, plus the (optional) peer cert, to
//     ValidatePSKBindingInputs to decide whether the PSK should be
//     used.
//
// The check is no-op'd when mode == PqPskBindingOff so operators who
// opt out pay no per-handshake cert-hash cost.
//
// pki may be nil in unit tests that don't have a full PKI wired up;
// the wrapper degrades to no-gossip semantics in that case. logger
// may be nil; the wrapper handles that case.
func pqLookupFromProviderWithBinding(p pq.Provider, mode pq.PqPskBindingMode, pki *PKI, logger *slog.Logger) handshake.PSKLookupFunc {
	if p == nil {
		return nil
	}
	if _, ok := p.(pq.NoProvider); ok {
		// No provider at all — leave pqPSKLookup nil so callers
		// (CertState.HasPQPSK, handshake credential) skip the PSK
		// plumbing path entirely. Any other Provider — including a
		// composedProvider whose layers are all empty right now —
		// gets the closure installed; PSKs that arrive at runtime
		// then resolve through the same closure with no reload.
		return nil
	}
	return func(peerStaticPubKey []byte, peerCert cert.Certificate) []byte {
		// LookupWithBinding resolves the PSK and its origin hash from
		// the SAME provider layer atomically. Calling Lookup +
		// LookupRPHash separately against a composedProvider could pair
		// one layer's live PSK with another layer's unrelated rpHash,
		// which under PqPskBindingEnforce can blackout a good PSK.
		psk, rpHash, ok := p.LookupWithBinding(peerStaticPubKey)
		if !ok {
			return nil
		}
		if mode == pq.PqPskBindingOff {
			return psk
		}
		var gossiped string
		if pki != nil && peerCert != nil {
			gossiped = pki.gossipedBindingHashFor(peerCert)
		}
		in := pq.BindingInputs{
			CertHash:          certHashHex(peerCert),
			GossipedHash:      gossiped,
			LocalProviderHash: rpHash,
		}
		if !pq.ValidatePSKBindingInputs(mode, in, logger) {
			return nil
		}
		return psk
	}
}

// pqPrevLookupFromProviderWithBinding is the previous-epoch
// counterpart of pqLookupFromProviderWithBinding: same binding
// validation, but the PSK and rpHash come from the provider's
// retained previous epoch. Used only by the epoch-skew healing paths;
// returns nil whenever no rotation has been observed for the peer.
func pqPrevLookupFromProviderWithBinding(p pq.Provider, mode pq.PqPskBindingMode, pki *PKI, logger *slog.Logger) handshake.PSKLookupFunc {
	if p == nil {
		return nil
	}
	if _, ok := p.(pq.NoProvider); ok {
		return nil
	}
	return func(peerStaticPubKey []byte, peerCert cert.Certificate) []byte {
		psk, rpHash, ok := pq.LookupPrevious(p, peerStaticPubKey)
		if !ok {
			return nil
		}
		if mode == pq.PqPskBindingOff {
			return psk
		}
		var gossiped string
		if pki != nil && peerCert != nil {
			gossiped = pki.gossipedBindingHashFor(peerCert)
		}
		in := pq.BindingInputs{
			CertHash:          certHashHex(peerCert),
			GossipedHash:      gossiped,
			LocalProviderHash: rpHash,
		}
		if !pq.ValidatePSKBindingInputs(mode, in, logger) {
			return nil
		}
		return psk
	}
}

// certHashHex is the nebula-package mirror of pq.certHashHex; defined
// here so the binding-wrapper closure doesn't have to round-trip
// through an exported pq helper. cert v1 / v2-without-extension /
// nil all collapse to "".
func certHashHex(c cert.Certificate) string {
	if c == nil {
		return ""
	}
	h := c.PqPskBinding()
	if len(h) != cert.PqPskBindingLen {
		return ""
	}
	return hex.EncodeToString(h)
}

func newCertStateFromConfig(c *config.C, cipher string, pqPSKLookup, pqPSKLookupPrev handshake.PSKLookupFunc) (*CertState, error) {
	var err error

	privPathOrPEM := c.GetString("pki.key", "")
	if privPathOrPEM == "" {
		return nil, errors.New("no pki.key path or PEM data provided")
	}

	rawKey, curve, isPkcs11, err := loadPrivateKey(privPathOrPEM)
	if err != nil {
		return nil, err
	}

	var rawCert []byte

	pubPathOrPEM := c.GetString("pki.cert", "")
	if pubPathOrPEM == "" {
		return nil, errors.New("no pki.cert path or PEM data provided")
	}

	if strings.Contains(pubPathOrPEM, "-----BEGIN") {
		rawCert = []byte(pubPathOrPEM)
		pubPathOrPEM = "<inline>"

	} else {
		rawCert, err = os.ReadFile(pubPathOrPEM)
		if err != nil {
			return nil, fmt.Errorf("unable to read pki.cert file %s: %s", pubPathOrPEM, err)
		}
	}

	var crt, v1, v2 cert.Certificate
	for {
		// Load the certificate
		crt, rawCert, err = loadCertificate(rawCert)
		if err != nil {
			return nil, err
		}

		switch crt.Version() {
		case cert.Version1:
			if v1 != nil {
				return nil, fmt.Errorf("v1 certificate already found in pki.cert")
			}
			v1 = crt
		case cert.Version2:
			if v2 != nil {
				return nil, fmt.Errorf("v2 certificate already found in pki.cert")
			}
			v2 = crt
		default:
			return nil, fmt.Errorf("unknown certificate version %v", crt.Version())
		}

		if len(rawCert) == 0 || strings.TrimSpace(string(rawCert)) == "" {
			break
		}
	}

	if v1 == nil && v2 == nil {
		return nil, errors.New("no certificates found in pki.cert")
	}

	useInitiatingVersion := uint32(1)
	if v1 == nil {
		// The only condition that requires v2 as the default is if only a v2 certificate is present
		// We do this to avoid having to configure it specifically in the config file
		useInitiatingVersion = 2
	}

	rawInitiatingVersion := c.GetUint32("pki.initiating_version", useInitiatingVersion)
	var initiatingVersion cert.Version
	switch rawInitiatingVersion {
	case 1:
		if v1 == nil {
			return nil, fmt.Errorf("can not use pki.initiating_version 1 without a v1 certificate in pki.cert")
		}
		initiatingVersion = cert.Version1
	case 2:
		initiatingVersion = cert.Version2
	default:
		return nil, fmt.Errorf("unknown pki.initiating_version: %v", rawInitiatingVersion)
	}

	return newCertState(initiatingVersion, v1, v2, isPkcs11, curve, rawKey, cipher, pqPSKLookup, pqPSKLookupPrev)
}

func newCertState(dv cert.Version, v1, v2 cert.Certificate, pkcs11backed bool, privateKeyCurve cert.Curve, privateKey []byte, cipher string, pqPSKLookup, pqPSKLookupPrev handshake.PSKLookupFunc) (*CertState, error) {
	cs := CertState{
		privateKey:               privateKey,
		pkcs11Backed:             pkcs11backed,
		cipher:                   cipher,
		pqPSKLookup:              pqPSKLookup,
		pqPSKLookupPrev:          pqPSKLookupPrev,
		myVpnNetworksTable:       new(bart.Lite),
		myVpnAddrsTable:          new(bart.Lite),
		myVpnBroadcastAddrsTable: new(bart.Lite),
	}

	if v1 != nil && v2 != nil {
		if !slices.Equal(v1.PublicKey(), v2.PublicKey()) {
			return nil, util.NewContextualError("v1 and v2 public keys are not the same, ignoring", nil, nil)
		}

		if v1.Curve() != v2.Curve() {
			return nil, util.NewContextualError("v1 and v2 curve are not the same, ignoring", nil, nil)
		}

		if v1.Networks()[0] != v2.Networks()[0] {
			return nil, util.NewContextualError("v1 and v2 networks are not the same", nil, nil)
		}

		cs.initiatingVersion = dv
	}

	if v1 != nil {
		if pkcs11backed {
			//NOTE: We do not currently have a method to verify a public private key pair when the private key is in an hsm
		} else {
			if err := v1.VerifyPrivateKey(privateKeyCurve, privateKey); err != nil {
				return nil, fmt.Errorf("private key is not a pair with public key in nebula cert")
			}
		}

		v1hs, err := v1.MarshalForHandshakes()
		if err != nil {
			return nil, fmt.Errorf("error marshalling v1 certificate for handshake: %w", err)
		}
		ncs, err := newCipherSuite(v1.Curve(), pkcs11backed, cipher)
		if err != nil {
			return nil, err
		}
		cs.v1Cert = v1
		cs.v1Credential = handshake.NewCredential(v1, v1hs, privateKey, ncs, pqPSKLookup)
		cs.v1Credential.SetPSKLookupPrev(pqPSKLookupPrev)

		if cs.initiatingVersion == 0 {
			cs.initiatingVersion = cert.Version1
		}
	}

	if v2 != nil {
		if pkcs11backed {
			//NOTE: We do not currently have a method to verify a public private key pair when the private key is in an hsm
		} else {
			if err := v2.VerifyPrivateKey(privateKeyCurve, privateKey); err != nil {
				return nil, fmt.Errorf("private key is not a pair with public key in nebula cert")
			}
		}

		v2hs, err := v2.MarshalForHandshakes()
		if err != nil {
			return nil, fmt.Errorf("error marshalling v2 certificate for handshake: %w", err)
		}
		ncs, err := newCipherSuite(v2.Curve(), pkcs11backed, cipher)
		if err != nil {
			return nil, err
		}
		cs.v2Cert = v2
		cs.v2Credential = handshake.NewCredential(v2, v2hs, privateKey, ncs, pqPSKLookup)
		cs.v2Credential.SetPSKLookupPrev(pqPSKLookupPrev)

		if cs.initiatingVersion == 0 {
			cs.initiatingVersion = cert.Version2
		}
	}

	var crt cert.Certificate
	crt = cs.getCertificate(cert.Version2)
	if crt == nil {
		// v2 certificates are a superset, only look at v1 if its all we have
		crt = cs.getCertificate(cert.Version1)
	}

	for _, network := range crt.Networks() {
		cs.myVpnNetworks = append(cs.myVpnNetworks, network)
		cs.myVpnNetworksTable.Insert(network)

		cs.myVpnAddrs = append(cs.myVpnAddrs, network.Addr())
		cs.myVpnAddrsTable.Insert(netip.PrefixFrom(network.Addr(), network.Addr().BitLen()))

		if network.Addr().Is4() {
			addr := network.Masked().Addr().As4()
			mask := net.CIDRMask(network.Bits(), network.Addr().BitLen())
			binary.BigEndian.PutUint32(addr[:], binary.BigEndian.Uint32(addr[:])|^binary.BigEndian.Uint32(mask))
			cs.myVpnBroadcastAddrsTable.Insert(netip.PrefixFrom(netip.AddrFrom4(addr), network.Addr().BitLen()))
		}
	}

	return &cs, nil
}

func loadPrivateKey(privPathOrPEM string) (rawKey []byte, curve cert.Curve, isPkcs11 bool, err error) {
	var pemPrivateKey []byte
	if strings.Contains(privPathOrPEM, "-----BEGIN") {
		pemPrivateKey = []byte(privPathOrPEM)
		privPathOrPEM = "<inline>"
		rawKey, _, curve, err = cert.UnmarshalPrivateKeyFromPEM(pemPrivateKey)
		if err != nil {
			return nil, curve, false, fmt.Errorf("error while unmarshaling pki.key %s: %s", privPathOrPEM, err)
		}
	} else if strings.HasPrefix(privPathOrPEM, "pkcs11:") {
		rawKey = []byte(privPathOrPEM)
		return rawKey, cert.Curve_P256, true, nil
	} else {
		pemPrivateKey, err = os.ReadFile(privPathOrPEM)
		if err != nil {
			return nil, curve, false, fmt.Errorf("unable to read pki.key file %s: %s", privPathOrPEM, err)
		}
		rawKey, _, curve, err = cert.UnmarshalPrivateKeyFromPEM(pemPrivateKey)
		if err != nil {
			return nil, curve, false, fmt.Errorf("error while unmarshaling pki.key %s: %s", privPathOrPEM, err)
		}
	}

	return
}

func loadCertificate(b []byte) (cert.Certificate, []byte, error) {
	c, b, err := cert.UnmarshalCertificateFromPEM(b)
	if err != nil {
		return nil, b, fmt.Errorf("error while unmarshaling pki.cert: %w", err)
	}

	if c.Expired(time.Now()) {
		return nil, b, fmt.Errorf("nebula certificate for this host is expired")
	}

	if len(c.Networks()) == 0 {
		return nil, b, fmt.Errorf("no networks encoded in certificate")
	}

	if c.IsCA() {
		return nil, b, fmt.Errorf("host certificate is a CA certificate")
	}

	return c, b, nil
}

func loadCAPoolFromConfig(l *slog.Logger, c *config.C) (*cert.CAPool, error) {
	caPathOrPEM := c.GetString("pki.ca", "")
	if caPathOrPEM == "" {
		return nil, errors.New("no pki.ca path or PEM data provided")
	}

	var caReader io.ReadCloser
	var err error

	if strings.Contains(caPathOrPEM, "-----BEGIN") {
		caReader = io.NopCloser(strings.NewReader(caPathOrPEM))
	} else {
		caReader, err = os.Open(caPathOrPEM)
		if err != nil {
			return nil, fmt.Errorf("unable to read pki.ca file %s: %s", caPathOrPEM, err)
		}
	}
	defer caReader.Close()

	caPool, err := cert.NewCAPoolFromPEMReader(caReader)
	if errors.Is(err, cert.ErrExpired) {
		var expired int
		for _, crt := range caPool.CAs {
			if crt.Certificate.Expired(time.Now()) {
				expired++
				l.Warn("expired certificate present in CA pool", "cert", crt)
			}
		}

		if expired >= len(caPool.CAs) {
			return nil, errors.New("no valid CA certificates present")
		}

	} else if err != nil {
		return nil, fmt.Errorf("error while adding CA certificate to CA trust store: %s", err)
	}

	bl := c.GetStringSlice("pki.blocklist", []string{})
	if len(bl) > 0 {
		for _, fp := range bl {
			caPool.BlocklistFingerprint(fp)
		}

		l.Info("Blocklisted certificates", "fingerprintCount", len(bl))
	}

	return caPool, nil
}
