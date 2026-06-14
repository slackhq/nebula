// Package pq owns nebula's post-quantum PSK material handling and the
// security policy around when PQ protection must be in force.
//
// The package separates three concerns that were previously tangled across
// pki.go, handshake_manager.go, and connection_manager.go:
//
//   - Provider: where PSK bytes come from (filesystem today, sockets/HSMs
//     tomorrow). The crypto code only sees an interface.
//   - State: per-peer PQ history (have we ever achieved IXPSK2 with this
//     peer? when?), persisted across restarts so downgrade attempts are
//     evidence-leaving.
//   - Policy: the security decisions — which subtype to initiate with,
//     whether to accept an incoming subtype, what to do when an upgrade
//     rekey fails. Driven by Provider + State + a small set of modes.
package pq

import "fmt"

// Provider supplies 32-byte post-quantum preshared keys keyed by peer
// static public key. Implementations are free to source the bytes
// however they want (file, unix socket, RPC, HSM); the rest of nebula
// is decoupled from the transport.
//
// Lookup must be safe for concurrent use. Subscribe returns a channel
// that fires every time the underlying material may have changed; the
// channel is buffered with size 1 and coalesces multiple events. A
// receiver that has already been notified of a change does not need to
// receive again before re-reading via Lookup. Close releases any OS
// resources (file watchers, sockets) and stops Subscribe channels.
type Provider interface {
	// Lookup returns the PSK for the given peer's static public key, or
	// nil if no PSK is configured for that peer (or the lookup table is
	// empty). For mesh-wide PSK semantics, the implementation may
	// ignore peerStaticPubKey.
	Lookup(peerStaticPubKey []byte) []byte

	// Subscribe returns a channel that receives a notification each
	// time the lookup table may have changed (e.g. file rotation,
	// SIGHUP, socket update). The receiver must not close the channel.
	// A Provider returns the same channel for every call within its
	// lifetime; multiple subscribers fan out via the caller, not the
	// Provider.
	Subscribe() <-chan struct{}

	// Close stops watchers, drains in-flight notifications, and
	// releases resources. After Close, Lookup may continue to serve
	// the last-known table or return nil; Subscribe is closed.
	Close() error

	// LookupRPHash returns the lowercase hex SHA-256 of the
	// provider pubkey expected to have derived the PSK for this
	// peer, or empty string if unknown / no such binding info is
	// tracked by this provider. Used by the handshake to validate
	// the PSK origin against the peer's CA-signed PQ-PSK binding
	// cert extension. Returning empty is safe — callers treat it as
	// "no binding info; behaviour depends on policy".
	//
	// Prefer LookupWithBinding for binding validation: calling
	// Lookup and LookupRPHash separately against a composedProvider
	// can resolve the PSK and the hash from DIFFERENT layers, pairing
	// one layer's live PSK with another layer's unrelated hash.
	LookupRPHash(peerStaticPubKey []byte) string

	// LookupWithBinding returns the PSK for the peer together with the
	// binding hint (rpHash) that the SAME source recorded for it. This
	// is the atomic counterpart to calling Lookup + LookupRPHash: for a
	// composedProvider it guarantees the rpHash describes the very PSK
	// being returned, instead of falling through to a different layer's
	// hash. ok is true iff a PSK was found; rpHash is "" when the
	// supplying source tracks no binding info for the peer (callers
	// treat "" as "no binding info; behaviour depends on policy").
	//
	// For leaf providers this is equivalent to (Lookup, LookupRPHash);
	// only the composition layer differs.
	LookupWithBinding(peerStaticPubKey []byte) (psk []byte, rpHash string, ok bool)
}

// NoProvider is a Provider that never serves any PSK. Used as the
// default when no PQ material is configured, so callers don't have to
// nil-check.
type NoProvider struct{}

func (NoProvider) Lookup([]byte) []byte       { return nil }
func (NoProvider) Subscribe() <-chan struct{} { return nil }
func (NoProvider) Close() error               { return nil }
func (NoProvider) LookupRPHash([]byte) string { return "" }
func (NoProvider) LookupWithBinding([]byte) (psk []byte, rpHash string, ok bool) {
	return nil, "", false
}

// PreviousEpochLookup is an optional Provider capability: providers
// that retain the previous epoch's PSK per peer (FileProvider)
// implement it; everything else doesn't. Callers use the
// LookupPrevious helper rather than type-asserting directly.
// Optional-interface (not a Provider method) so existing third-party
// and test-double Providers keep compiling.
type PreviousEpochLookup interface {
	LookupPreviousWithBinding(peerStaticPubKey []byte) (psk []byte, rpHash string, ok bool)
}

// LookupPrevious resolves the previous-epoch PSK for a peer if the
// provider (or, for compositions, the SAME layer that serves the
// peer's current PSK) retains one.
func LookupPrevious(p Provider, peerStaticPubKey []byte) (psk []byte, rpHash string, ok bool) {
	if p == nil {
		return nil, "", false
	}
	if pe, capable := p.(PreviousEpochLookup); capable {
		return pe.LookupPreviousWithBinding(peerStaticPubKey)
	}
	return nil, "", false
}

// HasPSK reports whether the given Provider currently holds any
// PSK material. It is structural rather than nominal: a composed
// provider whose constituents are all empty returns false, so
// callers wiring downstream "we have PQ material configured"
// behaviour don't get a false positive from an empty composition.
func HasPSK(p Provider) bool {
	if p == nil {
		return false
	}
	switch v := p.(type) {
	case NoProvider:
		return false
	case *composedProvider:
		for _, l := range v.Layers() {
			if HasPSK(l) {
				return true
			}
		}
		return false
	case *MemoryProvider:
		return v.hasAnyPSK()
	case *FileProvider:
		return v.hasAnyPSK()
	}
	// Unknown Provider implementation: be conservative and assume
	// it can serve. External test doubles preserve their current
	// semantics.
	return true
}

// PeerPSKStatus is one peer's entry in a provider status report.
type PeerPSKStatus struct {
	PeerKeyHash string `json:"peerKeyHash"` // sha256-hex of the peer static pubkey (the .psk stem)
	HasPSK      bool   `json:"hasPsk"`
	HasPrev     bool   `json:"hasPrev"`
	RPHash      string `json:"rpHash,omitempty"`
}

// ProviderStatus is a point-in-time diagnostic snapshot of a provider.
type ProviderStatus struct {
	Kind        string          `json:"kind"`
	SnapshotAge float64         `json:"snapshotAgeSeconds,omitempty"` // FileProvider only
	Peers       []PeerPSKStatus `json:"peers"`
}

// StatusReporter is an optional Provider capability used by the
// pq-status ssh command.
type StatusReporter interface {
	Status() ProviderStatus
}

// Status resolves status reports from any provider, recursing into
// compositions. Providers without the capability yield a Kind-only
// stub so the operator still sees what is wired.
func Status(p Provider) []ProviderStatus {
	switch v := p.(type) {
	case nil:
		return nil
	case *composedProvider:
		var out []ProviderStatus
		for _, l := range v.Layers() {
			out = append(out, Status(l)...)
		}
		return out
	}
	if sr, ok := p.(StatusReporter); ok {
		return []ProviderStatus{sr.Status()}
	}
	return []ProviderStatus{{Kind: fmt.Sprintf("%T", p)}}
}
