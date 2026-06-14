package pq

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"sort"
	"sync"
)

// MemoryProvider is a Provider whose contents are mutated in-process,
// not by the filesystem. Used as the sink for embedded post-quantum KEM
// daemons so derived PSKs land directly in nebula without ever touching
// disk.
//
// Concurrency: Lookup is safe for any number of readers; Set / Delete
// take the write lock briefly. Subscribe returns a single coalescing
// channel — multiple updates between drains collapse to one notify.
type MemoryProvider struct {
	mu     sync.RWMutex
	psks   map[string][]byte
	notify chan struct{}
	closed chan struct{}
	// callback, if non-nil, fires (outside the lock) after every
	// successful Set/Delete. Registered via WithCallback. Replaces
	// the coalescing Subscribe path for callers that want an
	// uncoalesced direct signal — see WithCallback for the contract.
	callback func()
}

// NewMemoryProvider returns an empty MemoryProvider ready for use.
func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{
		psks:   map[string][]byte{},
		notify: make(chan struct{}, 1),
		closed: make(chan struct{}),
	}
}

// Set installs psk for the given peer static public key. psk must be
// exactly 32 bytes. Triggers a Subscribe notification (coalesced) and
// invokes the WithCallback registrant, if any, outside the lock.
func (p *MemoryProvider) Set(peerStaticPubKey, psk []byte) {
	if len(psk) != 32 || len(peerStaticPubKey) == 0 {
		return
	}
	sum := sha256.Sum256(peerStaticPubKey)
	key := hex.EncodeToString(sum[:])
	cp := make([]byte, 32)
	copy(cp, psk)
	p.mu.Lock()
	p.psks[key] = cp
	cb := p.callback
	p.mu.Unlock()
	if cb != nil {
		cb()
	}
	p.fire()
}

// Delete removes any PSK entry for the given peer static public key.
// Invokes the WithCallback registrant, if any, outside the lock and
// then fires the coalescing Subscribe notification.
func (p *MemoryProvider) Delete(peerStaticPubKey []byte) {
	if len(peerStaticPubKey) == 0 {
		return
	}
	sum := sha256.Sum256(peerStaticPubKey)
	key := hex.EncodeToString(sum[:])
	p.mu.Lock()
	delete(p.psks, key)
	cb := p.callback
	p.mu.Unlock()
	if cb != nil {
		cb()
	}
	p.fire()
}

func (p *MemoryProvider) Lookup(peerStaticPubKey []byte) []byte {
	if len(peerStaticPubKey) == 0 {
		return nil
	}
	sum := sha256.Sum256(peerStaticPubKey)
	key := hex.EncodeToString(sum[:])
	p.mu.RLock()
	v := p.psks[key]
	// Copy on read so callers cannot alias internal storage. The
	// Provider interface contract says concurrent Lookup is safe; if
	// we returned the live slice and a concurrent Set/Delete fired
	// after the caller dropped its reference, the caller's slice
	// could change underneath them. 32 bytes is cheap.
	var out []byte
	if v != nil {
		out = make([]byte, len(v))
		copy(out, v)
	}
	p.mu.RUnlock()
	return out
}

func (p *MemoryProvider) Subscribe() <-chan struct{} { return p.notify }

// LookupRPHash always returns the empty string. MemoryProvider has
// no notion of the provider-pubkey-hash binding: in the embedded
// build the provider validates peer pubkeys directly against the
// CA-signed cert extension before deriving the PSK, so no separate
// companion record is kept here. Stub satisfies the Provider
// interface; callers treat "" as "no binding info, defer to policy".
func (p *MemoryProvider) LookupRPHash(peerStaticPubKey []byte) string {
	return ""
}

// LookupWithBinding returns the in-memory PSK for the peer paired with
// an always-empty rpHash. MemoryProvider tracks no binding hint (see
// LookupRPHash), so the hash is "" whenever a PSK is present; ok is
// true iff a PSK was found. Pairing the live PSK with its own (empty)
// hint here is what lets composedProvider avoid borrowing a different
// layer's hash for this PSK.
func (p *MemoryProvider) LookupWithBinding(peerStaticPubKey []byte) (psk []byte, rpHash string, ok bool) {
	v := p.Lookup(peerStaticPubKey)
	if v == nil {
		return nil, "", false
	}
	return v, "", true
}

// WithCallback registers fn to be called synchronously after every
// successful Set/Delete. The callback runs OUTSIDE the provider lock
// so it may safely do I/O, channel sends, logging, etc. It must not
// call back into this provider (no deadlock — we're outside the lock —
// but a Set/Delete inside the callback will recursively invoke it).
//
// This is the direct-signal counterpart to Subscribe. Subscribe is a
// single coalescing channel: multiple updates between drains collapse
// to one notify. The callback path does NOT coalesce — every Set/
// Delete fires it once. Callers that don't need every event should
// keep using Subscribe.
//
// Single-callback API: a second WithCallback replaces the first;
// passing nil clears any previously-registered callback. Fan-out is
// the caller's responsibility.
func (p *MemoryProvider) WithCallback(fn func()) {
	p.mu.Lock()
	p.callback = fn
	p.mu.Unlock()
}

// hasAnyPSK reports whether the in-memory map holds at least one
// entry. Used by HasPSK to decide whether an embedded-provider
// MemoryProvider is "live" yet.
func (p *MemoryProvider) hasAnyPSK() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.psks) > 0
}

// Status implements StatusReporter for the pq-status ssh command.
// MemoryProvider tracks no previous epoch (no on-disk rotation; the
// embedded path derives PSKs directly) and no binding hints, so
// HasPrev is always false and RPHash is always empty.
func (p *MemoryProvider) Status() ProviderStatus {
	st := ProviderStatus{Kind: "memory"}
	p.mu.RLock()
	for stem := range p.psks {
		st.Peers = append(st.Peers, PeerPSKStatus{
			PeerKeyHash: stem,
			HasPSK:      true,
		})
	}
	p.mu.RUnlock()
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].PeerKeyHash < st.Peers[j].PeerKeyHash })
	return st
}

func (p *MemoryProvider) Close() error {
	// Hold the write lock across the close so it serialises with
	// concurrent fire() calls. Without this, fire() could observe
	// p.closed as still open, then Close closes p.notify, then
	// fire's send-on-notify panics.
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.closed:
	default:
		close(p.closed)
		close(p.notify)
	}
	return nil
}

func (p *MemoryProvider) fire() {
	// Hold the write lock across the closed-check + send so a
	// concurrent Close (which closes both p.closed and p.notify
	// under the same lock) cannot race the second select. Without
	// this, the audit found a window where fire's first select
	// observes "not closed", then Close closes both channels, then
	// fire's second select panics with "send on closed channel".
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.closed:
		return
	default:
	}
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

// Compose returns a Provider that consults each constituent in order
// and returns the first non-nil PSK. Any subscriber is fanned in from
// every component. Used to layer a MemoryProvider (live, in-process
// provider output) on top of a FileProvider (preconfigured / sidecar
// drop-ins) without giving either one priority surprises.
func Compose(layers ...Provider) Provider {
	if len(layers) == 0 {
		return NoProvider{}
	}
	if len(layers) == 1 {
		return layers[0]
	}
	c := &composedProvider{
		layers: layers,
		notify: make(chan struct{}, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go c.run()
	return c
}

type composedProvider struct {
	layers []Provider
	notify chan struct{}
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
}

func (c *composedProvider) Lookup(peerStaticPubKey []byte) []byte {
	for _, l := range c.layers {
		if v := l.Lookup(peerStaticPubKey); v != nil {
			return v
		}
	}
	return nil
}

func (c *composedProvider) Subscribe() <-chan struct{} { return c.notify }

// LookupRPHash walks the constituent layers in the same order as
// Lookup and returns the first non-empty provider-pubkey-hash. Layers
// that don't track a binding hint (MemoryProvider, NoProvider,
// StaticProvider) return "" and are simply skipped. If no layer has
// binding info, returns "".
func (c *composedProvider) LookupRPHash(peerStaticPubKey []byte) string {
	for _, l := range c.layers {
		if h := l.LookupRPHash(peerStaticPubKey); h != "" {
			return h
		}
	}
	return ""
}

// LookupWithBinding walks the layers in the same order as Lookup and
// returns the PSK from the first layer that has one, paired with THAT
// SAME layer's binding hint. This is the correctness fix for the
// cross-layer mismatch: the independent Lookup / LookupRPHash walks
// could resolve a PSK from layer 0 (e.g. MemoryProvider, which tracks
// no hint) while LookupRPHash fell through to layer 1's (FileProvider)
// hash, pairing a live PSK with an unrelated rpHash. Binding
// validation must see the hash that describes the PSK it is validating,
// so we resolve both from one layer atomically.
func (c *composedProvider) LookupWithBinding(peerStaticPubKey []byte) (psk []byte, rpHash string, ok bool) {
	for _, l := range c.layers {
		if v, h, found := l.LookupWithBinding(peerStaticPubKey); found {
			return v, h, true
		}
	}
	return nil, "", false
}

// LookupPreviousWithBinding resolves the previous epoch from the SAME
// layer that serves the peer's current PSK. Walking all layers for
// any previous value would let layer 1's stale epoch shadow layer 0's
// live material — previous-epoch fallback is only meaningful within
// the layer that rotated.
func (c *composedProvider) LookupPreviousWithBinding(peerStaticPubKey []byte) (psk []byte, rpHash string, ok bool) {
	for _, l := range c.layers {
		if _, _, found := l.LookupWithBinding(peerStaticPubKey); found {
			return LookupPrevious(l, peerStaticPubKey)
		}
	}
	return nil, "", false
}

// Layers returns the constituent providers. Exposed so HasPSK can
// recursively decide whether anything in the composition is live;
// keeps the composed-vs-leaf detail out of the Provider interface.
func (c *composedProvider) Layers() []Provider {
	return c.layers
}

// Close stops the composedProvider's run goroutine and closes its
// notify channel. It does NOT cascade to the layers — callers own
// each layer's lifecycle and must close them separately. Cascading
// would have made it impossible to reuse a long-lived MemoryProvider
// across multiple Compose generations on config reload, since the
// first Close would tear it down.
func (c *composedProvider) Close() error {
	c.once.Do(func() {
		// Signal the run goroutine to exit, wait for it to finish,
		// then close the outbound notify chan. Closing notify before
		// the sender has drained risks "send on closed channel"
		// panics during the narrow window between run observing
		// c.stop and its next loop iteration.
		close(c.stop)
		<-c.done
		close(c.notify)
	})
	return nil
}

// run multiplexes notifications from every layer into c.notify using
// a single reflect.Select. One goroutine, one synchronisation point:
// no per-layer fan-out goroutines, no WaitGroup, no "send on closed
// channel" window. cases[0] is always c.stop; the rest are the live
// per-layer Subscribe channels. When a layer closes its channel we
// drop it from the case set; when only c.stop remains we park on it
// directly.
func (c *composedProvider) run() {
	defer close(c.done)

	cases := []reflect.SelectCase{
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(c.stop)},
	}
	for _, l := range c.layers {
		sub := l.Subscribe()
		if sub == nil {
			continue
		}
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(sub),
		})
	}

	for {
		chosen, _, ok := reflect.Select(cases)
		if chosen == 0 {
			// Stop signal: c.stop was closed.
			return
		}
		if !ok {
			// This layer's Subscribe channel was closed by the
			// layer. Drop it from the case set so reflect.Select
			// stops returning it.
			cases = append(cases[:chosen], cases[chosen+1:]...)
			if len(cases) == 1 {
				// Only c.stop remains — park on it directly so we
				// stop spinning through reflect.Select for no gain.
				<-c.stop
				return
			}
			continue
		}
		// Coalesce a notification on c.notify. Non-blocking send so a
		// slow consumer never stalls the producer side.
		select {
		case c.notify <- struct{}{}:
		default:
		}
	}
}
