package nebula

import (
	"log/slog"
	"testing"

	"github.com/slackhq/nebula/pq"
	"github.com/stretchr/testify/require"
)

// TestPSKLookup_EmptyProviderProducesNonNilClosure verifies the lookup
// closure is installed even when the Provider has no PSKs at construction
// time. This is the documented sidecar-starts-after-nebula path: nebula
// boots with an empty MemoryProvider (or an empty FileProvider dir), the
// rosenpass sidecar/embedded coordinator derives a PSK later and writes
// it into the live Provider. The closure must already be wired so the
// new PSK is visible to subsequent handshakes without a config reload.
//
// Regression test for the "HasPSK snapshot" bug: pre-fix,
// pqLookupFromProviderWithBinding returned nil here because the Provider
// was empty at construction, leaving CertState.pqPSKLookup permanently
// nil for that CertState's lifetime — PQ silently dead until SIGHUP.
func TestPSKLookup_EmptyProviderProducesNonNilClosure(t *testing.T) {
	mem := pq.NewMemoryProvider()
	t.Cleanup(func() { _ = mem.Close() })
	p := pq.Compose(mem, pq.NoProvider{})
	t.Cleanup(func() { _ = p.Close() })

	// Sanity: HasPSK is false right now (empty composition). Pre-fix
	// this caused the closure to be skipped entirely.
	require.False(t, pq.HasPSK(p), "precondition: composition is empty")

	// pki is nil here: the test exercises the wrapper purely as a
	// Provider-decoration. The wrapper degrades to "no gossiped
	// claim" when pki is nil, matching the early-boot path where the
	// LightHouse hasn't been wired up yet.
	lookup := pqLookupFromProviderWithBinding(p, pq.PqPskBindingWarn, nil, slog.Default())
	require.NotNil(t, lookup, "must install closure for live providers even when empty")

	peerPub := make([]byte, 32)
	for i := range peerPub {
		peerPub[i] = byte(i + 1)
	}
	require.Nil(t, lookup(peerPub, nil), "empty Provider returns nil PSK per peer")

	// Simulate sidecar landing a PSK after CertState construction.
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(0xA0 + i)
	}
	mem.Set(peerPub, psk)

	got := lookup(peerPub, nil)
	require.NotNil(t, got, "PSK set after closure construction must be visible")
	require.Equal(t, psk, got)
}

// TestPSKLookup_NoProviderReturnsNilClosure preserves the
// nil-pqPSKLookup semantic used by CertState.HasPQPSK and the
// handshake credential to short-circuit the PSK plumbing entirely when
// the operator has explicitly opted out (no provider configured).
func TestPSKLookup_NoProviderReturnsNilClosure(t *testing.T) {
	require.Nil(t, pqLookupFromProviderWithBinding(pq.NoProvider{}, pq.PqPskBindingWarn, nil, slog.Default()),
		"NoProvider must yield a nil closure so HasPQPSK reports false")
	require.Nil(t, pqLookupFromProviderWithBinding(nil, pq.PqPskBindingWarn, nil, slog.Default()),
		"nil Provider must yield a nil closure")
}
