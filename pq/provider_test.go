package pq

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHasPSKFalseForComposedOfNoProviders(t *testing.T) {
	if HasPSK(Compose(NoProvider{}, NoProvider{})) {
		t.Fatal("HasPSK must be false when every composed layer is NoProvider")
	}
}

func TestHasPSKFalseForComposedOfEmptyMemoryProvider(t *testing.T) {
	mem := NewMemoryProvider()
	p := Compose(mem, NoProvider{})
	if HasPSK(p) {
		t.Fatal("HasPSK must be false when MemoryProvider has nothing set and other layers are NoProvider")
	}
}

func TestHasPSKTrueAfterMemoryProviderSet(t *testing.T) {
	mem := NewMemoryProvider()
	// Use exactly 32 bytes for the peer pubkey
	mem.Set([]byte("peerpubkey-32-bytes-padding-aaaa"), make([]byte, 32))
	p := Compose(mem, NoProvider{})
	if !HasPSK(p) {
		t.Fatal("HasPSK must be true once a layer holds at least one PSK")
	}
}

func TestComposedProviderFansInLayerNotifications(t *testing.T) {
	mem := NewMemoryProvider()
	p := Compose(mem, NoProvider{})
	sub := p.Subscribe()
	if sub == nil {
		t.Fatal("composed Subscribe returned nil")
	}
	// Trigger an inner notification.
	mem.Set([]byte("peer-pubkey-32-bytes-padding-aaaa"), make([]byte, 32))
	select {
	case <-sub:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("composed provider did not propagate inner notification")
	}
}

func TestComposedProviderCloseDrainsGoroutines(t *testing.T) {
	base := runtime.NumGoroutine()
	for i := 0; i < 10; i++ {
		mem := NewMemoryProvider()
		p := Compose(mem, NoProvider{})
		_ = p.Subscribe()
		_ = p.Close()
	}
	// Give scheduler a tick to retire workers
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()
	if after > base+2 {
		t.Fatalf("composedProvider goroutine leak: base=%d after=%d", base, after)
	}
}

// TestMemoryProviderWithCallback verifies a registered callback fires
// synchronously on both Set and Delete. This is the direct-signal path
// used by callers (e.g. embedded rosenpass → PKI rotate) that prefer
// not to consume the coalescing Subscribe channel.
func TestMemoryProviderWithCallback(t *testing.T) {
	mem := NewMemoryProvider()
	var fired int32
	mem.WithCallback(func() { atomic.AddInt32(&fired, 1) })
	mem.Set([]byte("peer-pubkey-32-bytes-padding-aaaa"), make([]byte, 32))
	if atomic.LoadInt32(&fired) != 1 {
		t.Fatalf("callback should fire once on Set; fired=%d", atomic.LoadInt32(&fired))
	}
	mem.Delete([]byte("peer-pubkey-32-bytes-padding-aaaa"))
	if atomic.LoadInt32(&fired) != 2 {
		t.Fatalf("callback should also fire on Delete; fired=%d", atomic.LoadInt32(&fired))
	}
}

// TestMemoryProviderWithCallbackReplace documents the single-callback
// contract: a second WithCallback fully replaces the first. If callers
// want fan-out they own that themselves.
func TestMemoryProviderWithCallbackReplace(t *testing.T) {
	mem := NewMemoryProvider()
	var first, second int32
	mem.WithCallback(func() { atomic.AddInt32(&first, 1) })
	mem.WithCallback(func() { atomic.AddInt32(&second, 1) }) // replaces first
	mem.Set([]byte("peer-pubkey-32-bytes-padding-bbbb"), make([]byte, 32))
	if atomic.LoadInt32(&first) != 0 {
		t.Fatalf("first callback should have been replaced; fired=%d", atomic.LoadInt32(&first))
	}
	if atomic.LoadInt32(&second) != 1 {
		t.Fatalf("second callback should fire once; fired=%d", atomic.LoadInt32(&second))
	}
}

// TestMemoryProviderWithCallbackNilClears confirms nil is the documented
// way to detach a previously-registered callback.
func TestMemoryProviderWithCallbackNilClears(t *testing.T) {
	mem := NewMemoryProvider()
	var fired int32
	mem.WithCallback(func() { atomic.AddInt32(&fired, 1) })
	mem.WithCallback(nil) // clears
	mem.Set([]byte("peer-pubkey-32-bytes-padding-cccc"), make([]byte, 32))
	if atomic.LoadInt32(&fired) != 0 {
		t.Fatalf("callback should be cleared; fired=%d", atomic.LoadInt32(&fired))
	}
}

// TestMemoryProviderLookupRPHashEmpty pins the documented behaviour:
// MemoryProvider tracks no rpinfo binding (the embedded build path
// validates RP pubkeys against the cert extension directly via the
// coordinator). LookupRPHash must return "" regardless of state.
func TestMemoryProviderLookupRPHashEmpty(t *testing.T) {
	mem := NewMemoryProvider()
	pub := []byte("peer-pubkey-32-bytes-padding-aaaa")
	mem.Set(pub, make([]byte, 32))
	if got := mem.LookupRPHash(pub); got != "" {
		t.Fatalf("MemoryProvider.LookupRPHash must return empty; got %q", got)
	}
}

// TestComposedProviderLookupRPHashWalksLayers verifies a composed
// provider returns the first non-empty rpHash from its layers, so a
// MemoryProvider in front of a FileProvider doesn't mask the file's
// binding info just because it answers Lookup first.
func TestComposedProviderLookupRPHashWalksLayers(t *testing.T) {
	// Set up a FileProvider holding both a PSK and a valid .rpinfo
	// companion for one peer.
	dir := t.TempDir()
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0xEE
	}
	pubSum := sha256.Sum256(pub)
	stem := hex.EncodeToString(pubSum[:])
	rpHash := strings.Repeat("ab", 32)

	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".psk"), make([]byte, 32), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".rpinfo"), []byte(rpHash+"\n"), 0o600))

	fp, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = fp.Close() })

	// Compose with MemoryProvider in front. MemoryProvider returns
	// "" for LookupRPHash, so the composed walk should fall through
	// to FileProvider.
	mem := NewMemoryProvider()
	p := Compose(mem, fp)
	t.Cleanup(func() { _ = p.Close() })

	if got := p.LookupRPHash(pub); got != rpHash {
		t.Fatalf("composedProvider.LookupRPHash should walk layers; got %q want %q", got, rpHash)
	}

	// Unknown peer: every layer returns "" — composed must too.
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0x33
	}
	if got := p.LookupRPHash(other); got != "" {
		t.Fatalf("composedProvider.LookupRPHash for unknown peer should be empty; got %q", got)
	}
}

// TestComposedProviderLookupWithBindingSameLayer is the regression test
// for the cross-layer mismatch (audit: composed-rphash-psk-layer-mismatch).
// Layer 0 (MemoryProvider) holds the live PSK and tracks NO binding hint;
// layer 1 (FileProvider) holds a DIFFERENT PSK and a non-empty .rpinfo
// hash for the SAME peer. The atomic LookupWithBinding must return layer
// 0's PSK paired with layer 0's (empty) hash — it must NOT borrow layer
// 1's hash. The old separate Lookup + LookupRPHash walks would have
// paired the memory PSK with the file hash, which under
// PqPskBindingEnforce can blackout the live PSK.
func TestComposedProviderLookupWithBindingSameLayer(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0x7C
	}
	pubSum := sha256.Sum256(pub)
	stem := hex.EncodeToString(pubSum[:])

	// Layer 1: FileProvider with a distinct PSK + a real binding hint.
	dir := t.TempDir()
	filePSK := make([]byte, 32)
	for i := range filePSK {
		filePSK[i] = 0x11
	}
	fileHash := strings.Repeat("cd", 32)
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".psk"), filePSK, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".rpinfo"), []byte(fileHash+"\n"), 0o600))

	fp, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = fp.Close() })

	// Layer 0: MemoryProvider with a different live PSK and no hint.
	memPSK := make([]byte, 32)
	for i := range memPSK {
		memPSK[i] = 0x22
	}
	mem := NewMemoryProvider()
	mem.Set(pub, memPSK)

	p := Compose(mem, fp)
	t.Cleanup(func() { _ = p.Close() })

	// Sanity: the two layers genuinely disagree on both PSK and hash.
	require.NotEqual(t, memPSK, filePSK)
	require.Equal(t, fileHash, fp.LookupRPHash(pub))

	gotPSK, gotHash, ok := p.LookupWithBinding(pub)
	require.True(t, ok, "composed LookupWithBinding must find the layer-0 PSK")
	require.Equal(t, memPSK, gotPSK, "must return the live layer-0 (memory) PSK")
	require.Equal(t, "", gotHash, "hash must come from the SAME layer as the PSK (memory => empty), not layer 1's file hash")
	require.NotEqual(t, fileHash, gotHash, "must NOT borrow layer 1's rpHash for layer 0's PSK")

	// Unknown peer: no layer has a PSK, so ok is false.
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0x55
	}
	_, _, ok = p.LookupWithBinding(other)
	require.False(t, ok, "unknown peer must report no PSK")
}

// TestComposedProviderLookupWithBindingFallsThrough verifies the
// fall-through still works: when layer 0 has no PSK for the peer,
// LookupWithBinding returns layer 1's PSK AND layer 1's own hash
// together.
func TestComposedProviderLookupWithBindingFallsThrough(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0x9A
	}
	pubSum := sha256.Sum256(pub)
	stem := hex.EncodeToString(pubSum[:])

	dir := t.TempDir()
	filePSK := make([]byte, 32)
	for i := range filePSK {
		filePSK[i] = 0x33
	}
	fileHash := strings.Repeat("ef", 32)
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".psk"), filePSK, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".rpinfo"), []byte(fileHash+"\n"), 0o600))

	fp, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = fp.Close() })

	mem := NewMemoryProvider() // empty: no entry for pub
	p := Compose(mem, fp)
	t.Cleanup(func() { _ = p.Close() })

	gotPSK, gotHash, ok := p.LookupWithBinding(pub)
	require.True(t, ok)
	require.Equal(t, filePSK, gotPSK, "must fall through to layer 1's PSK")
	require.Equal(t, fileHash, gotHash, "and carry layer 1's own binding hash")
}

// TestNoProviderLookupRPHashEmpty pins that NoProvider returns "" so
// callers using NoProvider as their default don't have to nil-check.
func TestNoProviderLookupRPHashEmpty(t *testing.T) {
	if got := (NoProvider{}).LookupRPHash([]byte("anything")); got != "" {
		t.Fatalf("NoProvider.LookupRPHash must return empty; got %q", got)
	}
}

func TestLookupPrevious_HelperAndComposed(t *testing.T) {
	if _, _, ok := LookupPrevious(NoProvider{}, bytes32(1)); ok {
		t.Fatal("NoProvider must report no previous")
	}
	dir := t.TempDir()
	peer := bytes32(0xCC)
	sum := sha256.Sum256(peer)
	stem := hex.EncodeToString(sum[:])
	os.WriteFile(filepath.Join(dir, stem+".psk"), bytes32(0x01), 0o600)
	fp, err := NewFileProvider(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	os.WriteFile(filepath.Join(dir, stem+".psk"), bytes32(0x02), 0o600)
	if err := fp.rescan(); err != nil {
		t.Fatal(err)
	}

	mem := NewMemoryProvider()
	comp := Compose(mem, fp)
	defer comp.Close()
	prev, _, ok := LookupPrevious(comp, peer)
	if !ok || !bytes.Equal(prev, bytes32(0x01)) {
		t.Fatalf("composed previous = %x ok=%v, want epoch-1 psk", prev, ok)
	}
}
