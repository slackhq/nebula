package pq

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncBuffer is a goroutine-safe bytes.Buffer for capturing slog output
// from the FileProvider's background run loop without racing the test's
// reader against the loop's writer.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// pubKeyHashFile writes a 32-byte PSK to dir under the canonical name
// (sha256-hex of the supplied "pubkey" + ".psk") and returns the
// pubkey bytes the test should query Lookup with.
func pubKeyHashFile(t *testing.T, dir string, label byte, psk []byte) []byte {
	t.Helper()
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = label
	}
	sum := sha256.Sum256(pub)
	name := hex.EncodeToString(sum[:]) + ".psk"
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), psk, 0o600))
	return pub
}

func TestFileProvider_InitialLoad(t *testing.T) {
	dir := t.TempDir()
	pskA := bytes32(0x11)
	pskB := bytes32(0x22)
	pubA := pubKeyHashFile(t, dir, 0xAA, pskA)
	pubB := pubKeyHashFile(t, dir, 0xBB, pskB)

	p, err := NewFileProvider(dir, nil)
	require.NoError(t, err)
	defer p.Close()

	assert.Equal(t, pskA, p.Lookup(pubA))
	assert.Equal(t, pskB, p.Lookup(pubB))
	assert.Nil(t, p.Lookup(bytes32(0xCC)), "unknown peer must return nil")
}

func TestFileProvider_RotationViaFsnotify(t *testing.T) {
	dir := t.TempDir()
	cfg := FileProviderConfig{Dir: dir, Debounce: 30 * time.Millisecond}
	p, err := NewFileProviderWithConfig(cfg)
	require.NoError(t, err)
	defer p.Close()

	// Drop a PSK after the provider is already running; expect notification.
	pskV1 := bytes32(0x77)
	pubA := pubKeyHashFile(t, dir, 0xAA, pskV1)

	select {
	case <-p.Subscribe():
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe did not fire on initial PSK drop")
	}
	assert.Equal(t, pskV1, p.Lookup(pubA))

	// Rotate: replace via tempfile + atomic rename, mirroring Rosenpass.
	pskV2 := bytes32(0x88)
	tmp := filepath.Join(dir, ".rotate.tmp")
	require.NoError(t, os.WriteFile(tmp, pskV2, 0o600))

	sum := sha256.Sum256(pubA)
	finalName := filepath.Join(dir, hex.EncodeToString(sum[:])+".psk")
	require.NoError(t, os.Rename(tmp, finalName))

	select {
	case <-p.Subscribe():
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe did not fire on rotation")
	}
	assert.Equal(t, pskV2, p.Lookup(pubA))
}

func TestFileProvider_BadFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	// non-hex name
	require.NoError(t, os.WriteFile(filepath.Join(dir, "garbage.psk"), bytes32(0x01), 0o600))
	// wrong size
	require.NoError(t, os.WriteFile(filepath.Join(dir, "11"+repeat("a", 62)+".psk"), []byte("short"), 0o600))
	// good entry should still load
	good := bytes32(0x55)
	pub := pubKeyHashFile(t, dir, 0xCC, good)

	p, err := NewFileProvider(dir, nil)
	require.NoError(t, err)
	defer p.Close()
	assert.Equal(t, good, p.Lookup(pub))
}

func TestFileProvider_SymlinksSkipped(t *testing.T) {
	dir := t.TempDir()

	// Create a real PSK file in a separate location, then symlink
	// it into the watched directory. The provider must refuse to
	// follow the symlink so an attacker who can drop a symlink
	// can't substitute arbitrary file contents as a peer's PSK.
	target := filepath.Join(t.TempDir(), "evil-bytes")
	require.NoError(t, os.WriteFile(target, bytes32(0xEE), 0o600))

	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0xCA
	}
	sum := sha256.Sum256(pub)
	linkName := filepath.Join(dir, hex.EncodeToString(sum[:])+".psk")
	require.NoError(t, os.Symlink(target, linkName))

	p, err := NewFileProvider(dir, nil)
	require.NoError(t, err)
	defer p.Close()
	assert.Nil(t, p.Lookup(pub), "symlinked psk file must be skipped")
}

func TestFileProvider_RejectsMissingDir(t *testing.T) {
	_, err := NewFileProvider(filepath.Join(t.TempDir(), "nope"), nil)
	require.Error(t, err)
}

func TestFileProviderRejectsSymlinkSubstitution(t *testing.T) {
	// A static symlink in the dir whose name is a valid sha256-hex
	// stem must be rejected, not silently followed. Closes the
	// Lstat->ReadFile TOCTOU class noted in audit round 5.
	dir := t.TempDir()
	target := filepath.Join(dir, "..", "secret-32-bytes")
	require.NoError(t, os.WriteFile(target, bytes.Repeat([]byte{0xDE}, 32), 0o600))
	t.Cleanup(func() { _ = os.Remove(target) })

	hexStem := strings.Repeat("ab", 32)
	linkPath := filepath.Join(dir, hexStem+".psk")
	require.NoError(t, os.Symlink(target, linkPath))

	p, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	m := p.entries.Load()
	require.NotNil(t, m)
	_, present := (*m)[hexStem]
	require.False(t, present, "symlinked psk file must be rejected")
}

// TestFileProviderReadsRPInfoCompanion verifies that a valid
// "<stem>.rpinfo" companion file makes LookupRPHash return the
// hash from the file, while Lookup keeps returning the PSK bytes.
func TestFileProviderReadsRPInfoCompanion(t *testing.T) {
	dir := t.TempDir()

	// Construct a peer pubkey deterministically, then derive the
	// filename stem from sha256(pub). This is the same convention
	// pubKeyHashFile uses; spelled out here because the test also
	// needs to write the companion file at the matching stem.
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0xAA
	}
	pubSum := sha256.Sum256(pub)
	stem := hex.EncodeToString(pubSum[:])

	rpHash := strings.Repeat("cd", 32)
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".psk"), bytes32(0x11), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".rpinfo"), []byte(rpHash+"\n"), 0o600))

	p, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	assert.Equal(t, bytes32(0x11), p.Lookup(pub))
	assert.Equal(t, rpHash, p.LookupRPHash(pub))
}

// TestFileProviderRPInfoAbsent verifies that a PSK file with no
// companion still loads, and LookupRPHash returns "" — empty is the
// documented "no binding info" signal.
func TestFileProviderRPInfoAbsent(t *testing.T) {
	dir := t.TempDir()
	pub := pubKeyHashFile(t, dir, 0xBB, bytes32(0x22))

	p, err := NewFileProvider(dir, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	assert.Equal(t, bytes32(0x22), p.Lookup(pub))
	assert.Equal(t, "", p.LookupRPHash(pub))
}

// TestFileProviderRPInfoMalformed covers all rejection paths: wrong
// length, uppercase, non-hex content, and oversize. None of these
// must prevent the PSK from loading; the rpHash just stays empty.
func TestFileProviderRPInfoMalformed(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
	}{
		{"short", []byte("deadbeef\n")},
		{"long", []byte(strings.Repeat("a", 70))},
		{"uppercase", []byte(strings.ToUpper(strings.Repeat("ab", 32)) + "\n")},
		{"non-hex", []byte(strings.Repeat("zz", 32) + "\n")},
		{"oversize", bytes.Repeat([]byte("a"), bindingHintMaxBytes+8)},
		{"empty", []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pub := make([]byte, 32)
			for i := range pub {
				pub[i] = 0xCC
			}
			pubSum := sha256.Sum256(pub)
			stem := hex.EncodeToString(pubSum[:])

			require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".psk"), bytes32(0x33), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".rpinfo"), tc.content, 0o600))

			p, err := NewFileProvider(dir, slog.Default())
			require.NoError(t, err)
			t.Cleanup(func() { _ = p.Close() })

			assert.Equal(t, bytes32(0x33), p.Lookup(pub), "PSK must still load when .rpinfo is malformed")
			assert.Equal(t, "", p.LookupRPHash(pub), "malformed .rpinfo must result in empty rpHash")
		})
	}
}

// TestFileProviderRPInfoSymlinkRejected verifies the O_NOFOLLOW
// discipline applies to .rpinfo too: a symlink that resolves to a
// well-formed 64-hex file outside the watched dir must not influence
// the loaded rpHash, mirroring the existing PSK symlink protection.
func TestFileProviderRPInfoSymlinkRejected(t *testing.T) {
	dir := t.TempDir()

	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0xDD
	}
	pubSum := sha256.Sum256(pub)
	stem := hex.EncodeToString(pubSum[:])
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".psk"), bytes32(0x44), 0o600))

	// Realistic-looking content at the symlink target; the test must
	// pass *because of O_NOFOLLOW*, not because content was bad.
	target := filepath.Join(t.TempDir(), "evil-rpinfo")
	require.NoError(t, os.WriteFile(target, []byte(strings.Repeat("ee", 32)+"\n"), 0o600))

	link := filepath.Join(dir, stem+".rpinfo")
	require.NoError(t, os.Symlink(target, link))

	p, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	assert.Equal(t, bytes32(0x44), p.Lookup(pub))
	assert.Equal(t, "", p.LookupRPHash(pub), "symlinked .rpinfo must not be followed")
}

// TestFileProviderRPInfoFixedBuffer is a regression guard for the
// stat-time-buffer bug: the loader used to allocate buf = make([]byte,
// fi.Size()), which silently truncated reads if a writer grew the file
// between fd.Stat() and io.ReadFull. The fix decouples the buffer size
// from fi.Size(), allocating up to bindingHintMaxBytes and trusting the read
// to surface ErrUnexpectedEOF / EOF semantics.
//
// We can't deterministically reproduce the grow-during-read race
// without injecting an io.Reader, so this test settles for verifying
// the canonical 64-hex-plus-newline shape still loads correctly under
// the rewritten code path. It's the cheapest signal that the rewrite
// didn't accidentally regress the happy path.
func TestFileProviderRPInfoFixedBuffer(t *testing.T) {
	dir := t.TempDir()

	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0xEF
	}
	pubSum := sha256.Sum256(pub)
	stem := hex.EncodeToString(pubSum[:])

	rpHash := strings.Repeat("9a", 32)
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".psk"), bytes32(0x55), 0o600))
	// Trailing newline is the realistic sidecar-emitted form; the
	// fixed-size buffer + io.ReadFull path must still trim it cleanly.
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".rpinfo"), []byte(rpHash+"\n"), 0o600))

	p, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	assert.Equal(t, bytes32(0x55), p.Lookup(pub))
	assert.Equal(t, rpHash, p.LookupRPHash(pub), "fixed-size buffer must still resolve the canonical 64-hex form")
}

func TestFileProvider_AcceptsBase64PSK(t *testing.T) {
	// rosenpass's `key_out` writes base64-encoded PSK files (44
	// chars + optional newline) because its primary downstream is
	// WireGuard's PSK slot which takes base64. nebula's FileProvider
	// must auto-accept this format alongside its native raw-32-byte
	// format to support sidecar deployments without an adapter
	// script in the operator's provisioning pipeline.
	dir := t.TempDir()
	pub := bytes32(0xAA)
	psk := bytes32(0x77)
	encoded := base64.StdEncoding.EncodeToString(psk) + "\n" // 45 bytes incl newline

	sum := sha256.Sum256(pub)
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".psk")
	require.NoError(t, os.WriteFile(path, []byte(encoded), 0o600))

	p, err := NewFileProvider(dir, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	assert.Equal(t, psk, p.Lookup(pub), "base64-encoded PSK file must decode to raw 32 bytes")
}

func TestFileProvider_RejectsBadBase64PSK(t *testing.T) {
	dir := t.TempDir()
	pub := bytes32(0xBB)
	// 44 chars but not valid base64 of 32 bytes (random chars).
	bad := "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@="
	sum := sha256.Sum256(pub)
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".psk")
	require.NoError(t, os.WriteFile(path, []byte(bad), 0o600))

	p, err := NewFileProvider(dir, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	assert.Nil(t, p.Lookup(pub), "garbage 44-byte file must not load as PSK")
}

// D4: removing the watched directory out from under the provider must
//   - retain the last-known PSK snapshot (stale PSKs are valid material),
//   - fire an escalating Error + the watch_lost / rescan_failed metrics,
//   - and self-heal (re-Add the watch + rescan) once the dir reappears.
func TestFileProvider_WatchedDirRemovedSelfHeals(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "psk")
	require.NoError(t, os.Mkdir(dir, 0o700))

	pskA := bytes32(0x11)
	pubA := pubKeyHashFile(t, dir, 0xAA, pskA)

	var logbuf syncBuffer
	logger := slog.New(slog.NewTextHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	wlBefore := metrics.GetOrRegisterCounter(MetricFileWatchLost, nil).Count()
	rfBefore := metrics.GetOrRegisterCounter(MetricFileRescanFailed, nil).Count()

	// Fast health ticker so the self-heal loop runs many times within
	// the test window.
	cfg := FileProviderConfig{
		Dir:      dir,
		Debounce: 20 * time.Millisecond,
		Health:   50 * time.Millisecond,
		Logger:   logger,
	}
	p, err := NewFileProviderWithConfig(cfg)
	require.NoError(t, err)
	defer p.Close()

	require.Equal(t, pskA, p.Lookup(pubA), "PSK must load before dir removal")

	// Remove the entire watched directory.
	require.NoError(t, os.RemoveAll(dir))

	// The snapshot must keep serving the last-known PSK — never cleared.
	// Give the run loop time to process the Remove event + several
	// health ticks (which rescan-fail while the dir is gone).
	require.Eventually(t, func() bool {
		out := logbuf.String()
		return strings.Contains(out, "watch lost") &&
			metrics.GetOrRegisterCounter(MetricFileWatchLost, nil).Count() > wlBefore
	}, 3*time.Second, 25*time.Millisecond, "watch_lost log+metric must fire on dir removal; log=%q", logbuf.String())

	// Snapshot retained throughout.
	assert.Equal(t, pskA, p.Lookup(pubA), "stale snapshot must survive dir removal")

	// Repeated rescan failures must bump the rescan_failed metric and
	// escalate to Error.
	require.Eventually(t, func() bool {
		return metrics.GetOrRegisterCounter(MetricFileRescanFailed, nil).Count() > rfBefore &&
			strings.Contains(logbuf.String(), "level=ERROR")
	}, 3*time.Second, 25*time.Millisecond, "rescan_failed metric + escalating Error expected; log=%q", logbuf.String())

	// Self-heal: recreate the dir with a different PSK; the provider must
	// re-Add the watch and pick up the new content without restart.
	require.NoError(t, os.Mkdir(dir, 0o700))
	pskB := bytes32(0x22)
	pubB := pubKeyHashFile(t, dir, 0xBB, pskB)

	require.Eventually(t, func() bool {
		return bytes.Equal(p.Lookup(pubB), pskB)
	}, 5*time.Second, 50*time.Millisecond, "provider must self-heal and load PSK dropped after dir reappeared; log=%q", logbuf.String())

	assert.Contains(t, logbuf.String(), "watch re-established",
		"recovery must be logged; got %q", logbuf.String())
}

func TestFileProvider_PreviousEpochRetention(t *testing.T) {
	dir := t.TempDir()
	peer := bytes32(0xAA)
	sum := sha256.Sum256(peer)
	stem := hex.EncodeToString(sum[:])
	pskA := bytes32(0x01)
	pskB := bytes32(0x02)
	pskC := bytes32(0x03)

	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), pskA, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewFileProvider(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Epoch 1: no previous yet.
	if _, _, ok := p.LookupPreviousWithBinding(peer); ok {
		t.Fatal("expected no previous epoch after initial scan")
	}

	// Rotate to B: A becomes previous.
	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), pskB, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.rescan(); err != nil {
		t.Fatal(err)
	}
	prev, _, ok := p.LookupPreviousWithBinding(peer)
	if !ok || !bytes.Equal(prev, pskA) {
		t.Fatalf("previous = %x ok=%v, want %x", prev, ok, pskA)
	}
	if cur := p.Lookup(peer); !bytes.Equal(cur, pskB) {
		t.Fatalf("current = %x, want %x", cur, pskB)
	}

	// No-op rescan must NOT shift epochs.
	if err := p.rescan(); err != nil {
		t.Fatal(err)
	}
	prev, _, ok = p.LookupPreviousWithBinding(peer)
	if !ok || !bytes.Equal(prev, pskA) {
		t.Fatal("no-op rescan must keep previous epoch")
	}

	// Rotate to C: B becomes previous, A gone (window of 2).
	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), pskC, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.rescan(); err != nil {
		t.Fatal(err)
	}
	prev, _, _ = p.LookupPreviousWithBinding(peer)
	if !bytes.Equal(prev, pskB) {
		t.Fatalf("previous = %x, want %x", prev, pskB)
	}

	// Peer file removed entirely: both epochs drop (peer removed != rotation).
	if err := os.Remove(filepath.Join(dir, stem+".psk")); err != nil {
		t.Fatal(err)
	}
	if err := p.rescan(); err != nil {
		t.Fatal(err)
	}
	if p.Lookup(peer) != nil {
		t.Fatal("current must drop on file removal")
	}
	if _, _, ok := p.LookupPreviousWithBinding(peer); ok {
		t.Fatal("previous must drop on file removal")
	}
}

func TestFileProvider_PreviousEpochKeepsItsBindingHint(t *testing.T) {
	dir := t.TempDir()
	peer := bytes32(0xBB)
	sum := sha256.Sum256(peer)
	stem := hex.EncodeToString(sum[:])
	hashOld := strings.Repeat("aa", 32)
	hashNew := strings.Repeat("bb", 32)

	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), bytes32(0x01), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stem+".rpinfo"), []byte(hashOld+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewFileProvider(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), bytes32(0x02), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stem+".rpinfo"), []byte(hashNew+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.rescan(); err != nil {
		t.Fatal(err)
	}
	_, rpHash, ok := p.LookupPreviousWithBinding(peer)
	if !ok || rpHash != hashOld {
		t.Fatalf("previous rpHash = %q, want %q (the OLD epoch's hint)", rpHash, hashOld)
	}
	_, rpHash, _ = p.LookupWithBinding(peer)
	if rpHash != hashNew {
		t.Fatalf("current rpHash = %q, want %q", rpHash, hashNew)
	}
}

func TestFileProvider_PreviousEpochRetention_Base64(t *testing.T) {
	dir := t.TempDir()
	peer := bytes32(0xAB)
	sum := sha256.Sum256(peer)
	stem := hex.EncodeToString(sum[:])
	rawA := bytes32(0x11)
	rawB := bytes32(0x22)
	b64 := func(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(b) + "\n") }

	// write base64-encoded PSK (rosenpass key_out format)
	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), b64(rawA), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewFileProvider(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Epoch 1: current == rawA, no previous yet.
	if cur := p.Lookup(peer); !bytes.Equal(cur, rawA) {
		t.Fatalf("initial current = %x, want %x", cur, rawA)
	}
	if _, _, ok := p.LookupPreviousWithBinding(peer); ok {
		t.Fatal("expected no previous epoch after initial scan")
	}

	// rotate: replace with base64(rawB) — rawA becomes previous
	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), b64(rawB), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.rescan(); err != nil {
		t.Fatal(err)
	}

	if cur := p.Lookup(peer); !bytes.Equal(cur, rawB) {
		t.Fatalf("current after rotate = %x, want %x", cur, rawB)
	}
	prev, _, ok := p.LookupPreviousWithBinding(peer)
	if !ok || !bytes.Equal(prev, rawA) {
		t.Fatalf("previous after rotate = %x ok=%v, want %x", prev, ok, rawA)
	}
}

func TestFileProviderStatus(t *testing.T) {
	dir := t.TempDir()
	peer := bytes32(0xEE)
	sum := sha256.Sum256(peer)
	stem := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), bytes32(0x01), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewFileProvider(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// Write a new PSK so the first becomes the previous epoch.
	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), bytes32(0x02), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.rescan(); err != nil {
		t.Fatal(err)
	}
	sts := Status(p)
	if len(sts) != 1 || sts[0].Kind != "file" || len(sts[0].Peers) != 1 {
		t.Fatalf("unexpected status shape: %+v", sts)
	}
	pe := sts[0].Peers[0]
	if pe.PeerKeyHash != stem || !pe.HasPSK || !pe.HasPrev {
		t.Fatalf("unexpected peer status: %+v", pe)
	}
}

func bytes32(v byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = v
	}
	return out
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestSnapshotsEqual(t *testing.T) {
	a := map[string]fileEntry{"k1": {psk: bytes32(0x01), rpHash: "aa"}}
	same := map[string]fileEntry{"k1": {psk: bytes32(0x01), rpHash: "aa"}}
	diffPSK := map[string]fileEntry{"k1": {psk: bytes32(0x02), rpHash: "aa"}}
	diffHash := map[string]fileEntry{"k1": {psk: bytes32(0x01), rpHash: "bb"}}
	diffKey := map[string]fileEntry{"k2": {psk: bytes32(0x01), rpHash: "aa"}}
	extra := map[string]fileEntry{
		"k1": {psk: bytes32(0x01), rpHash: "aa"},
		"k2": {psk: bytes32(0x02)},
	}

	assert.True(t, snapshotsEqual(a, same))
	assert.True(t, snapshotsEqual(map[string]fileEntry{}, map[string]fileEntry{}))
	assert.False(t, snapshotsEqual(a, diffPSK))
	assert.False(t, snapshotsEqual(a, diffHash))
	assert.False(t, snapshotsEqual(a, diffKey))
	assert.False(t, snapshotsEqual(a, extra))
}

func TestFileProvider_LastChangeOnlyAdvancesOnContentChange(t *testing.T) {
	dir := t.TempDir()
	pubA := pubKeyHashFile(t, dir, 0xAA, bytes32(0x11))

	p, err := NewFileProvider(dir, nil)
	require.NoError(t, err)
	defer p.Close()
	require.NotNil(t, p.Lookup(pubA))

	t0 := p.lastChange.Load()
	require.NotZero(t, t0, "initial scan must set lastChange")

	// Identical-content rescan (the health-tick path) must NOT advance
	// lastChange, or a dead rotator would never look stale.
	require.NoError(t, p.rescan())
	assert.Equal(t, t0, p.lastChange.Load(), "no-op rescan advanced lastChange")

	// A real rotation must advance it.
	time.Sleep(2 * time.Millisecond) // ensure UnixNano strictly increases
	pubKeyHashFile(t, dir, 0xAA, bytes32(0x22))
	require.NoError(t, p.rescan())
	assert.Greater(t, p.lastChange.Load(), t0, "content change did not advance lastChange")
}

func TestFileProvider_CheckStale(t *testing.T) {
	dir := t.TempDir()
	pubKeyHashFile(t, dir, 0xAA, bytes32(0x11))

	logBuf := &syncBuffer{}
	p, err := NewFileProviderWithConfig(FileProviderConfig{
		Dir:            dir,
		Logger:         slog.New(slog.NewTextHandler(logBuf, nil)),
		StaleWarnAfter: time.Minute,
	})
	require.NoError(t, err)
	defer p.Close()

	base := time.Unix(0, p.lastChange.Load())
	var warned bool

	// Fresh: under threshold, no warning.
	p.checkStale(base.Add(30*time.Second), &warned)
	assert.False(t, warned)
	assert.NotContains(t, logBuf.String(), "staleness threshold")

	// Crossing the threshold warns exactly once per episode.
	p.checkStale(base.Add(2*time.Minute), &warned)
	assert.True(t, warned)
	assert.Contains(t, logBuf.String(), "staleness threshold")
	before := logBuf.String()
	p.checkStale(base.Add(3*time.Minute), &warned)
	assert.Equal(t, before, logBuf.String(), "stale warning must not repeat within an episode")

	// Fresh material resets the episode and logs recovery.
	pubKeyHashFile(t, dir, 0xAA, bytes32(0x22))
	require.NoError(t, p.rescan())
	p.checkStale(time.Unix(0, p.lastChange.Load()).Add(time.Second), &warned)
	assert.False(t, warned)
	assert.Contains(t, logBuf.String(), "rotation resumed")
}

func TestFileProvider_CheckStaleDisabledOrEmpty(t *testing.T) {
	// Knob unset: never warns no matter the age.
	dir := t.TempDir()
	pubKeyHashFile(t, dir, 0xAA, bytes32(0x11))
	logBuf := &syncBuffer{}
	p, err := NewFileProviderWithConfig(FileProviderConfig{
		Dir:    dir,
		Logger: slog.New(slog.NewTextHandler(logBuf, nil)),
	})
	require.NoError(t, err)
	defer p.Close()
	var warned bool
	p.checkStale(time.Unix(0, p.lastChange.Load()).Add(24*time.Hour), &warned)
	assert.False(t, warned)
	assert.NotContains(t, logBuf.String(), "staleness threshold")

	// Empty dir: provisioning state, not a dead rotator — no warning
	// even with the knob set.
	emptyDir := t.TempDir()
	logBuf2 := &syncBuffer{}
	p2, err := NewFileProviderWithConfig(FileProviderConfig{
		Dir:            emptyDir,
		Logger:         slog.New(slog.NewTextHandler(logBuf2, nil)),
		StaleWarnAfter: time.Minute,
	})
	require.NoError(t, err)
	defer p2.Close()
	var warned2 bool
	p2.checkStale(time.Unix(0, p2.lastChange.Load()).Add(24*time.Hour), &warned2)
	assert.False(t, warned2)
	assert.NotContains(t, logBuf2.String(), "staleness threshold")
}
