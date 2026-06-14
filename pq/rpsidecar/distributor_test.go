package rpsidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/pq/rphttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fetcherStatic returns the supplied body for every fetch, mirroring
// rphttp.FetchPubkey's hash-mismatch error type when the expected hash
// doesn't match.
func fetcherStatic(body []byte) rphttp.Fetcher {
	return func(_ context.Context, _ *net.TCPAddr, expectedHash string, _ *net.Dialer) ([]byte, error) {
		got := hashHex(body)
		if expectedHash != "" && expectedHash != got {
			return nil, rphttp.ErrPubkeyHashMismatch{Expected: expectedHash, Got: got}
		}
		return body, nil
	}
}

func newTestDistributor(t *testing.T, dir string, fetcher rphttp.Fetcher) *Distributor {
	t.Helper()
	d, err := New(Config{
		PubkeyDir:     dir,
		Fetcher:       fetcher,
		DiscoveryPort: 51820,
		FetchRetries:  1,
		FetchTimeout:  200 * time.Millisecond,
	})
	require.NoError(t, err)
	d.Start()
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// TestDistributor_WritesFile pins the core happy path: a Notify with
// a hash-bound peer cert results in <fingerprint>.pub appearing in
// the configured directory with the exact pubkey bytes.
func TestDistributor_WritesFile(t *testing.T) {
	dir := t.TempDir()
	body := []byte("fake-rosenpass-pubkey-bytes")
	d := newTestDistributor(t, dir, fetcherStatic(body))

	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.42"),
		PeerStaticPubKey:   []byte("peer-static-key-32-bytes-aaaaaaa"),
		Fingerprint:        "fp-1",
		ExpectedPubkeyHash: hashHex(body),
	}
	d.Notify(ev)

	dst := filepath.Join(dir, "fp-1.pub")
	require.Eventually(t, func() bool {
		_, err := os.Stat(dst)
		return err == nil
	}, 2*time.Second, 10*time.Millisecond, "pubkey file did not appear")

	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, body, got)
}

// TestDistributor_AtomicWrite pins that the file is replaced
// atomically — a concurrent reader sees either the old contents or
// the new, never a partial write or empty file. We approximate this
// by writing twice and ensuring no .tmp leak persists.
func TestDistributor_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	body1 := []byte("first-pubkey")
	body2 := []byte("second-pubkey-longer")

	// Prepopulate the destination so the rename overwrites a real file.
	dst := filepath.Join(dir, "fp-1.pub")
	require.NoError(t, os.WriteFile(dst, body1, 0o644))

	d := newTestDistributor(t, dir, fetcherStatic(body2))

	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.42"),
		PeerStaticPubKey:   []byte("peer-static-key-32-bytes-bbbbbbb"),
		Fingerprint:        "fp-1",
		ExpectedPubkeyHash: hashHex(body2),
	}
	d.Notify(ev)

	require.Eventually(t, func() bool {
		got, err := os.ReadFile(dst)
		return err == nil && string(got) == string(body2)
	}, 2*time.Second, 10*time.Millisecond, "file was not replaced with new contents")

	// No .tmp files should remain on a successful write.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".rppub-"),
			"leftover tmp file: %s", e.Name())
	}
}

// TestDistributor_RefusesMissingExtension pins down the trust anchor:
// if the peer's cert lacks the rosenpassPubKeySha256 extension
// (ExpectedPubkeyHash == ""), the distributor must refuse and not
// touch the filesystem.
func TestDistributor_RefusesMissingExtension(t *testing.T) {
	dir := t.TempDir()
	body := []byte("pubkey-bytes")
	d := newTestDistributor(t, dir, fetcherStatic(body))

	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.42"),
		PeerStaticPubKey:   []byte("peer-static-key-32-bytes-ccccccc"),
		Fingerprint:        "fp-no-ext",
		ExpectedPubkeyHash: "", // empty -> refuse
	}
	d.Notify(ev)

	// Give the goroutine time to attempt + fail.
	time.Sleep(200 * time.Millisecond)
	_, err := os.Stat(filepath.Join(dir, "fp-no-ext.pub"))
	assert.True(t, os.IsNotExist(err), "file should not have been written")
}

// TestDistributor_RefusesHashMismatch pins that even if the fetcher
// returns bytes, a hash mismatch against the cert-bound expected hash
// is rejected and no file is written.
func TestDistributor_RefusesHashMismatch(t *testing.T) {
	dir := t.TempDir()
	body := []byte("actual-bytes")
	d := newTestDistributor(t, dir, fetcherStatic(body))

	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.42"),
		PeerStaticPubKey:   []byte("peer-static-key-32-bytes-ddddddd"),
		Fingerprint:        "fp-mismatch",
		ExpectedPubkeyHash: "deadbeef" + strings.Repeat("0", 56), // 64-hex but wrong
	}
	d.Notify(ev)

	time.Sleep(300 * time.Millisecond)
	_, err := os.Stat(filepath.Join(dir, "fp-mismatch.pub"))
	assert.True(t, os.IsNotExist(err), "file should not have been written on hash mismatch")
}

// TestDistributor_HashOnlyMode (PubkeyDir == "") pins that the
// distributor still verifies the fetch but writes nothing — useful
// for deployments that only want the trust-binding signal.
func TestDistributor_HashOnlyMode(t *testing.T) {
	body := []byte("verified-only-pubkey")
	fetched := make(chan struct{}, 1)
	fetcher := rphttp.Fetcher(func(_ context.Context, _ *net.TCPAddr, _ string, _ *net.Dialer) ([]byte, error) {
		select {
		case fetched <- struct{}{}:
		default:
		}
		return body, nil
	})
	d, err := New(Config{
		Fetcher:      fetcher,
		FetchRetries: 1,
		FetchTimeout: 200 * time.Millisecond,
	})
	require.NoError(t, err)
	d.Start()
	defer d.Close()

	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.42"),
		PeerStaticPubKey:   []byte("peer-static-key-32-bytes-eeeeeee"),
		Fingerprint:        "fp-hashonly",
		ExpectedPubkeyHash: hashHex(body),
	}
	d.Notify(ev)

	select {
	case <-fetched:
	case <-time.After(2 * time.Second):
		t.Fatal("fetcher was not called")
	}
	// Nothing else to assert: file-write is disabled.
}

// TestDistributor_InflightDedup mirrors the Coordinator's dedup
// guarantee: while a fetch is in flight for a peer, further Notify
// events for that peer queue (single-slot pending) instead of
// spawning additional goroutines.
func TestDistributor_InflightDedup(t *testing.T) {
	dir := t.TempDir()
	body := []byte("dedup-test-pubkey")
	gate := make(chan struct{})
	fetcherStarted := make(chan struct{}, 1)
	var fetchMu sync.Mutex
	var fetchCount int
	fetcher := rphttp.Fetcher(func(ctx context.Context, _ *net.TCPAddr, expectedHash string, _ *net.Dialer) ([]byte, error) {
		fetchMu.Lock()
		fetchCount++
		isFirst := fetchCount == 1
		fetchMu.Unlock()
		if isFirst {
			select {
			case fetcherStarted <- struct{}{}:
			default:
			}
			select {
			case <-gate:
			case <-ctx.Done():
			}
		}
		got := hashHex(body)
		if expectedHash != "" && expectedHash != got {
			return nil, rphttp.ErrPubkeyHashMismatch{Expected: expectedHash, Got: got}
		}
		return body, nil
	})
	d := newTestDistributor(t, dir, fetcher)

	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.42"),
		PeerStaticPubKey:   []byte("peer-static-key-32-bytes-fffffff"),
		Fingerprint:        "fp-dedup",
		ExpectedPubkeyHash: hashHex(body),
	}

	d.Notify(ev)
	<-fetcherStarted
	// Pile on while the first fetch is blocked. Only one of these
	// should result in a second fetch after the gate releases.
	for i := 0; i < 20; i++ {
		d.Notify(ev)
	}
	close(gate)

	require.Eventually(t, func() bool {
		fetchMu.Lock()
		defer fetchMu.Unlock()
		return fetchCount == 2 // first + one replay
	}, 2*time.Second, 20*time.Millisecond,
		"expected exactly 2 fetches (first + pending-replay), got different")
}

// TestDistributor_RejectsMissingDir surfaces config errors at New().
func TestDistributor_RejectsMissingDir(t *testing.T) {
	_, err := New(Config{
		PubkeyDir: "/nonexistent/path/that/should/not/exist",
		Fetcher:   fetcherStatic([]byte{}),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "stat"),
		"expected stat / not-exist error, got: %v", err)
}

// TestDistributor_NotifyAfterClose is a smoke test that Notify is
// safe to call after Close — it should drop the event silently
// rather than panic on the closed context.
func TestDistributor_NotifyAfterClose(t *testing.T) {
	dir := t.TempDir()
	d := newTestDistributor(t, dir, fetcherStatic([]byte("x")))
	require.NoError(t, d.Close())

	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.42"),
		PeerStaticPubKey:   []byte("post-close"),
		Fingerprint:        "fp-late",
		ExpectedPubkeyHash: hashHex([]byte("x")),
	}
	// Should not panic.
	d.Notify(ev)
}
