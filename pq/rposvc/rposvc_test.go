//go:build rosenpass_embedded

package rposvc

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	rp "cunicu.li/go-rosenpass"
	"github.com/rcrowley/go-metrics"

	"github.com/slackhq/nebula/pq"
	"github.com/stretchr/testify/require"
)

// counterVal reads the current value of a default-registry counter by
// name. Used to assert the new observability metrics fired (or didn't).
func counterVal(name string) int64 {
	return metrics.GetOrRegisterCounter(name, nil).Count()
}

func TestServiceClosePreStartDoesNotDeadlock(t *testing.T) {
	tmp := t.TempDir()
	svc, err := New(Config{
		StateDir:       tmp,
		ListenAddr:     &net.UDPAddr{IP: net.IPv4zero, Port: 0},
		MemoryProvider: pq.NewMemoryProvider(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = svc.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() blocked >2s pre-Start (deadlock)")
	}
}

// TestService_AddPeerRefreshesEndpoint pins down the Prod-1 fix-A
// contract: Service.AddPeer must NOT be sticky on the cached
// endpoint. When called for an already-registered peer with a
// different endpoint (the gossip-arrived-late path), the prior rp
// peer registration is dropped and a fresh one is installed pointing
// at the new endpoint. Without this, the Coordinator's first AddPeer
// (using cfg.RosenpassPort fallback) would pin the rosenpass server
// to the wrong UDP destination for the lifetime of the tunnel and
// ix_psk2 would never complete.
//
// Idempotence for the steady-state path (identical args) is also
// pinned: that case must remain a no-op so the dedup in the
// Coordinator continues to work.
func TestService_AddPeerRefreshesEndpoint(t *testing.T) {
	tmp := t.TempDir()
	svc, err := New(Config{
		StateDir:       tmp,
		ListenAddr:     &net.UDPAddr{IP: net.IPv4zero, Port: 0},
		MemoryProvider: pq.NewMemoryProvider(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	// A real rosenpass pubkey for the "peer" side. We need a real
	// keypair because the underlying rp.Server tries to initiate a
	// handshake on AddPeer; with a malformed pubkey it would either
	// reject or panic depending on go-rosenpass internals. The send
	// itself will fail (no UDP listener at the endpoint) but that
	// path just logs — the registration state on our Service side
	// is what we're asserting against.
	peerRPPub, _, err := rp.GenerateKeyPair()
	require.NoError(t, err)
	peerStatic := []byte("peer-static-key-32-bytes-zzzzzzz")

	ep1 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 42), Port: 51823}
	require.NoError(t, svc.AddPeer(peerStatic, peerRPPub, ep1))
	// Snapshot the rp.PeerID we recorded for this peer.
	svc.mu.Lock()
	pid1, ok := svc.peers[hexFingerprint(peerStatic)]
	svc.mu.Unlock()
	require.True(t, ok, "AddPeer did not record peer in s.peers")

	// Same args -> true no-op. PeerID stays stable, endpoint cache
	// unchanged.
	require.NoError(t, svc.AddPeer(peerStatic, peerRPPub, ep1))
	svc.mu.Lock()
	pid1b, ok := svc.peers[hexFingerprint(peerStatic)]
	endKey1 := svc.peerEnd[pid1b]
	svc.mu.Unlock()
	require.True(t, ok)
	require.Equal(t, pid1, pid1b, "identical-args AddPeer must not re-register (PeerID drift = duplicate registration bug)")
	require.Equal(t, udpAddrKeyFromAddr(ep1), endKey1)

	// Endpoint changes (gossip arrived with a new port) -> must
	// re-register. Same pubkey, but the rp.Server gets a fresh
	// AddPeer call so handshakes start driving toward the new port.
	ep2 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 42), Port: 51824}
	require.NoError(t, svc.AddPeer(peerStatic, peerRPPub, ep2))
	svc.mu.Lock()
	pid2, ok := svc.peers[hexFingerprint(peerStatic)]
	endKey2 := svc.peerEnd[pid2]
	// The old rp.PeerID for ep1 must be gone from our caches even
	// though rp.PeerID is a deterministic hash of the pubkey (so
	// pid1 == pid2 in this test — that's fine, what matters is the
	// endpoint map is fresh and the rp.Server was kicked).
	svc.mu.Unlock()
	require.True(t, ok)
	require.Equal(t, udpAddrKeyFromAddr(ep2), endKey2,
		"endpoint cache must reflect the new endpoint after re-registration")

	// Pubkey change (peer rotated rosenpass keys) -> also re-
	// registers. Tests the other half of the change-detection path.
	peerRPPub2, _, err := rp.GenerateKeyPair()
	require.NoError(t, err)
	require.NoError(t, svc.AddPeer(peerStatic, peerRPPub2, ep2))
	svc.mu.Lock()
	pid3, ok := svc.peers[hexFingerprint(peerStatic)]
	pubKey3 := svc.peerRP[pid3]
	svc.mu.Unlock()
	require.True(t, ok)
	require.Equal(t, []byte(peerRPPub2), pubKey3,
		"pubkey cache must reflect the rotated rosenpass pubkey")
}

// TestService_DoneErrSurface pins the C1 exported surface: Done()
// returns a channel that closes when the run loop exits, and Err()
// reports the exit error. Pre-Start the channel must NOT be closed
// (nothing has run yet); after Close it must close cleanly with a nil
// Err (clean shutdown, not a death).
func TestService_DoneErrSurface(t *testing.T) {
	tmp := t.TempDir()
	svc, err := New(Config{
		StateDir:       tmp,
		ListenAddr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		MemoryProvider: pq.NewMemoryProvider(),
	})
	require.NoError(t, err)

	// Pre-Start: Done must be open and Err nil.
	select {
	case <-svc.Done():
		t.Fatal("Done() closed before Start/Close")
	default:
	}
	require.NoError(t, svc.Err())

	svc.Start()
	require.NoError(t, svc.Close())

	// After a clean Close, Done is closed and Err reports no error:
	// Close cancels the run loop's ctx, so the exit is expected and
	// must NOT be surfaced as a death.
	select {
	case <-svc.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done() did not close after Close()")
	}
	require.NoError(t, svc.Err(), "clean Close must not record a run error")
}

// TestLoadOrGenerateKeypair_TruncatedFiles pins C3: a both-present but
// length-invalid keypair (truncated mid-write) must NOT load as a
// success. It bumps keypair_load_failed and, with no cert binding and
// non-strict, falls through to generation (which itself bumps
// keypair_generated). The returned keypair must be the freshly
// generated, correctly-sized one.
func TestLoadOrGenerateKeypair_TruncatedFiles(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "rp.pub"), []byte("too-short"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "rp.sk"), []byte("also-short"), 0o600))

	loadFailBefore := counterVal(metricKeypairLoadFailed)
	genBefore := counterVal(metricKeypairGenerated)

	pub, sec, err := loadOrGenerateKeypair(tmp, testLogger(), false /*certHasBinding*/, false /*strict*/)
	require.NoError(t, err, "non-strict truncated keypair must fall through to generation, not error")
	require.Len(t, []byte(pub), rpPublicKeySize, "regenerated pubkey must be full length")
	require.True(t, validRPSecretKeyLen(len(sec)), "regenerated secret key must be a valid length")

	require.Equal(t, loadFailBefore+1, counterVal(metricKeypairLoadFailed),
		"truncated keyfile must bump keypair_load_failed")
	require.Equal(t, genBefore+1, counterVal(metricKeypairGenerated),
		"falling through to generation must bump keypair_generated")
}

// TestLoadOrGenerateKeypair_TruncatedFiles_Strict pins the strict
// opt-in: with strict_identity set, a truncated keyfile is a hard
// error instead of a silent regenerate.
func TestLoadOrGenerateKeypair_TruncatedFiles_Strict(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "rp.pub"), []byte("too-short"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "rp.sk"), []byte("also-short"), 0o600))

	_, _, err := loadOrGenerateKeypair(tmp, testLogger(), false, true /*strict*/)
	require.Error(t, err, "strict_identity must refuse a truncated keypair")
}

// TestLoadOrGenerateKeypair_DangerousRegen pins the issue-#6 detection:
// both files absent (wiped state_dir) WHILE the node's cert already
// binds a PQ identity (certHasBinding=true) is the dangerous regen. It
// must bump keypair_regen_danger and, by default, still generate
// (fresh keypair returned, node keeps running). Under strict it must
// refuse.
func TestLoadOrGenerateKeypair_DangerousRegen(t *testing.T) {
	tmp := t.TempDir() // empty: both files absent

	dangerBefore := counterVal(metricKeypairRegenDanger)
	genBefore := counterVal(metricKeypairGenerated)

	pub, sec, err := loadOrGenerateKeypair(tmp, testLogger(), true /*certHasBinding*/, false /*strict*/)
	require.NoError(t, err, "default behaviour must still generate so fresh nodes work; degrade is handled by the loud log + identity-mismatch check")
	require.Len(t, []byte(pub), rpPublicKeySize)
	require.True(t, validRPSecretKeyLen(len(sec)))

	require.Equal(t, dangerBefore+1, counterVal(metricKeypairRegenDanger),
		"regen-with-cert-binding must bump keypair_regen_danger")
	require.Equal(t, genBefore+1, counterVal(metricKeypairGenerated))

	// Strict variant: a fresh empty dir + cert binding must refuse.
	tmp2 := t.TempDir()
	_, _, err = loadOrGenerateKeypair(tmp2, testLogger(), true, true /*strict*/)
	require.Error(t, err, "strict_identity must refuse the dangerous regen")
}

// TestLoadOrGenerateKeypair_FreshNodeSilent pins the normal path: both
// files absent and NO cert binding (a genuinely fresh node) generates
// without tripping the dangerous-regen counter.
func TestLoadOrGenerateKeypair_FreshNodeSilent(t *testing.T) {
	tmp := t.TempDir()

	dangerBefore := counterVal(metricKeypairRegenDanger)
	genBefore := counterVal(metricKeypairGenerated)

	pub, sec, err := loadOrGenerateKeypair(tmp, testLogger(), false /*certHasBinding*/, false)
	require.NoError(t, err)
	require.Len(t, []byte(pub), rpPublicKeySize)
	require.True(t, validRPSecretKeyLen(len(sec)))

	require.Equal(t, dangerBefore, counterVal(metricKeypairRegenDanger),
		"fresh node (no cert binding) must NOT trip the dangerous-regen counter")
	require.Equal(t, genBefore+1, counterVal(metricKeypairGenerated))
}

// testLogger returns a discard-backed slog logger for tests that don't
// assert on log output.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestWriteAtomicChmodsBeforeWrite(t *testing.T) {
	// After writeAtomic returns, the file must have exactly the
	// requested mode bits. This is a regression guard against
	// future refactors that reintroduce a write-before-chmod
	// window on platforms where CreateTemp doesn't default to 0600.
	dir := t.TempDir()
	path := filepath.Join(dir, "rp.sk")
	require.NoError(t, writeAtomic(path, []byte("super-secret"), 0o600))
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(),
		"writeAtomic must apply mode exactly")
}
