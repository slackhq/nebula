//go:build rosenpass_embedded

package rposvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula/pq/rphttp"
	"github.com/stretchr/testify/require"
)

// fakeService is a ServiceAPI stub that records AddPeer / RemovePeer
// calls. It deliberately does no real work: the Coordinator tests
// only need to observe what the Coordinator did, not what a real
// rosenpass server would have done with it.
type fakeService struct {
	mu        sync.Mutex
	added     map[string][]byte      // hex(peerStatic) -> rosenpassPubKey
	endpoints map[string]*net.UDPAddr // hex(peerStatic) -> endpoint AddPeer was called with
	removed   map[string]int         // hex(peerStatic) -> RemovePeer call count
	addCount  map[string]int         // hex(peerStatic) -> AddPeer call count (counts every invocation, even no-op idempotent ones)
}

func newFakeService() *fakeService {
	return &fakeService{
		added:     map[string][]byte{},
		endpoints: map[string]*net.UDPAddr{},
		removed:   map[string]int{},
		addCount:  map[string]int{},
	}
}

func (f *fakeService) AddPeer(peerStaticPubKey, rosenpassPubKey []byte, endpoint *net.UDPAddr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := hex.EncodeToString(peerStaticPubKey)
	f.addCount[key]++
	f.added[key] = append([]byte(nil), rosenpassPubKey...)
	if endpoint != nil {
		cp := *endpoint
		if endpoint.IP != nil {
			cp.IP = append(net.IP(nil), endpoint.IP...)
		}
		f.endpoints[key] = &cp
	} else {
		f.endpoints[key] = nil
	}
	return nil
}

func (f *fakeService) RemovePeer(peerStaticPubKey []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := hex.EncodeToString(peerStaticPubKey)
	delete(f.added, key)
	f.removed[key]++
}

func (f *fakeService) PublicKey() []byte    { return []byte("fake-pub") }
func (f *fakeService) PublicKeyHex() string { return "fakepub" }

// addedKeys returns the set of currently-registered peers (raw
// peer-static bytes), in deterministic-enough form for length checks.
func (f *fakeService) addedKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.added))
	for k := range f.added {
		keys = append(keys, k)
	}
	return keys
}

func (f *fakeService) addPeerCount(peerStaticPubKey []byte) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addCount[hex.EncodeToString(peerStaticPubKey)]
}

func (f *fakeService) endpointFor(peerStaticPubKey []byte) *net.UDPAddr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.endpoints[hex.EncodeToString(peerStaticPubKey)]
}

// newTestCoordinator builds a Coordinator wired to a fake service +
// stub fetcher. Discovery is required by NewCoordinator but the
// Coordinator never touches it during fetch (FetchPubkey is replaced
// by the injected Fetcher), so a sentinel value is enough.
func newTestCoordinator(t *testing.T, svc ServiceAPI, fetcher rphttp.Fetcher) *Coordinator {
	t.Helper()
	// NewCoordinator requires a non-nil Discovery. We construct a real
	// one bound to a wildcard port; the Coordinator never calls into
	// it during the test because the injected Fetcher short-circuits
	// the discovery client. We still Close it on cleanup so the test
	// doesn't leak the listener.
	disc, err := rphttp.NewDiscovery(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, []byte("placeholder-pubkey"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = disc.Close() })

	coord, err := NewCoordinator(CoordinatorConfig{
		Service:       svc,
		Discovery:     disc,
		Fetcher:       fetcher,
		RosenpassPort: 51821,
		DiscoveryPort: 51820,
		FetchRetries:  1,
		FetchTimeout:  100 * time.Millisecond,
	})
	require.NoError(t, err)
	return coord
}

// TestCoordinatorForgetThenRenotifyReregisters pins down the steady-
// state guarantee that survives the simp-1 simplification: after a
// Forget, a fresh Notify for the same peer must re-drive a fetch and
// re-register the peer.
func TestCoordinatorForgetThenRenotifyReregisters(t *testing.T) {
	body := []byte("fake-rosenpass-pubkey")
	svc := newFakeService()
	coord := newTestCoordinator(t, svc, fetcherStrict(body))
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-aaaaaaa")
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.42"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-1",
		ExpectedPubkeyHash: hashHex(body),
	}

	coord.Notify(ev)
	// Wait for the registration goroutine to finish AND release its
	// in-flight slot. Without checking inflight, the follow-up
	// Notify below could race the goroutine's defer-delete and be
	// dropped by the dedup check.
	require.Eventually(t, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return len(svc.addedKeys()) == 1 && len(coord.inflight) == 0
	}, 2*time.Second, 10*time.Millisecond, "initial Notify did not result in AddPeer + clear inflight")

	coord.Forget(peerStatic)
	require.Eventually(t, func() bool {
		return len(svc.addedKeys()) == 0
	}, 2*time.Second, 10*time.Millisecond, "Forget did not result in RemovePeer")

	coord.Notify(ev)
	require.Eventually(t, func() bool {
		return len(svc.addedKeys()) == 1
	}, 2*time.Second, 10*time.Millisecond, "post-Forget Notify did not re-register peer")
}

// TestCoordinatorInflightDedup pins down the dedup-with-pending
// contract: while a fetch is in flight for peer X, further Notify
// events for X do NOT spawn additional concurrent goroutines —
// instead the latest event is queued and replayed exactly once after
// the in-flight fetch completes. Critical for the gossip-driven
// re-Notify case: HostUpdate may arrive DURING the initial wrong-port
// fetch carrying corrected ports; without the pending-replay path the
// new args would be silently dropped under inflight-dedup and the
// Coordinator would stay pinned to cfg fallbacks for the lifetime of
// the tunnel.
func TestCoordinatorInflightDedup(t *testing.T) {
	body := []byte("fake-rosenpass-pubkey")
	svc := newFakeService()
	gate := make(chan struct{}) // closed by the test to unblock the first fetch
	fetcherStarted := make(chan struct{}, 1)
	var fetchMu sync.Mutex
	var fetchCount int
	fetcher := func(ctx context.Context, _ *net.TCPAddr, expectedHash string, _ *net.Dialer) ([]byte, error) {
		fetchMu.Lock()
		fetchCount++
		isFirst := fetchCount == 1
		fetchMu.Unlock()
		if isFirst {
			select {
			case fetcherStarted <- struct{}{}:
			default:
			}
			// Block the first fetch until the test releases the gate.
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
	}
	fetchCountFn := func() int {
		fetchMu.Lock()
		defer fetchMu.Unlock()
		return fetchCount
	}
	coord := newTestCoordinator(t, svc, fetcher)
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-bbbbbbb")
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.43"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-2",
		ExpectedPubkeyHash: hashHex(body),
	}

	// First Notify: kicks off a fetch that blocks on the gate.
	coord.Notify(ev)
	<-fetcherStarted

	// Fire many additional Notify events while the first fetch is
	// stuck in the fetcher. No additional goroutine spawns; the
	// latest is queued in `pending` and replayed exactly once after
	// the in-flight finishes.
	for i := 0; i < 10; i++ {
		coord.Notify(ev)
	}
	require.Equal(t, 1, fetchCountFn(),
		"no second goroutine should run concurrently with the in-flight fetch")
	coord.mu.Lock()
	_, hasPending := coord.pending[hexFingerprint(peerStatic)]
	coord.mu.Unlock()
	require.True(t, hasPending, "Notify during in-flight must populate pending slot")

	// Release the gate. The first fetch completes, then the
	// goroutine replays the queued pending Notify (one more fetch),
	// then clears inflight when nothing else is pending.
	close(gate)
	require.Eventually(t, func() bool {
		return fetchCountFn() == 2
	}, 2*time.Second, 10*time.Millisecond, "pending Notify must replay exactly once after in-flight completes")
	require.Eventually(t, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return len(coord.inflight) == 0 && len(coord.pending) == 0
	}, 2*time.Second, 10*time.Millisecond, "inflight and pending should both be empty after drain")

	// AddPeer should have fired twice (idempotent, but the replay
	// path runs the full register sequence).
	require.GreaterOrEqual(t, svc.addPeerCount(peerStatic), 1,
		"AddPeer fires at least once for the in-flight + replay sequence")

	// A fresh Notify after drain must drive a new fetch.
	coord.Notify(ev)
	require.Eventually(t, func() bool {
		return fetchCountFn() >= 3
	}, 2*time.Second, 10*time.Millisecond, "post-completion Notify did not drive a new fetch")
}

// TestCoordinatorRetriesAfterFetchFailure asserts the contract that
// replaces the removed cooldown state machine: when a fetch fails,
// the Coordinator does not record any backoff — the next Notify
// simply retries. This is the "handshake events are the retry
// signal" simplification at the heart of simp-1.
func TestCoordinatorRetriesAfterFetchFailure(t *testing.T) {
	body := []byte("fake-rosenpass-pubkey")
	svc := newFakeService()
	var fetchMu sync.Mutex
	var fetchCount int
	fetcher := func(_ context.Context, _ *net.TCPAddr, _ string, _ *net.Dialer) ([]byte, error) {
		fetchMu.Lock()
		fetchCount++
		isFirst := fetchCount == 1
		fetchMu.Unlock()
		if isFirst {
			return nil, errors.New("simulated discovery service down")
		}
		return body, nil
	}
	coord := newTestCoordinator(t, svc, fetcher)
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-ccccccc")
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.44"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-3",
		ExpectedPubkeyHash: hashHex(body),
	}

	// First Notify: fetch fails. The Coordinator logs and clears
	// in-flight, no peer added.
	coord.Notify(ev)
	require.Eventually(t, func() bool {
		fetchMu.Lock()
		defer fetchMu.Unlock()
		return fetchCount == 1
	}, 2*time.Second, 10*time.Millisecond, "first fetch did not run")

	// Drain the in-flight set: poll until the first goroutine has
	// released its slot. Without this we'd race the dedup check on
	// the second Notify.
	require.Eventually(t, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return len(coord.inflight) == 0
	}, 2*time.Second, 10*time.Millisecond, "in-flight slot not cleared after fetch failure")

	require.Empty(t, svc.addedKeys(), "no peer should be added on fetch failure")

	// Second Notify: fetch succeeds, peer registers. The
	// Coordinator carries no penalty / cooldown from the prior
	// failure.
	coord.Notify(ev)
	require.Eventually(t, func() bool {
		return len(svc.addedKeys()) == 1
	}, 2*time.Second, 10*time.Millisecond, "retry Notify did not register peer")
}

// TestCoordinatorCloseWaitsForInflight asserts that Close drains all
// in-flight fetch goroutines before returning. Without this, the
// Coordinator could leak goroutines (and racing AddPeer/RemovePeer
// calls) past the package's lifecycle boundary.
func TestCoordinatorCloseWaitsForInflight(t *testing.T) {
	svc := newFakeService()
	released := make(chan struct{})
	fetcher := func(ctx context.Context, _ *net.TCPAddr, _ string, _ *net.Dialer) ([]byte, error) {
		// Block until ctx is cancelled (Close fires the cancel) or
		// the test forcibly releases. Either path lets Close return.
		select {
		case <-ctx.Done():
		case <-released:
		}
		return nil, ctx.Err()
	}
	coord := newTestCoordinator(t, svc, fetcher)
	coord.Start()

	peerStatic := []byte("peer-static-key-32-bytes-ddddddd")
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.45"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-4",
		ExpectedPubkeyHash: hashHex([]byte("placeholder")),
	}
	coord.Notify(ev)

	// Wait until the fetch goroutine is actually running before we
	// call Close, so the test exercises the wg.Wait() drain path.
	require.Eventually(t, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return len(coord.inflight) == 1
	}, 2*time.Second, 10*time.Millisecond, "fetch goroutine did not start")

	closeDone := make(chan struct{})
	go func() {
		_ = coord.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		// Close returned, drain complete.
	case <-time.After(3 * time.Second):
		close(released) // unblock the fetcher so the test can exit
		t.Fatal("Close did not return; in-flight goroutine was not drained")
	}

	// After Close, further Notify events are no-ops.
	coord.Notify(ev)
	coord.mu.Lock()
	inflight := len(coord.inflight)
	coord.mu.Unlock()
	require.Zero(t, inflight, "Notify after Close should be a no-op")
}

// hashHex is a small helper for the cert-extension tests below: it
// returns the lowercase hex SHA-256 of b, matching the encoding stored
// in cert v2 details and in pq.Store.
func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fetcherStrict is a Fetcher that mirrors the production FetchPubkey's
// hash-check semantics without standing up an HTTP listener: if
// expectedHash is non-empty and does not match the canned body's hash,
// it returns rphttp.ErrPubkeyHashMismatch (same error type the real fetcher
// emits, which the Coordinator treats as fatal). This lets cert-
// extension tests assert that the Coordinator plumbs the expected hash
// through to the fetcher and surfaces mismatches without spinning up
// the Discovery HTTP server.
func fetcherStrict(body []byte) rphttp.Fetcher {
	return func(_ context.Context, _ *net.TCPAddr, expectedHash string, _ *net.Dialer) ([]byte, error) {
		got := hashHex(body)
		if expectedHash != "" && expectedHash != got {
			return nil, rphttp.ErrPubkeyHashMismatch{Expected: expectedHash, Got: got}
		}
		return body, nil
	}
}

// TestCoordinator_CertExtensionHash_AcceptsMatching pins down the simp-2
// happy path: when the peer's cert binds a rosenpass pubkey hash and
// the discovery fetch returns a body whose SHA-256 matches, the peer is
// registered. No TOFU pin write should happen against the supplied
// Store because the cert hash already provided trust binding (the pin
// is still written for migration robustness — see the test below for
// the TOFU-fallback case — but the registration succeeds either way).
func TestCoordinator_CertExtensionHash_AcceptsMatching(t *testing.T) {
	body := []byte("real-rosenpass-pubkey-body-aaaaa")
	expected := hashHex(body)

	svc := newFakeService()
	coord := newTestCoordinator(t, svc, fetcherStrict(body))
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-eeeeeee")
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.50"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-cert-match",
		ExpectedPubkeyHash: expected,
	}
	coord.Notify(ev)
	require.Eventually(t, func() bool {
		return len(svc.addedKeys()) == 1
	}, 2*time.Second, 10*time.Millisecond, "matching cert-extension hash did not result in AddPeer")
}

// TestCoordinator_CertExtensionHash_RejectsMismatch asserts that when
// the cert-extension hash and the fetched body disagree, the
// Coordinator refuses to register the peer. This is the whole point of
// binding the hash into the cert: a peer cannot silently swap its
// rosenpass identity post-issuance.
func TestCoordinator_CertExtensionHash_RejectsMismatch(t *testing.T) {
	body := []byte("real-rosenpass-pubkey-body-bbbbb")
	wrong := hashHex([]byte("an-entirely-different-pubkey"))

	svc := newFakeService()
	coord := newTestCoordinator(t, svc, fetcherStrict(body))
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-fffffff")
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.51"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-cert-mismatch",
		ExpectedPubkeyHash: wrong,
	}
	coord.Notify(ev)

	// Wait for the in-flight slot to clear: the fetch returns the
	// hash-mismatch error, the goroutine logs + deletes the slot.
	require.Eventually(t, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return len(coord.inflight) == 0
	}, 2*time.Second, 10*time.Millisecond, "in-flight slot not cleared after mismatch")

	require.Empty(t, svc.addedKeys(), "AddPeer must not run when cert-extension hash mismatches fetched body")
}

// TestCoordinator_CertExtensionAbsent_RefusesRegistration asserts that
// when the peer's cert does not carry the rosenpass-pubkey-hash
// extension (ExpectedPubkeyHash empty in the rphttp.PeerObserved event), the
// Coordinator refuses to register the peer. This replaces the prior
// TOFU-pin fallback: after Simp 3 the cert extension is the sole trust
// binding, so peers with unsigned identities must fall through to
// non-PQ handshakes until the operator rotates their cert.
func TestCoordinator_CertExtensionAbsent_RefusesRegistration(t *testing.T) {
	body := []byte("real-rosenpass-pubkey-body-ccccc")

	svc := newFakeService()
	coord := newTestCoordinator(t, svc, fetcherStrict(body))
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-ggggggg")
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.52"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-no-ext",
		ExpectedPubkeyHash: "", // peer cert lacks the extension
	}

	coord.Notify(ev)

	// Wait for the in-flight slot to clear (the fetch goroutine
	// returns immediately with the no-extension error).
	require.Eventually(t, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return len(coord.inflight) == 0
	}, 2*time.Second, 10*time.Millisecond, "in-flight slot not cleared after no-extension refusal")

	require.Empty(t, svc.addedKeys(),
		"AddPeer must not run when the peer cert lacks rosenpassPubKeySha256")
}

// TestCoordinator_UsesPeerObservedRosenpassPort pins the new contract
// behind the heterogeneous-port fix: when rphttp.PeerObserved carries a
// non-zero RosenpassPort (the value the peer gossiped), the
// Coordinator must hand THAT port to Service.AddPeer's endpoint —
// not cfg.RosenpassPort. Without this, peers that legitimately run
// rosenpass on a non-default UDP port handshake silently to the wrong
// destination and ix_psk2 never completes.
func TestCoordinator_UsesPeerObservedRosenpassPort(t *testing.T) {
	body := []byte("fake-rosenpass-pubkey")
	svc := newFakeService()
	coord := newTestCoordinator(t, svc, fetcherStrict(body))
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-hhhhhhh")
	const gossipedPort = 51824
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.60"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-heterogeneous-port",
		ExpectedPubkeyHash: hashHex(body),
		RosenpassPort:      gossipedPort,
	}
	coord.Notify(ev)
	require.Eventually(t, func() bool {
		return svc.endpointFor(peerStatic) != nil
	}, 2*time.Second, 10*time.Millisecond, "AddPeer was never called")

	got := svc.endpointFor(peerStatic)
	require.NotNil(t, got)
	require.Equal(t, gossipedPort, got.Port,
		"Coordinator must use the gossiped RosenpassPort, not cfg.RosenpassPort")
}

// TestCoordinator_FallsBackToCfgRosenpassPort pins the backwards-
// compatibility leg of the same contract: when rphttp.PeerObserved.RosenpassPort
// is 0 (peer is an older binary that doesn't gossip the port, or
// first contact before any HostUpdate has arrived), the Coordinator
// falls back to cfg.RosenpassPort. This preserves the pre-fix
// behaviour for homogeneous fleets and old peers.
func TestCoordinator_FallsBackToCfgRosenpassPort(t *testing.T) {
	body := []byte("fake-rosenpass-pubkey")
	svc := newFakeService()
	coord := newTestCoordinator(t, svc, fetcherStrict(body))
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-iiiiiii")
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.61"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-port-fallback",
		ExpectedPubkeyHash: hashHex(body),
		// RosenpassPort intentionally omitted (== 0).
	}
	coord.Notify(ev)
	require.Eventually(t, func() bool {
		return svc.endpointFor(peerStatic) != nil
	}, 2*time.Second, 10*time.Millisecond, "AddPeer was never called")

	got := svc.endpointFor(peerStatic)
	require.NotNil(t, got)
	// newTestCoordinator wires RosenpassPort: 51821.
	require.Equal(t, 51821, got.Port,
		"RosenpassPort=0 in rphttp.PeerObserved must fall back to cfg.RosenpassPort")
}

// fetcherCapture is a Fetcher that records the TCPAddr the Coordinator
// passed in so DiscoveryPort tests can assert the right port was used
// for the HTTP pubkey-fetch leg of fetchAndRegister. body is returned
// on every call; expectedHash is honoured the same way fetcherStrict
// does (mismatches abort the registration), so the existing cert-
// extension test stays valid alongside.
type fetcherCapture struct {
	mu        sync.Mutex
	gotAddr   *net.TCPAddr
	gotHash   string
	body      []byte
}

func (f *fetcherCapture) Fetch(_ context.Context, addr *net.TCPAddr, expectedHash string, _ *net.Dialer) ([]byte, error) {
	f.mu.Lock()
	// Defensive copy of the address: callers commonly reuse the
	// underlying net.IP slice across requests in production, so we
	// snapshot it here to keep test assertions stable.
	cp := *addr
	if addr.IP != nil {
		cp.IP = append(net.IP(nil), addr.IP...)
	}
	f.gotAddr = &cp
	f.gotHash = expectedHash
	f.mu.Unlock()
	got := hashHex(f.body)
	if expectedHash != "" && expectedHash != got {
		return nil, rphttp.ErrPubkeyHashMismatch{Expected: expectedHash, Got: got}
	}
	return f.body, nil
}

func (f *fetcherCapture) snapshotAddr() *net.TCPAddr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotAddr
}

// TestCoordinator_UsesPeerObservedDiscoveryPort pins the TCP-side
// heterogeneous-port contract: when rphttp.PeerObserved carries a non-zero
// DiscoveryPort (the value the peer gossiped for its rosenpass-
// discovery HTTP service), the Coordinator must hand THAT port to
// the Fetcher's TCPAddr — not cfg.DiscoveryPort. Without this, the
// HTTP fetch hits the wrong port and FetchPubkey fails with
// connection-refused, so the peer never gets registered.
func TestCoordinator_UsesPeerObservedDiscoveryPort(t *testing.T) {
	body := []byte("fake-rosenpass-pubkey-disc-port")
	fetcher := &fetcherCapture{body: body}
	svc := newFakeService()
	coord := newTestCoordinator(t, svc, fetcher.Fetch)
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-jjjjjjj")
	const gossipedDiscPort = 51841
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.62"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-heterogeneous-disc-port",
		ExpectedPubkeyHash: hashHex(body),
		DiscoveryPort:      gossipedDiscPort,
	}
	coord.Notify(ev)
	require.Eventually(t, func() bool {
		return svc.endpointFor(peerStatic) != nil
	}, 2*time.Second, 10*time.Millisecond, "AddPeer was never called")

	got := fetcher.snapshotAddr()
	require.NotNil(t, got, "Fetcher was never invoked")
	require.Equal(t, gossipedDiscPort, got.Port,
		"Coordinator must use the gossiped DiscoveryPort, not cfg.DiscoveryPort")
}

// safeBuffer wraps bytes.Buffer with a mutex so it can be safely
// written to from background goroutines while the test reads from it.
// bytes.Buffer is not concurrency-safe and slog handlers may write
// from any goroutine.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestCoordinator_PendingReplayCapped pins the DoS hardening that
// bounds the Notify goroutine's `for {}` loop. Setup: a fetcher that
// (a) does just enough work that the test can re-Notify before it
// returns, and (b) registers each call so we can count iterations.
// We then re-Notify in a tight loop while the goroutine is iterating
// — without the cap the goroutine would spin forever; with the cap
// it bails after pendingReplayCap iterations and logs a Warn.
func TestCoordinator_PendingReplayCapped(t *testing.T) {
	body := []byte("fake-rosenpass-pubkey-for-cap-test")

	// Gate the first fetch so the test can queue a pending Notify
	// before the goroutine's iteration loop starts churning. After
	// the gate is released, fetches return quickly so the goroutine
	// drains pending and re-iterates.
	gate := make(chan struct{})
	gateOnce := sync.Once{}
	releaseGate := func() { gateOnce.Do(func() { close(gate) }) }
	t.Cleanup(releaseGate) // safety net in case the test fails before releasing

	var fetchCount atomic.Int64
	fetcher := func(ctx context.Context, _ *net.TCPAddr, expectedHash string, _ *net.Dialer) ([]byte, error) {
		n := fetchCount.Add(1)
		if n == 1 {
			// Block the first fetch so the test can fill the pending
			// slot and stage the looping condition.
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		got := hashHex(body)
		if expectedHash != "" && expectedHash != got {
			return nil, rphttp.ErrPubkeyHashMismatch{Expected: expectedHash, Got: got}
		}
		return body, nil
	}

	// Build a coordinator wired to a capturing logger so we can
	// assert the Warn message fires when the cap is hit.
	logBuf := &safeBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc := newFakeService()
	disc, err := rphttp.NewDiscovery(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, []byte("placeholder-pubkey"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = disc.Close() })
	coord, err := NewCoordinator(CoordinatorConfig{
		Service:       svc,
		Discovery:     disc,
		Fetcher:       fetcher,
		RosenpassPort: 51821,
		DiscoveryPort: 51820,
		FetchRetries:  1,
		FetchTimeout:  100 * time.Millisecond,
		Logger:        logger,
	})
	require.NoError(t, err)
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-zzzzzzz")
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.99"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-cap",
		ExpectedPubkeyHash: hashHex(body),
	}

	// First Notify: kicks off a fetch that blocks on the gate.
	coord.Notify(ev)
	require.Eventually(t, func() bool {
		return fetchCount.Load() >= 1
	}, 2*time.Second, 5*time.Millisecond, "first fetch did not start")

	// Stage the pending slot before releasing the gate. After this
	// Notify, the goroutine — once the gate is released — will see
	// `pending[key]` populated on every iteration, because we keep
	// re-Notifying in a background goroutine below.
	coord.Notify(ev)

	// Re-Notify in a tight background loop so that every time the
	// goroutine drains `pending[key]` and unlocks the mutex, another
	// Notify re-fills it. This is the gossip-churn DoS scenario.
	stopRefill := make(chan struct{})
	refillDone := make(chan struct{})
	go func() {
		defer close(refillDone)
		for {
			select {
			case <-stopRefill:
				return
			default:
				coord.Notify(ev)
				time.Sleep(time.Microsecond)
			}
		}
	}()
	t.Cleanup(func() {
		select {
		case <-stopRefill:
		default:
			close(stopRefill)
		}
		<-refillDone
	})

	// Release the gate so the goroutine starts iterating.
	releaseGate()

	// The goroutine should hit pendingReplayCap and bail. Detect
	// completion via the Warn log message.
	require.Eventually(t, func() bool {
		return strings.Contains(logBuf.String(), "rosenpass pending replay cap hit")
	}, 5*time.Second, 10*time.Millisecond,
		"goroutine never hit the replay cap — it may be looping unbounded; logs so far: %s", logBuf.String())

	// Stop the refill goroutine so we can observe a quiescent state.
	close(stopRefill)
	<-refillDone

	// After hitting the cap the goroutine clears inflight; another
	// Notify (the cleanup of the refill goroutine fired some, but
	// they may have been deduped if a new fetch was already in
	// flight). Drain by polling for a steady state where inflight is
	// 0 OR the fetch count has grown past the cap (meaning a new
	// goroutine picked up where the capped one left off — also
	// acceptable; the cap bounds per-goroutine lifetime, not total
	// work across the system).
	//
	// The substantive assertion is the Warn fired and the goroutine
	// did NOT spin forever, which the require.Eventually above
	// already confirmed.
	require.GreaterOrEqual(t, fetchCount.Load(), int64(pendingReplayCap),
		"goroutine bailed before completing pendingReplayCap iterations")

	// Sanity: structured log carries the iteration count so operators
	// can correlate churn signal across peers.
	require.Contains(t, logBuf.String(), `"iterations":`,
		"replay-cap log must carry iteration count for operator triage")
}

// TestCoordinator_FallsBackToCfgDiscoveryPort pins the backwards-
// compatibility leg of the same contract: when rphttp.PeerObserved.
// DiscoveryPort is 0 (peer is a pre-gossip binary, or first contact
// before HostUpdate has arrived), the Coordinator falls back to
// cfg.DiscoveryPort. Mirrors TestCoordinator_FallsBackToCfgRosenpassPort.
func TestCoordinator_FallsBackToCfgDiscoveryPort(t *testing.T) {
	body := []byte("fake-rosenpass-pubkey-disc-fbk")
	fetcher := &fetcherCapture{body: body}
	svc := newFakeService()
	coord := newTestCoordinator(t, svc, fetcher.Fetch)
	coord.Start()
	t.Cleanup(func() { _ = coord.Close() })

	peerStatic := []byte("peer-static-key-32-bytes-kkkkkkk")
	ev := rphttp.PeerObserved{
		VpnIP:              netip.MustParseAddr("10.0.0.63"),
		PeerStaticPubKey:   peerStatic,
		Fingerprint:        "fp-disc-port-fallback",
		ExpectedPubkeyHash: hashHex(body),
		// DiscoveryPort intentionally omitted (== 0).
	}
	coord.Notify(ev)
	require.Eventually(t, func() bool {
		return svc.endpointFor(peerStatic) != nil
	}, 2*time.Second, 10*time.Millisecond, "AddPeer was never called")

	got := fetcher.snapshotAddr()
	require.NotNil(t, got, "Fetcher was never invoked")
	// newTestCoordinator wires DiscoveryPort: 51820.
	require.Equal(t, 51820, got.Port,
		"DiscoveryPort=0 in rphttp.PeerObserved must fall back to cfg.DiscoveryPort")
}
