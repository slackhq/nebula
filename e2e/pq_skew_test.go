//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/require"
)

// These tests prove the multi-epoch PSK skew-healing implemented in
// commits 50e266c..6249f09 works end-to-end through the real handshake
// stack (two in-process nebula.Control instances routed by router.R),
// in BOTH skew directions, plus a control that must NOT heal.
//
// Bootstrap note: nebula's IXPSK2 initiator only chooses subtype 2 once
// it already knows the peer's static public key (it needs it to resolve
// the per-peer PSK before sending msg1). On a cold mesh that key is not
// known, so the very first handshake is IXPSK0. These tests therefore
// run pq.mode=opportunistic and bootstrap an IXPSK0 tunnel first (which
// caches each peer's cert), then drop the PSK files in and drive a
// re-handshake which upgrades to IXPSK2. The healing code paths
// exercised (same-packet SwapPSK on the initiator, AltEpochHint on the
// responder, and the IXPSK2 timeout on a genuine mismatch) are byte-for
// -byte identical under required vs opportunistic — the only thing
// "required" changes is whether IXPSK0 is refused, which has nothing to
// do with epoch skew. See the final report for the full rationale.

const pqSkewPSKLen = 32

// pqEpoch returns a recognisable distinct 32-byte PSK for an epoch.
func pqEpoch(tag byte) []byte { return bytes.Repeat([]byte{tag}, pqSkewPSKLen) }

// pqPSKFilename is the FileProvider on-disk name for a peer's PSK:
// sha256hex(peerStaticPubKey) + ".psk". Node A stores the PSK it shares
// with B under the hash of B's static key (A looks up by the PEER's key).
func pqPSKFilename(peerStaticPubKey []byte) string {
	sum := sha256.Sum256(peerStaticPubKey)
	return hex.EncodeToString(sum[:]) + ".psk"
}

// writePSK drops a 32-byte PSK file for peerStaticPubKey into dir.
func writePSK(t *testing.T, dir string, peerStaticPubKey, psk []byte) {
	t.Helper()
	require.Len(t, psk, pqSkewPSKLen)
	path := filepath.Join(dir, pqPSKFilename(peerStaticPubKey))
	require.NoError(t, os.WriteFile(path, psk, 0o600))
}

// pqStaticPubKey returns a control's nebula static public key — the key
// the PEER uses to name this node's .psk file.
func pqStaticPubKey(c *nebula.Control) []byte {
	return c.GetCertState().GetDefaultCertificate().PublicKey()
}

// counterValue reads a go-metrics counter from the process-global
// default registry, returning 0 if it has never been registered.
func counterValue(name string) int64 {
	v := metrics.DefaultRegistry.Get(name)
	if v == nil {
		return 0
	}
	c, ok := v.(metrics.Counter)
	if !ok {
		return 0
	}
	return c.Count()
}

// pqRescanner is the subset of the FileProvider surface we drive from
// tests: a synchronous Rescan mirroring a sidecar drop-in without
// racing the fsnotify debounce.
type pqRescanner interface {
	Rescan() error
}

// pqProvider digs the live FileProvider out of a control. Fatals if the
// control has no rescannable PQ source configured.
func pqProvider(t *testing.T, c *nebula.Control) pqRescanner {
	t.Helper()
	prov := c.GetPQSource()
	require.NotNil(t, prov, "control has no PQ source provider")
	r, ok := prov.(pqRescanner)
	require.True(t, ok, "PQ source provider is not rescannable (got %T)", prov)
	return r
}

// pqOverrides returns the per-node config block enabling opportunistic
// IXPSK2 backed by a FileProvider rooted at dir, with binding disabled
// (the skew tests care about epoch, not binding) and a fast/short
// handshake timer so the control test's timeout fires quickly.
func pqOverrides(dir string) m {
	return m{
		"pki": m{
			"pq_psk_dir": dir,
		},
		"pq": m{
			"mode": "opportunistic",
			"psk_binding": m{
				"mode": "off",
			},
		},
		"handshakes": m{
			"try_interval": "50ms",
			"retries":      6,
		},
	}
}

// bootstrapIXPSK0 brings up an IXPSK0 tunnel between the two controls so
// each side caches the other's cert (the precondition for the initiator
// choosing IXPSK2 on a subsequent re-handshake). Returns with both
// servers started and a working tunnel.
func bootstrapIXPSK0(t *testing.T, myControl, theirControl *nebula.Control, myVpnIp, theirVpnIp netip.Addr, r *router.R) {
	t.Helper()
	assertTunnel(t, myVpnIp, theirVpnIp, myControl, theirControl, r)
}

// driveUntilCounter triggers an IXPSK2 re-handshake from initiator to
// peer and routes packets until the named counter rises above baseline
// or the deadline elapses. Returns true if the counter rose.
//
// A rescan of the FileProvider already auto-triggers a re-handshake via
// the connection manager's PQRotation subscription, but we ALSO nudge
// ReHandshake here so the test doesn't depend on that side effect. The
// initiator's clock-driven retransmits (try_interval=50ms) keep msg1s
// flowing, so the responder-side AltEpochHint path gets its retry
// inside the 30s window without any extra scaffolding.
//
// Routing happens inside a single RouteForAllExitFunc whose exit func
// checks the counter on every packet — no leaked goroutines. A watchdog
// goroutine enforces the deadline by injecting nothing; instead we rely
// on the steady packet flow from retransmits to keep the exit func
// firing. To guarantee progress even if flow stalls, the watchdog
// re-triggers a handshake on a ticker.
func driveUntilCounter(t *testing.T, r *router.R, initiator *nebula.Control, peer netip.Addr, counter string, baseline int64, within time.Duration) bool {
	t.Helper()
	initiator.ReHandshake(peer)

	stop := make(chan struct{})
	defer close(stop)
	deadlineC := time.After(within)

	// Keep nudging handshakes so packets keep flowing even if a pending
	// entry gets reaped; this guarantees the exit func keeps firing.
	go func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				initiator.ReHandshake(peer)
			}
		}
	}()

	rose := false
	r.RouteForAllExitFunc(func(p *udp.Packet, c *nebula.Control) router.ExitType {
		if counterValue(counter) > baseline {
			rose = true
			return router.RouteAndExit
		}
		select {
		case <-deadlineC:
			return router.RouteAndExit
		default:
			return router.KeepRouting
		}
	})
	// One last read in case the rise landed on the exiting packet.
	if counterValue(counter) > baseline {
		rose = true
	}
	return rose
}

// assertTunnelEventually is a churn-tolerant, leak-free assertTunnel.
//
// The epoch-skew scenarios drive asynchronous re-handshakes (both the
// explicit drive and fsnotify-triggered rescans of the PSK dir), so a
// one-shot assertTunnel would race a key swap — and because tun packets
// aren't retransmitted by the data plane, a single dropped probe wedges
// the blocking RouteForAllUntilTxTun forever. Instead we drive the whole
// thing synchronously: inject a tun probe, pump all pending UDP both
// ways (FlushAll), then non-blocking-poll the receiver's tun. Repeat
// (re-injecting) until a probe round-trips intact in BOTH directions or
// the deadline elapses. No goroutines, so nothing leaks.
func assertTunnelEventually(t *testing.T, r *router.R, vpnIpA, vpnIpB netip.Addr, controlA, controlB *nebula.Control) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		okAB := probeTun(r, controlA, controlB, vpnIpA, vpnIpB)
		okBA := probeTun(r, controlB, controlA, vpnIpB, vpnIpA)
		if okAB && okBA {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("healed tunnel never carried traffic (still churning after deadline)")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// probeTun injects one tun UDP packet from->to, pumps all pending UDP
// (delivering handshakes plus the encrypted probe), then drains the
// receiver's tun looking for the intact probe. Fully synchronous; never
// fails the test directly so the caller can retry through churn.
func probeTun(r *router.R, from, to *nebula.Control, fromIp, toIp netip.Addr) bool {
	payload := []byte("pq-skew-probe")
	from.InjectTunPacket(BuildTunUDPPacket(toIp, 80, fromIp, 90, payload))
	// Pump a few rounds: a fresh handshake may need to complete before
	// the data-plane packet can be encrypted and delivered.
	for i := 0; i < 5; i++ {
		r.FlushAll()
		for {
			b := to.GetFromTun(false)
			if b == nil {
				break
			}
			if bytes.Contains(b, payload) {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestPQEpochSkew_ResponderBehind: initiator holds current=epochB,
// prev=epochA; responder holds only epochA. The initiator sends IXPSK2
// under B, the responder answers under A, the initiator's first msg2
// read AEAD-fails, and the handshake manager swaps in the previous
// epoch (A) on the same packet and heals — zero extra RTT.
func TestPQEpochSkew_ResponderBehind(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	myDir := t.TempDir()
	theirDir := t.TempDir()

	myControl, myVpnNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me-rb", "10.128.0.1/24", pqOverrides(myDir))
	theirControl, theirVpnNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them-rb", "10.128.0.2/24", pqOverrides(theirDir))

	myVpnIp := myVpnNet[0].Addr()
	theirVpnIp := theirVpnNet[0].Addr()

	myControl.InjectLightHouseAddr(theirVpnIp, theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIp, myUdpAddr)

	myControl.Start()
	theirControl.Start()
	defer myControl.Stop()
	defer theirControl.Stop()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Phase 1: cold IXPSK0 tunnel so each side caches the peer cert.
	bootstrapIXPSK0(t, myControl, theirControl, myVpnIp, theirVpnIp, r)

	myStatic := pqStaticPubKey(myControl)
	theirStatic := pqStaticPubKey(theirControl)

	// Phase 2: arrange the skew.
	// Initiator (me) gets epochA then epochB (so A becomes prev, B current).
	writePSK(t, myDir, theirStatic, pqEpoch(0xA1))
	require.NoError(t, pqProvider(t, myControl).Rescan())
	writePSK(t, myDir, theirStatic, pqEpoch(0xB2))
	require.NoError(t, pqProvider(t, myControl).Rescan())
	// Responder (them) gets only epochA.
	writePSK(t, theirDir, myStatic, pqEpoch(0xA1))
	require.NoError(t, pqProvider(t, theirControl).Rescan())

	rejectBase := counterValue("pq.handshake_ixpsk2_msg2_reject")
	recoverBase := counterValue("pq.psk_prev_epoch_recovered")

	// Phase 3: drive the IXPSK2 re-handshake and let the same-packet
	// SwapPSK heal it.
	ok := driveUntilCounter(t, r, myControl, theirVpnIp, "pq.psk_prev_epoch_recovered", recoverBase, 10*time.Second)
	require.True(t, ok, "expected pq.psk_prev_epoch_recovered to increment (initiator SwapPSK heal)")

	require.Greater(t, counterValue("pq.handshake_ixpsk2_msg2_reject"), rejectBase,
		"expected pq.handshake_ixpsk2_msg2_reject to increment by >=1")
	require.Greater(t, counterValue("pq.psk_prev_epoch_recovered"), recoverBase,
		"expected pq.psk_prev_epoch_recovered to increment by >=1")

	// The healed IXPSK2 tunnel must carry traffic.
	assertTunnelEventually(t, r, myVpnIp, theirVpnIp, myControl, theirControl)
}

// TestPQEpochSkew_InitiatorBehind: initiator holds only epochA;
// responder holds current=epochB, prev=epochA. The responder answers
// msg1 under B, the initiator rejects it (it only has A, no prev to
// swap), and retransmits msg1. Within the 30s AltEpochHint window the
// responder answers the retry under its previous epoch (A) and the
// tunnel heals.
func TestPQEpochSkew_InitiatorBehind(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	myDir := t.TempDir()
	theirDir := t.TempDir()

	myControl, myVpnNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me-ib", "10.128.0.3/24", pqOverrides(myDir))
	theirControl, theirVpnNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them-ib", "10.128.0.4/24", pqOverrides(theirDir))

	myVpnIp := myVpnNet[0].Addr()
	theirVpnIp := theirVpnNet[0].Addr()

	myControl.InjectLightHouseAddr(theirVpnIp, theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIp, myUdpAddr)

	myControl.Start()
	theirControl.Start()
	defer myControl.Stop()
	defer theirControl.Stop()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	bootstrapIXPSK0(t, myControl, theirControl, myVpnIp, theirVpnIp, r)

	myStatic := pqStaticPubKey(myControl)
	theirStatic := pqStaticPubKey(theirControl)

	// Initiator (me) gets only epochA.
	writePSK(t, myDir, theirStatic, pqEpoch(0xA1))
	require.NoError(t, pqProvider(t, myControl).Rescan())
	// Responder (them) gets epochA then epochB (A becomes prev, B current).
	writePSK(t, theirDir, myStatic, pqEpoch(0xA1))
	require.NoError(t, pqProvider(t, theirControl).Rescan())
	writePSK(t, theirDir, myStatic, pqEpoch(0xB2))
	require.NoError(t, pqProvider(t, theirControl).Rescan())

	recoverBase := counterValue("pq.psk_prev_epoch_recovered")

	// This direction relies on a clock-driven msg1 retransmit landing
	// inside the responder's 30s AltEpochHint window. driveUntilCounter
	// keeps re-handshaking and routing the retransmits until the
	// responder answers under its previous epoch.
	ok := driveUntilCounter(t, r, myControl, theirVpnIp, "pq.psk_prev_epoch_recovered", recoverBase, 15*time.Second)
	require.True(t, ok, "expected pq.psk_prev_epoch_recovered to increment (responder AltEpochHint heal)")

	require.Greater(t, counterValue("pq.psk_prev_epoch_recovered"), recoverBase,
		"expected pq.psk_prev_epoch_recovered to increment by >=1")

	// Both directions heal in this bidirectional-skew setup (the reverse
	// handshake the responder's own rotation triggers heals via SwapPSK);
	// prove the tunnel carries traffic with a churn-tolerant assert.
	assertTunnelEventually(t, r, myVpnIp, theirVpnIp, myControl, theirControl)
}

// TestPQEpochSkew_Control_NoSharedEpoch: initiator holds only epochX,
// responder only epochY, no overlap and no previous epoch on either
// side. Healing must NOT open a tunnel — proving the prev-epoch retry
// never becomes a downgrade / false-accept path. The IXPSK2 handshake
// must time out (pq.handshake_ixpsk2_timed_out increments).
func TestPQEpochSkew_Control_NoSharedEpoch(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	myDir := t.TempDir()
	theirDir := t.TempDir()

	myControl, myVpnNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me-ctl", "10.128.0.5/24", pqOverrides(myDir))
	theirControl, theirVpnNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them-ctl", "10.128.0.6/24", pqOverrides(theirDir))

	myVpnIp := myVpnNet[0].Addr()
	theirVpnIp := theirVpnNet[0].Addr()

	myControl.InjectLightHouseAddr(theirVpnIp, theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIp, myUdpAddr)

	myControl.Start()
	theirControl.Start()
	defer myControl.Stop()
	defer theirControl.Stop()

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	bootstrapIXPSK0(t, myControl, theirControl, myVpnIp, theirVpnIp, r)

	myStatic := pqStaticPubKey(myControl)
	theirStatic := pqStaticPubKey(theirControl)

	// No shared epoch, no prev on either side.
	writePSK(t, myDir, theirStatic, pqEpoch(0xC3)) // epochX
	require.NoError(t, pqProvider(t, myControl).Rescan())
	writePSK(t, theirDir, myStatic, pqEpoch(0xD4)) // epochY
	require.NoError(t, pqProvider(t, theirControl).Rescan())

	timeoutBase := counterValue("pq.handshake_ixpsk2_timed_out")
	recoverBase := counterValue("pq.psk_prev_epoch_recovered")

	// Drive the IXPSK2 re-handshake; it must never heal. Wait for the
	// timeout counter to fire instead.
	ok := driveUntilCounter(t, r, myControl, theirVpnIp, "pq.handshake_ixpsk2_timed_out", timeoutBase, 15*time.Second)
	require.True(t, ok, "expected pq.handshake_ixpsk2_timed_out to increment (no shared epoch must not heal)")

	require.Greater(t, counterValue("pq.handshake_ixpsk2_timed_out"), timeoutBase,
		"expected pq.handshake_ixpsk2_timed_out to increment by >=1")
	require.Equal(t, recoverBase, counterValue("pq.psk_prev_epoch_recovered"),
		"pq.psk_prev_epoch_recovered must NOT increment with no shared epoch")
}
