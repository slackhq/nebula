//go:build rosenpass_embedded

package rposvc

import "github.com/rcrowley/go-metrics"

// Metric names for the embedded-rosenpass subsystem. These follow
// nebula's existing go-metrics convention (dot-separated lowercase,
// registered on the default registry via metrics.GetOrRegisterCounter).
//
// They exist so an embedded-rosenpass failure that degrades a node to
// classical IXPSK0 is LOUD and observable rather than silent. None of
// these counters firing changes nebula's control flow on their own —
// they are pure observability at the new fail-fast log sites.
const (
	// metricServerExited counts unexpected exits of the embedded
	// go-rosenpass run loop (i.e. server.Run() returned while the
	// service was not being shut down). After this fires the service
	// no longer drives PQ handshakes; new peers silently stay on
	// IXPSK0 unless a restart succeeds.
	metricServerExited = "pq.embedded.server_exited"

	// metricIdentityMismatch counts the case where the local embedded
	// rosenpass pubkey hash does not match the PqPskBinding the CA
	// signed into this node's cert. Peers will reject our PQ identity;
	// tunnels degrade to IXPSK0.
	metricIdentityMismatch = "pq.embedded.identity_mismatch"

	// metricKeypairGenerated counts fresh keypair generation. Expected
	// once on a brand-new node; firing on an already-provisioned node
	// (cert binds an existing identity) is the dangerous regen of
	// issue #6 and is additionally counted by metricKeypairRegenDanger.
	metricKeypairGenerated = "pq.embedded.keypair_generated"

	// metricKeypairRegenDanger counts the specific dangerous case: a
	// new keypair was minted even though the node's cert already binds
	// a PQ identity. Peers will reject us until the cert is re-issued.
	metricKeypairRegenDanger = "pq.embedded.keypair_regen_danger"

	// metricKeypairLoadFailed counts a keyfile that was present but
	// unusable (e.g. truncated mid-write, wrong length). The service
	// falls back to generation (or refuses under strict_identity).
	metricKeypairLoadFailed = "pq.embedded.keypair_load_failed"

	// metricCoordFetchFailed counts pubkey-discovery fetch failures in
	// the Coordinator. Each failure leaves the peer on IXPSK0 until the
	// next handshake re-Notify retries.
	metricCoordFetchFailed = "pq.coordinator.fetch_failed"

	// metricCoordPSKDerived counts successful PSK derivations (a peer
	// completed a rosenpass handshake and a PSK was installed).
	metricCoordPSKDerived = "pq.coordinator.psk_derived"

	// metricCoordReplayCapHit counts pending-replay-cap bail-outs in
	// the Coordinator (gossip churn / possible compromised lighthouse).
	metricCoordReplayCapHit = "pq.coordinator.replay_cap_hit"

	// metricUnknownPeerPSKDropped counts derived PSKs dropped because
	// the rosenpass PeerID had no live nebula-peer mapping (a peer was
	// removed mid-handshake). The PSK is discarded, not installed.
	metricUnknownPeerPSKDropped = "pq.embedded.unknown_peer_psk_dropped"
)

func incCounter(name string) {
	metrics.GetOrRegisterCounter(name, nil).Inc(1)
}
