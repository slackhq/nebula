package pq

import "github.com/rcrowley/go-metrics"

// Metric names for the base PQ-PSK subsystem (provider + state cache +
// policy degradation). These follow nebula's existing go-metrics
// convention (dot-separated lowercase, registered on the default
// registry via metrics.GetOrRegisterCounter), matching pq/rposvc's
// style so all PQ observability shares the "pq." prefix.
//
// None of these counters firing changes nebula's control flow on their
// own — they are pure observability at sites where the PQ subsystem
// degrades, serves stale material, or recovers. The control-flow
// decisions (degrade to IXPSK0, gated teardown, keep-serving-stale)
// live at the call sites; the counters just make those decisions
// loud and observable.
const (
	// MetricStateLoadFailed counts pq-state.json files that were present
	// but unparseable at boot (truncated mid-write, manual edit, schema
	// drift). The store starts empty (warm-start cache only, so this is
	// not fatal) but the operator loses the boot-path identity cache for
	// every peer until the next IXPSK2 handshake re-populates it.
	MetricStateLoadFailed = "pq.state.load_failed"

	// MetricFileRescanFailed counts failed rescans of the FileProvider's
	// watched directory (e.g. os.ReadDir error after the dir was removed
	// or became unreadable). The last-known PSK snapshot is retained and
	// keeps serving valid material, but no new drop-ins are picked up
	// until a rescan succeeds again.
	MetricFileRescanFailed = "pq.file.rescan_failed"

	// MetricFileWatchLost counts loss of the FileProvider's fsnotify
	// watch on its directory (the dir was removed or renamed out from
	// under us). After this fires the provider self-heals by retrying
	// the watch add and periodic rescans; the stale snapshot keeps
	// serving in the meantime.
	MetricFileWatchLost = "pq.file.watch_lost"

	// MetricFileSnapshotAge is a gauge of seconds since the
	// FileProvider's snapshot content last changed. For a rotating
	// sidecar deployment this saw-tooths around the rekey interval; a
	// monotonically climbing value means the sidecar stopped rotating
	// (dead daemon, or its peer KEX can't complete) even though the
	// files on disk still look healthy. Updated on every health tick.
	MetricFileSnapshotAge = "pq.file.snapshot_age_seconds"

	// MetricFileSnapshotStale counts stale episodes: each time the
	// snapshot age first crosses the configured
	// pki.pq_psk_stale_warn threshold while PSKs are loaded. Zero when
	// the knob is unset.
	MetricFileSnapshotStale = "pq.file.snapshot_stale"

	// MetricHandshakeMsg2Reject counts IXPSK2 msg2 AEAD rejections on
	// the initiator side, once per handshake cycle (retransmits of the
	// same rejected msg2 are not re-counted). Unlike the timeout
	// counter this PROVES the peer is alive and the PSK bytes differ —
	// the definitive epoch-mismatch / broken-pairing signal.
	MetricHandshakeMsg2Reject = "pq.handshake_ixpsk2_msg2_reject"

	// MetricPrevEpochRecovered counts handshakes that completed using
	// the previous-epoch PSK (either side). A steady low rate tracks
	// rotation skew; a high rate means the sidecar file delivery is
	// chronically lagging.
	MetricPrevEpochRecovered = "pq.psk_prev_epoch_recovered"

	// MetricForcedDegrade counts IXPSK2->IXPSK0 degrade episodes: one per
	// cooldown window armed (a re-arm while a cooldown is still active is
	// not re-counted). Each tick is a 60s window during which NEW
	// handshakes to that peer form classical instead of PQ. Because the
	// degrade only arms on proven msg2 rejects, a climbing count means
	// either a persistent rosenpass desync OR an active on-path attacker
	// forging/corrupting msg2 to strip PQ — both warrant investigation.
	// In opportunistic mode this is the loud signal that downgrade is
	// happening; the operator's true-prevention lever is pq.mode=required
	// on the affected link (accepting its deadlock-on-desync tradeoff).
	MetricForcedDegrade = "pq.handshake_ixpsk2_forced_degrade"

	// MetricBindingMismatch counts CA-signed-cert vs local-provider-hint
	// PQ-PSK binding mismatches — the signal that a peer's rosenpass key
	// was rotated/replaced after its cert was issued (benign re-key the
	// operator forgot to re-sign, OR a swapped sidecar key after a cert
	// compromise). Fires in BOTH warn and enforce mode (the mismatch is
	// the event; the mode only decides whether the PSK is still used).
	// Under the deployed warn mode the PSK is used anyway, so this counter
	// is the only machine-readable trace — alert on it instead of scraping
	// the warn logs.
	MetricBindingMismatch = "pq.psk_binding_mismatch"
)

// incCounter bumps the named counter on the default go-metrics
// registry by one. Mirrors pq/rposvc's helper of the same name so the
// two PQ metric sites read identically.
func incCounter(name string) {
	metrics.GetOrRegisterCounter(name, nil).Inc(1)
}

// IncCounter bumps a pq metric from outside the package (handshake
// manager call sites).
func IncCounter(name string) { incCounter(name) }

// updateGauge sets the named float64 gauge on the default go-metrics
// registry.
func updateGauge(name string, v float64) {
	metrics.GetOrRegisterGaugeFloat64(name, nil).Update(v)
}
