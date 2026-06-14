package rpsidecar

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/rcrowley/go-metrics"
)

// Metric names for the sidecar distribution path. Mirrors
// pq/rposvc/metrics.go (pq.coordinator.*) so embedded and sidecar
// deployments expose the same failure signals under parallel names —
// an operator dashboard can alert on either without knowing which
// provisioning mode a node runs.
const (
	// metricDistFetchFailed counts pubkey fetch+write attempts that
	// failed after retries (peer unreachable, hash mismatch, write
	// error). Log-only failure here was invisible to monitoring.
	metricDistFetchFailed = "pq.sidecar.fetch_failed"

	// metricDistReplayCapHit counts distribution goroutines that bailed
	// out at pendingReplayCap with a pending event still queued
	// (gossip churning faster than fetch+write completes).
	metricDistReplayCapHit = "pq.sidecar.replay_cap_hit"
)

// incCounter bumps the named counter on the default go-metrics
// registry by one. Same helper as pq and pq/rposvc so all PQ metric
// sites read identically.
func incCounter(name string) {
	metrics.GetOrRegisterCounter(name, nil).Inc(1)
}

// hexFingerprint returns hex(sha256(b)) — the same peer-key convention
// pq/rposvc uses for its inflight/pending maps and log fields. Hashing
// keeps raw static-key bytes out of any log line that ever prints the
// map key.
func hexFingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
