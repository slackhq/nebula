//go:build !rosenpass_embedded

package nebula

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/slackhq/nebula/config"
)

// startEmbeddedRosenpass is a no-op in default builds. PSK provisioning
// is handled by an external sidecar process (the official rosenpass
// daemon from rosenpass.eu, the go-rosenpass standalone binary, or any
// other process that writes 32-byte PSK files into pki.pq_psk_dir).
//
// Build with -tags rosenpass_embedded to enable the in-process
// rosenpass implementation. That path uses cunicu.li/go-rosenpass,
// which has not been audited (see its README). The sidecar path
// allows pairing nebula with the audited Rust reference implementation
// instead.
//
// If pq.embedded_rosenpass.enabled is set in a default-build binary
// the operator has misconfigured the deployment: the binary cannot
// honor the flag. Control.Start treats a non-nil pqProviderStart as an
// explicit operator opt-in where startup failure is fatal, so fail
// loudly here rather than degrade to a silent missing-PQ posture —
// a node that comes up "healthy" without the PQ layer the operator
// asked for is worse than one that refuses to start.
func startEmbeddedRosenpass(_ context.Context, _ *slog.Logger, c *config.C, _ *Interface) (io.Closer, error) {
	if c.GetBool("pq.embedded_rosenpass.enabled", false) {
		return nil, errors.New("pq.embedded_rosenpass.enabled is set but this nebula binary was built without -tags rosenpass_embedded; rebuild with the tag or switch to sidecar provisioning via pki.pq_psk_dir")
	}
	return nil, nil
}
