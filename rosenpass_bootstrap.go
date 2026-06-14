package nebula

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/slackhq/nebula/config"
)

// pqGossipPorts resolves the two PQ-PSK provider ports the lighthouse
// gossips to peers in HostUpdate: the provider UDP port and the
// discovery HTTP port. Generic keys (pq.provider_port /
// pq.discovery_port) are preferred; the rosenpass-specific legacy keys
// (pq.rosenpass_port / pq.embedded_rosenpass.port /
// pq.embedded_rosenpass.discovery_port) are honoured as fallbacks for
// existing deployments. Living in the provider layer keeps these
// provider-specific config strings out of core lighthouse.go.
//
// Both ports are returned as uint32 to match the protobuf wire type
// the lighthouse stores them in. 0 means "do not gossip this field".
func pqGossipPorts(l *slog.Logger, c *config.C) (rpPort, discoveryPort uint32) {
	rawRP := c.GetInt("pq.provider_port",
		c.GetInt("pq.rosenpass_port",
			c.GetInt("pq.embedded_rosenpass.port", 0)))
	rawDisc := c.GetInt("pq.discovery_port",
		c.GetInt("pq.embedded_rosenpass.discovery_port", 0))
	return clampGossipPort(l, "pq.provider_port", rawRP),
		clampGossipPort(l, "pq.discovery_port", rawDisc)
}

// clampGossipPort validates a configured port fits in the uint16 the wire
// fields hold. An out-of-range value (e.g. a fat-fingered 70000) is logged
// at Warn and treated as 0 ("do not gossip this field") so the
// misconfiguration is visible rather than silently truncated to a bogus
// low port (70000 & 0xFFFF == 4464).
func clampGossipPort(l *slog.Logger, key string, raw int) uint32 {
	if raw < 0 || raw > 0xFFFF {
		if l != nil {
			l.Warn("Configured PQ gossip port out of range; not gossiping it",
				"key", key, "value", raw, "max", 0xFFFF)
		}
		return 0
	}
	return uint32(raw)
}

// buildPQProviderStart selects and constructs the deferred start
// closure for whichever embedded PQ-PSK provider the operator has
// configured, or returns nil when none is enabled.
//
// This is the provider-layer composition root: it is the one place
// that knows about the concrete rosenpass provider (embedded
// in-process daemon vs. external sidecar with nebula-driven pubkey
// distribution) and reads the provider-specific config keys
// (pq.embedded_rosenpass.* / pq.sidecar.*). Keeping it here rather
// than in main.go keeps the core composition path provider-agnostic.
//
// The returned closure is deferred until Control.Start so the
// provider's listeners bind after the tun's local VPN address is
// assigned; see Control.pqProviderStart.
//
// Both branches stash the started provider instance in ifce.pqProvider
// (held as io.Closer) so the build-tag-gated notify path can type-
// assert it back to its concrete type to drive peer registration.
//
//   - pq.embedded_rosenpass.enabled: in-process go-rosenpass. Only the
//     rosenpass_embedded build pulls in the real implementation; the
//     default build's startEmbeddedRosenpass stub fails startup so a
//     misbuilt binary can't come up silently without its PQ layer.
//   - pq.sidecar.pubkey_serve_file / pq.sidecar.pubkey_distribute_dir:
//     external rosenpass binary with nebula handling pubkey
//     distribution (lighthouse gossip + cert-bound fetch + atomic file
//     write), giving operators the same liveness story as embedded
//     mode without the unaudited go-rosenpass dependency.
func buildPQProviderStart(ctx context.Context, l *slog.Logger, c *config.C, ifce *Interface) func() error {
	switch {
	case c.GetBool("pq.embedded_rosenpass.enabled", false):
		return func() error {
			coord, rpErr := startEmbeddedRosenpass(ctx, l, c, ifce)
			if rpErr != nil {
				return fmt.Errorf("embedded rosenpass: %w", rpErr)
			}
			ifce.pqProvider = coord
			return nil
		}
	case c.GetString("pq.sidecar.pubkey_serve_file", "") != "" ||
		c.GetString("pq.sidecar.pubkey_distribute_dir", "") != "":
		return func() error {
			bundle, rpErr := startSidecarDistributor(ctx, l, c, ifce)
			if rpErr != nil {
				return fmt.Errorf("rosenpass sidecar: %w", rpErr)
			}
			ifce.pqProvider = bundle
			return nil
		}
	}
	return nil
}
