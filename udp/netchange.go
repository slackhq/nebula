package udp

import (
	"context"
	"log/slog"

	"github.com/slackhq/nebula/config"
)

// NetworkChangeMonitor rebinds the udp listener when the local network moves out from under it.
//
// Detection lives here in the udp package, next to the socket it concerns and the platform matrix that already knows
// which sockets go stale. What to do about a change — updating the lighthouse, requerying tunnels — is not the udp
// package's business, so the reaction is injected as a plain function pointer. The monitor calls it once a change
// has settled and stays ignorant of what it does.
//
// On platforms whose sockets do not go stale, watchNetworkChanges hands back a nil channel and Start returns.
type NetworkChangeMonitor struct {
	l       *slog.Logger
	ctx     context.Context
	enabled bool
	// rebind is what we call once a change has settled. It is injected because the udp package has no business
	// knowing what a rebind entails, only when one is warranted.
	rebind func()
}

// NewNetworkChangeMonitor builds a monitor that calls rebind whenever the local network moves. The returned monitor
// is always usable: Start is safe to call unconditionally, it no-ops when disabled or on a platform that does not
// need it.
func NewNetworkChangeMonitor(ctx context.Context, l *slog.Logger, c *config.C, rebind func()) *NetworkChangeMonitor {
	return &NetworkChangeMonitor{
		l:       l,
		ctx:     ctx,
		enabled: c.GetBool("listen.rebind_on_network_change", true),
		rebind:  rebind,
	}
}

// Start watches for network changes until the context is cancelled, calling rebind once per settled change. It
// blocks, so callers run it in a goroutine, and it no-ops when disabled, unsupported, or with nothing to rebind.
func (m *NetworkChangeMonitor) Start() {
	if !m.enabled || m.rebind == nil || m.ctx.Err() != nil {
		return
	}

	changes, err := watchNetworkChanges(m.ctx, m.l)
	if err != nil {
		// Not fatal. Everything else still works, we just won't notice a network change on our own.
		m.l.Error("Failed to watch for network changes, will not rebind the udp listener when the network moves",
			"error", err,
		)
		return
	}

	if changes == nil {
		// This platform's sockets don't go stale, so there is nothing to watch for.
		return
	}

	m.l.Info("Watching for network changes to rebind the udp listener")

	for range changes {
		m.l.Info("Local network changed, rebinding the udp listener")
		m.rebind()
	}
}
