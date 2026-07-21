package nebula

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/udp"
)

// networkChangeMonitor rebinds the udp listener when the local network moves.
//
// The detection lives in the udp package, next to the socket it concerns and the platform matrix that already knows
// which sockets go stale. This side owns the reaction, because updating the lighthouse and requerying tunnels are
// not the udp package's business. On platforms that do not need it, udp hands back a nil channel and Start returns.
type networkChangeMonitor struct {
	l   *slog.Logger
	ctx context.Context

	// enabled mirrors the config knob. Start consults it so callers don't need to know the gating rules.
	enabled atomic.Bool

	runMu sync.Mutex
	run   *networkChangeRuntime // non-nil while a watch is live
	// rebind is what we call once a change has settled. It is guarded because it lands after we are already
	// reachable by a reload, see setRebind.
	rebind func()
}

// networkChangeRuntime is the live state owned by a single Start invocation. Start stashes a pointer under runMu so
// Stop and Start's own exit path can tell "my runtime" apart from one that replaced it after a reload.
type networkChangeRuntime struct {
	cancel context.CancelFunc
}

// newNetworkChangeMonitorFromConfig builds a networkChangeMonitor and registers its reload callback. The callback is
// registered before the initial config is applied so a SIGHUP can turn this on later even if it started out off.
//
// The returned pointer is always usable. Start is safe to call unconditionally, it no-ops when disabled.
func newNetworkChangeMonitorFromConfig(ctx context.Context, l *slog.Logger, c *config.C) *networkChangeMonitor {
	m := &networkChangeMonitor{
		l:   l,
		ctx: ctx,
	}

	c.RegisterReloadCallback(func(c *config.C) {
		m.reload(c, false)
	})
	m.reload(c, true)

	return m
}

// setRebind wires up what to call when the network changes. Control owns rebinding and the state gating around it,
// and Control is built after we are, so this cannot be a constructor argument. By then a SIGHUP can already reach
// reload, hence the lock.
func (m *networkChangeMonitor) setRebind(rebind func()) {
	m.runMu.Lock()
	defer m.runMu.Unlock()
	m.rebind = rebind
}

// reload applies the config knob. On the initial pass it only records the value, Control.Start is what launches the
// first watch. After that a change starts or stops us to match.
func (m *networkChangeMonitor) reload(c *config.C, initial bool) {
	enabled := c.GetBool("listen.rebind_on_network_change", true)
	was := m.enabled.Swap(enabled)
	if initial || enabled == was {
		return
	}

	if enabled {
		go m.Start()
	} else {
		m.l.Info("No longer watching for network changes to rebind the udp listener")
		m.Stop()
	}
}

// Start watches for network changes until the context is cancelled or Stop is called. It blocks, so callers run it
// in a goroutine, and it no-ops when disabled, unsupported, or when there is nothing to rebind yet.
func (m *networkChangeMonitor) Start() {
	if !m.enabled.Load() {
		return
	}

	m.runMu.Lock()
	if m.ctx.Err() != nil || m.run != nil || m.rebind == nil {
		m.runMu.Unlock()
		return
	}
	rebind := m.rebind

	ctx, cancel := context.WithCancel(m.ctx)
	changes, err := udp.WatchNetworkChanges(ctx, m.l)
	if err != nil {
		cancel()
		m.runMu.Unlock()
		// Not fatal. Everything else still works, we just won't notice a network change on our own.
		m.l.Error("Failed to watch for network changes, will not rebind the udp listener when the network moves",
			"error", err,
		)
		return
	}

	if changes == nil {
		// This platform's sockets don't go stale, so there is nothing to watch for.
		cancel()
		m.runMu.Unlock()
		return
	}

	rt := &networkChangeRuntime{cancel: cancel}
	m.run = rt
	m.runMu.Unlock()

	m.l.Info("Watching for network changes to rebind the udp listener")

	for range changes {
		m.l.Info("Local network changed, rebinding the udp listener")
		rebind()
	}

	cancel()

	m.runMu.Lock()
	if m.run == rt {
		m.run = nil
	}
	m.runMu.Unlock()
}

// Stop ends the current watch, if any. It is idempotent.
func (m *networkChangeMonitor) Stop() {
	m.runMu.Lock()
	rt := m.run
	m.run = nil
	m.runMu.Unlock()

	if rt != nil {
		rt.cancel()
	}
}
