//go:build darwin && !ios && !e2e_testing
// +build darwin,!ios,!e2e_testing

package nebula

import (
	"context"
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// These are darwin only because that is the one platform where udp.WatchNetworkChanges hands back a real channel.
// Everywhere else Start correctly returns immediately and there is no lifecycle to exercise.

func running(m *networkChangeMonitor) bool {
	m.runMu.Lock()
	defer m.runMu.Unlock()
	return m.run != nil
}

func TestNetworkChangeMonitorStartStop(t *testing.T) {
	// IgnoreCurrent because other tests in this package leave readers running; we only care about what this test
	// leaks itself.
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	l := test.NewLogger()
	c := config.NewC(l)
	// Deliberately says nothing about rebinding, so this also covers the default
	require.NoError(t, c.LoadString("listen:\n  host: 0.0.0.0\n"))

	m := newNetworkChangeMonitorFromConfig(context.Background(), l, c)
	assert.True(t, m.enabled.Load(), "should default to on")

	// Nothing to rebind yet, so Start must decline rather than sit on an open socket
	m.Start()
	assert.False(t, running(m), "Start without a rebind target should not leave a runtime behind")

	m.setRebind(func() {})

	done := make(chan struct{})
	go func() {
		m.Start()
		close(done)
	}()

	assert.Eventually(t, func() bool { return running(m) }, time.Second*5, time.Millisecond*10,
		"Start should register a runtime")

	m.Stop()
	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Fatal("Start did not return after Stop")
	}

	assert.False(t, running(m), "Stop should clear the runtime")

	m.Stop() // idempotent
}

func TestNetworkChangeMonitorStopsWithContext(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString("listen:\n  rebind_on_network_change: true\n"))

	ctx, cancel := context.WithCancel(context.Background())
	m := newNetworkChangeMonitorFromConfig(ctx, l, c)
	m.setRebind(func() {})

	done := make(chan struct{})
	go func() {
		m.Start()
		close(done)
	}()

	assert.Eventually(t, func() bool { return running(m) }, time.Second*5, time.Millisecond*10)

	// Cancelling the daemon context has to be enough on its own, Control.Stop never calls m.Stop directly
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Fatal("Start did not return after the context was cancelled")
	}

	// Start after the context is dead must not open anything
	m.Start()
	assert.False(t, running(m))
}

func TestNetworkChangeMonitorReloadTogglesWatch(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	l := test.NewLogger()
	off := config.NewC(l)
	require.NoError(t, off.LoadString("listen:\n  rebind_on_network_change: false\n"))

	m := newNetworkChangeMonitorFromConfig(context.Background(), l, off)
	m.setRebind(func() {})
	require.False(t, m.enabled.Load())

	// Turning it on with a HUP should start watching without anyone calling Start again
	on := config.NewC(l)
	require.NoError(t, on.LoadString("listen:\n  rebind_on_network_change: true\n"))
	m.reload(on, false)

	assert.Eventually(t, func() bool { return running(m) }, time.Second*5, time.Millisecond*10,
		"reload to enabled should start watching")

	// And turning it back off should stop it
	m.reload(off, false)
	assert.Eventually(t, func() bool { return !running(m) }, time.Second*5, time.Millisecond*10,
		"reload to disabled should stop watching")
}

func TestNetworkChangeMonitorDisabledByConfig(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString("listen:\n  rebind_on_network_change: false\n"))

	m := newNetworkChangeMonitorFromConfig(context.Background(), l, c)
	m.setRebind(func() {})
	assert.False(t, m.enabled.Load())

	m.Start()
	assert.False(t, running(m), "disabled Start should be a no-op")
}
