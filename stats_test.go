package nebula

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStatsServer(t *testing.T) (*statsServer, *config.C) {
	t.Helper()
	l := slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &statsServer{
		l:   l,
		ctx: ctx,
	}, config.NewC(l)
}

func setStatsConfig(c *config.C, m map[string]any) {
	c.Settings["stats"] = m
}

func currentRuntime(s *statsServer) *statsRuntime {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.run
}

func TestStatsServer_reload_initial_disabled(t *testing.T) {
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{"type": "none"})

	require.NoError(t, s.reload(c, true))
	assert.False(t, s.enabled.Load())
	assert.Nil(t, currentRuntime(s))
}

func TestStatsServer_reload_initial_invalidInterval(t *testing.T) {
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":   "graphite",
		"host":   "127.0.0.1:0",
		"prefix": "test",
	})

	err := s.reload(c, true)
	require.Error(t, err)
	assert.False(t, s.enabled.Load())
}

func TestStatsServer_reload_initial_unknownType(t *testing.T) {
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "carbon",
		"interval": "1s",
	})

	err := s.reload(c, true)
	require.Error(t, err)
	assert.False(t, s.enabled.Load())
}

func TestStatsServer_reload_unchanged_noOp(t *testing.T) {
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{"type": "none"})

	require.NoError(t, s.reload(c, true))
	require.NoError(t, s.reload(c, false))
	assert.False(t, s.enabled.Load())
}

func TestStatsServer_reload_initial_graphite(t *testing.T) {
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "graphite",
		"interval": "1s",
		"protocol": "tcp",
		"host":     "127.0.0.1:2003",
		"prefix":   "test",
	})

	require.NoError(t, s.reload(c, true))
	assert.True(t, s.enabled.Load())
	// reload only records config; Start builds the runtime.
	assert.Nil(t, currentRuntime(s))
}

func TestStatsServer_reload_initial_prometheus(t *testing.T) {
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:0",
		"path":     "/metrics",
	})

	require.NoError(t, s.reload(c, true))
	assert.True(t, s.enabled.Load())
	// reload only records config; Start builds the runtime.
	assert.Nil(t, currentRuntime(s))
}

func TestStatsServer_Start_graphite_blocksUntilStop(t *testing.T) {
	sink := newGraphiteSink(t)
	defer sink.Close()

	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "graphite",
		"interval": "1s",
		"protocol": "tcp",
		"host":     sink.Addr(),
		"prefix":   "test",
	})
	require.NoError(t, s.reload(c, true))

	done := make(chan struct{})
	go func() {
		s.Start()
		close(done)
	}()

	// Wait for Start to publish runtime state.
	waitFor(t, func() bool { return currentRuntime(s) != nil })
	rt := currentRuntime(s)
	require.NotNil(t, rt)
	assert.Nil(t, rt.listener, "graphite has no listener")

	s.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("graphite Start did not return after Stop")
	}
	assert.Nil(t, currentRuntime(s))
}

func TestStatsServer_StartStop_lifecycle(t *testing.T) {
	port := freeTCPPort(t)
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port,
		"path":     "/metrics",
	})
	require.NoError(t, s.reload(c, true))

	done := make(chan struct{})
	go func() {
		s.Start()
		close(done)
	}()

	waitForListening(t, "127.0.0.1:"+port)
	rt := currentRuntime(s)
	require.NotNil(t, rt)
	require.NotNil(t, rt.listener)

	s.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
	assert.Nil(t, currentRuntime(s))
}

func TestStatsServer_reload_disable_stopsRunningRuntime(t *testing.T) {
	port := freeTCPPort(t)
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port,
		"path":     "/metrics",
	})
	require.NoError(t, s.reload(c, true))

	done := make(chan struct{})
	go func() {
		s.Start()
		close(done)
	}()
	waitForListening(t, "127.0.0.1:"+port)

	setStatsConfig(c, map[string]any{"type": "none"})
	require.NoError(t, s.reload(c, false))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after reload disabled stats")
	}
	assert.False(t, s.enabled.Load())
	assert.Nil(t, currentRuntime(s))
}

func TestStatsServer_reload_changeListener_restartsListener(t *testing.T) {
	port1 := freeTCPPort(t)
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port1,
		"path":     "/metrics",
	})
	require.NoError(t, s.reload(c, true))

	firstDone := make(chan struct{})
	go func() {
		s.Start()
		close(firstDone)
	}()
	waitForListening(t, "127.0.0.1:"+port1)
	first := currentRuntime(s)
	require.NotNil(t, first)

	port2 := freeTCPPort(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port2,
		"path":     "/metrics",
	})
	require.NoError(t, s.reload(c, false))

	select {
	case <-firstDone:
	case <-time.After(5 * time.Second):
		t.Fatal("old Start did not return after reload")
	}

	waitForListening(t, "127.0.0.1:"+port2)
	second := currentRuntime(s)
	require.NotNil(t, second)
	assert.NotSame(t, first, second, "expected a new runtime after listen address change")

	s.Stop()
}

func TestStatsServer_Stop_beforeStart_doesNotBlock(t *testing.T) {
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:0",
		"path":     "/metrics",
	})
	require.NoError(t, s.reload(c, true))

	stopped := make(chan struct{})
	go func() {
		s.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop hung with no runtime started")
	}
}

func TestStatsServer_configTest_validatesWithoutSpawning(t *testing.T) {
	s, c := newTestStatsServer(t)
	s.configTest = true
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:0",
		"path":     "/metrics",
	})

	require.NoError(t, s.reload(c, true))
	s.Start()
	assert.Nil(t, currentRuntime(s))
}

func TestStatsServer_ctxCancel_unblocksStart(t *testing.T) {
	// Ensures ctx cancellation alone (no explicit Stop) tears down both
	// graphite and prom Start invocations.
	port := freeTCPPort(t)
	l := slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &statsServer{l: l, ctx: ctx}
	c := config.NewC(l)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port,
		"path":     "/metrics",
	})
	require.NoError(t, s.reload(c, true))

	done := make(chan struct{})
	go func() {
		s.Start()
		close(done)
	}()
	waitForListening(t, "127.0.0.1:"+port)

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
}

func TestStatsServer_listenerBindFailure_sameCfgReloadRetries(t *testing.T) {
	// Hold the port so ListenAndServe will fail on first Start.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(blocker.Addr().(*net.TCPAddr).Port)

	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port,
		"path":     "/metrics",
	})
	require.NoError(t, s.reload(c, true))

	done := make(chan struct{})
	go func() {
		s.Start()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after bind failure")
	}
	// Bind failure should have dropped the cached config so a same-cfg
	// SIGHUP can retry.
	s.runMu.Lock()
	cfgAfterFailure := s.runCfg
	s.runMu.Unlock()
	assert.Nil(t, cfgAfterFailure)

	// Free the port and reload with the same config; Start should fire again.
	require.NoError(t, blocker.Close())
	require.NoError(t, s.reload(c, false))

	waitForListening(t, "127.0.0.1:"+port)
	require.NotNil(t, currentRuntime(s))

	s.Stop()
}

func waitForListening(t *testing.T, addr string) {
	t.Helper()
	waitFor(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
}

// graphiteSink is a minimal TCP accept-and-discard server so graphite.Once
// calls in tests don't spam error logs or wedge on connection refused.
type graphiteSink struct {
	ln net.Listener
}

func newGraphiteSink(t *testing.T) *graphiteSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	g := &graphiteSink{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}(conn)
		}
	}()
	return g
}

func (g *graphiteSink) Addr() string { return g.ln.Addr().String() }
func (g *graphiteSink) Close()       { _ = g.ln.Close() }

func freeTCPPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return strconv.Itoa(port)
}
