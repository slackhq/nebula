package nebula

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStatsServer(t *testing.T) (*statsServer, *config.C) {
	t.Helper()
	l := logrus.New()
	l.Out = io.Discard
	return &statsServer{
		l:   l,
		ctx: context.Background(),
	}, config.NewC(l)
}

func setStatsConfig(c *config.C, m map[string]any) {
	c.Settings["stats"] = m
}

func TestStatsServer_reload_initial_disabled(t *testing.T) {
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{"type": "none"})

	require.NoError(t, s.reload(c, true))
	assert.False(t, s.enabled.Load())
	assert.Nil(t, s.listener)
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
	// Same config; second reload must be a no-op.
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
	assert.Nil(t, s.listener) // graphite has no listener
	require.NotNil(t, s.runCancel)

	s.Stop()
	assert.False(t, s.enabled.Load())
}

func TestStatsServer_reload_initial_prometheus(t *testing.T) {
	port := freeTCPPort(t)
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port,
		"path":     "/metrics",
	})

	require.NoError(t, s.reload(c, true))
	assert.True(t, s.enabled.Load())
	require.NotNil(t, s.listener)
	require.NotNil(t, s.runCancel)

	s.Stop()
	assert.False(t, s.enabled.Load())
	assert.Nil(t, s.listener)
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
	require.NotNil(t, s.listener)
	require.NotNil(t, s.runCancel)

	// Toggle stats off; reload should tear the runtime down.
	setStatsConfig(c, map[string]any{"type": "none"})
	require.NoError(t, s.reload(c, false))
	assert.False(t, s.enabled.Load())
	assert.Nil(t, s.listener)
	assert.Nil(t, s.runCancel)
}

func TestStatsServer_reload_changeListener_restartsListener(t *testing.T) {
	s, c := newTestStatsServer(t)
	port1 := freeTCPPort(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port1,
		"path":     "/metrics",
	})

	require.NoError(t, s.reload(c, true))
	first := s.listener
	require.NotNil(t, first)

	port2 := freeTCPPort(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port2,
		"path":     "/metrics",
	})

	require.NoError(t, s.reload(c, false))
	second := s.listener
	require.NotNil(t, second)
	assert.NotSame(t, first, second, "expected a new http.Server after listen address change")

	s.Stop()
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

	// Wait for the listener to actually accept connections.
	waitFor(t, func() bool {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})

	s.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestStatsServer_Stop_beforeStart_doesNotBlock(t *testing.T) {
	port := freeTCPPort(t)
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port,
		"path":     "/metrics",
	})
	require.NoError(t, s.reload(c, true))

	// Stop without ever calling Start. http.Server.Shutdown handles this:
	// inShutdown is set, and any subsequent Start would see ErrServerClosed.
	stopped := make(chan struct{})
	go func() {
		s.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop hung when Start was never called")
	}

	// Start now should be a quick no-op since enabled is false after Stop.
	done := make(chan struct{})
	go func() {
		s.Start()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start hung after Stop")
	}
}

func TestStatsServer_configTest_validatesWithoutSpawning(t *testing.T) {
	port := freeTCPPort(t)
	s, c := newTestStatsServer(t)
	s.configTest = true
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:" + port,
		"path":     "/metrics",
	})

	require.NoError(t, s.reload(c, true))
	// configTest mode validates but never spawns or binds.
	assert.False(t, s.enabled.Load())
	assert.Nil(t, s.listener)
	assert.Nil(t, s.runCancel)
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return strconv.Itoa(port)
}
