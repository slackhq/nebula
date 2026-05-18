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

// TestStatsServer_buildRuntime_AppliesDefaultTimeouts asserts the full
// pipeline: with no timeout keys set, loadStatsConfig substitutes the
// default constants, and buildRuntime forwards them onto the
// *http.Server. A future edit that drops a field is caught at the
// source rather than only surfacing as a missing slowloris defense in
// production.
func TestStatsServer_buildRuntime_AppliesDefaultTimeouts(t *testing.T) {
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:0",
		"path":     "/metrics",
	})
	cfg, err := loadStatsConfig(c)
	require.NoError(t, err)

	_, server := s.buildRuntime(cfg)
	require.NotNil(t, server, "prometheus config must produce an *http.Server")

	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadHeaderTimeout", server.ReadHeaderTimeout, defaultStatsReadHeaderTimeout},
		{"ReadTimeout", server.ReadTimeout, defaultStatsReadTimeout},
		{"WriteTimeout", server.WriteTimeout, defaultStatsWriteTimeout},
		{"IdleTimeout", server.IdleTimeout, defaultStatsIdleTimeout},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got,
				"%s must be set to its default constant", tc.name)
		})
	}
	assert.Equal(t, defaultStatsHandlerTimeout, cfg.prom.handlerTimeout,
		"cfg.prom.handlerTimeout must default to defaultStatsHandlerTimeout")
}

// TestLoadStatsConfig_PromTimeouts_Overrides asserts that each
// stats.*_timeout YAML key overrides the corresponding default. One
// row per key plus a final row asserting all keys overridden together,
// which catches plumbing mistakes where one key's value silently lands
// in another field.
func TestLoadStatsConfig_PromTimeouts_Overrides(t *testing.T) {
	tests := []struct {
		name     string
		override map[string]any
		want     promConfig
	}{
		{
			name:     "read_header_timeout only",
			override: map[string]any{"read_header_timeout": "3s"},
			want: promConfig{
				readHeaderTimeout: 3 * time.Second,
				readTimeout:       defaultStatsReadTimeout,
				writeTimeout:      defaultStatsWriteTimeout,
				idleTimeout:       defaultStatsIdleTimeout,
				handlerTimeout:    defaultStatsHandlerTimeout,
			},
		},
		{
			name:     "read_timeout only",
			override: map[string]any{"read_timeout": "7s"},
			want: promConfig{
				readHeaderTimeout: defaultStatsReadHeaderTimeout,
				readTimeout:       7 * time.Second,
				writeTimeout:      defaultStatsWriteTimeout,
				idleTimeout:       defaultStatsIdleTimeout,
				handlerTimeout:    defaultStatsHandlerTimeout,
			},
		},
		{
			name:     "write_timeout only",
			override: map[string]any{"write_timeout": "45s"},
			want: promConfig{
				readHeaderTimeout: defaultStatsReadHeaderTimeout,
				readTimeout:       defaultStatsReadTimeout,
				writeTimeout:      45 * time.Second,
				idleTimeout:       defaultStatsIdleTimeout,
				handlerTimeout:    defaultStatsHandlerTimeout,
			},
		},
		{
			name:     "idle_timeout only",
			override: map[string]any{"idle_timeout": "200s"},
			want: promConfig{
				readHeaderTimeout: defaultStatsReadHeaderTimeout,
				readTimeout:       defaultStatsReadTimeout,
				writeTimeout:      defaultStatsWriteTimeout,
				idleTimeout:       200 * time.Second,
				handlerTimeout:    defaultStatsHandlerTimeout,
			},
		},
		{
			name:     "handler_timeout zero disables the wrap",
			override: map[string]any{"handler_timeout": "0s"},
			want: promConfig{
				readHeaderTimeout: defaultStatsReadHeaderTimeout,
				readTimeout:       defaultStatsReadTimeout,
				writeTimeout:      defaultStatsWriteTimeout,
				idleTimeout:       defaultStatsIdleTimeout,
				handlerTimeout:    0,
			},
		},
		{
			name: "all five overridden together",
			override: map[string]any{
				"read_header_timeout": "1s",
				"read_timeout":        "2s",
				"write_timeout":       "3s",
				"idle_timeout":        "4s",
				"handler_timeout":     "5s",
			},
			want: promConfig{
				readHeaderTimeout: 1 * time.Second,
				readTimeout:       2 * time.Second,
				writeTimeout:      3 * time.Second,
				idleTimeout:       4 * time.Second,
				handlerTimeout:    5 * time.Second,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, c := newTestStatsServer(t)
			base := map[string]any{
				"type":     "prometheus",
				"interval": "1s",
				"listen":   "127.0.0.1:0",
				"path":     "/metrics",
			}
			for k, v := range tc.override {
				base[k] = v
			}
			setStatsConfig(c, base)

			cfg, err := loadStatsConfig(c)
			require.NoError(t, err)
			assert.Equal(t, tc.want.readHeaderTimeout, cfg.prom.readHeaderTimeout, "readHeaderTimeout")
			assert.Equal(t, tc.want.readTimeout, cfg.prom.readTimeout, "readTimeout")
			assert.Equal(t, tc.want.writeTimeout, cfg.prom.writeTimeout, "writeTimeout")
			assert.Equal(t, tc.want.idleTimeout, cfg.prom.idleTimeout, "idleTimeout")
			assert.Equal(t, tc.want.handlerTimeout, cfg.prom.handlerTimeout, "handlerTimeout")
		})
	}
}

// TestLoadStatsConfig_PromTimeouts_NegativeRejected verifies that a
// negative duration on any of the five timeout keys is rejected at
// config-load time. A negative net/http timeout silently breaks the
// server in non-obvious ways (zero would be the safer "no limit"
// interpretation), so we reject rather than silently substitute.
func TestLoadStatsConfig_PromTimeouts_NegativeRejected(t *testing.T) {
	tests := []string{
		"read_header_timeout",
		"read_timeout",
		"write_timeout",
		"idle_timeout",
		"handler_timeout",
	}
	for _, key := range tests {
		t.Run(key, func(t *testing.T) {
			_, c := newTestStatsServer(t)
			setStatsConfig(c, map[string]any{
				"type":     "prometheus",
				"interval": "1s",
				"listen":   "127.0.0.1:0",
				"path":     "/metrics",
				key:        "-5s",
			})
			_, err := loadStatsConfig(c)
			require.Error(t, err, "negative %s must be rejected", key)
			require.Contains(t, err.Error(), "stats."+key,
				"error must name the offending key so the operator can find it")
		})
	}
}

// TestStatsTimeoutDefaults_AreConsistent guards the invariant that
// ReadTimeout must be at least as large as ReadHeaderTimeout. If a
// future edit shortens ReadTimeout below ReadHeaderTimeout, the read
// phase would terminate before headers had a chance to finish - giving
// a generic i/o-timeout instead of the more useful slowloris-shaped
// failure.
func TestStatsTimeoutDefaults_AreConsistent(t *testing.T) {
	require.GreaterOrEqual(t,
		defaultStatsReadTimeout, defaultStatsReadHeaderTimeout,
		"defaultStatsReadTimeout must be >= defaultStatsReadHeaderTimeout")
}
