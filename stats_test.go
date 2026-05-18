package nebula

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
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
	h := newGraphiteHost(t, 0)

	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":     "graphite",
		"interval": "1s",
		"protocol": "tcp",
		"host":     h.ln.Addr().String(),
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

// stopAtCleanup returns the ctx to build *s with, and stops it when the test ends. Cancelling first turns away a Start
// a reload spawned that hasn't run yet, then Stop waits out the last pass, so nothing captures into the next test
func stopAtCleanup(t *testing.T, s **statsServer) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		if *s != nil {
			(*s).Stop()
		}
	})
	return ctx
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return strconv.Itoa(port)
}

// Each export has to see what emitStats set in the same pass
func TestStatsServer_emitStatsRunsBeforeExport(t *testing.T) {
	defer metrics.DefaultRegistry.Unregister("emitter.order.test")

	l := slog.New(slog.DiscardHandler)
	c := config.NewC(l)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1s",
		"listen":   "127.0.0.1:0",
		"path":     "/metrics",
	})
	gauge := metrics.GetOrRegisterGauge("emitter.order.test", nil)
	s, err := newStatsServerFromConfig(t.Context(), l, c, "", false, func() { gauge.Update(42) })
	require.NoError(t, err)

	s.runMu.Lock()
	fns, srv := s.buildRuntime(t.Context(), *s.runCfg)
	s.runMu.Unlock()
	require.NotNil(t, srv)
	for _, fn := range fns {
		fn()
	}

	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	assert.Contains(t, rec.Body.String(), "emitter_order_test 42")
}

// A scrape that lands the moment the listener is up already sees what emitStats set (issue #907)
func TestStatsServer_Start_primesBeforeServing(t *testing.T) {
	defer metrics.DefaultRegistry.Unregister("prime.before.serving")

	port := freeTCPPort(t)
	l := slog.New(slog.DiscardHandler)
	c := config.NewC(l)
	setStatsConfig(c, map[string]any{
		"type":     "prometheus",
		"interval": "1h",
		"listen":   "127.0.0.1:" + port,
		"path":     "/metrics",
	})
	gauge := metrics.GetOrRegisterGauge("prime.before.serving", nil)
	// The pause would let a listener that came up before the prime serve the zero value
	var s *statsServer
	ctx := stopAtCleanup(t, &s)
	s, err := newStatsServerFromConfig(ctx, l, c, "", false, func() {
		time.Sleep(200 * time.Millisecond)
		gauge.Update(42)
	})
	require.NoError(t, err)

	go s.Start()
	waitForListening(t, "127.0.0.1:"+port)

	resp, err := http.Get("http://127.0.0.1:" + port + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "prime_before_serving 42")
}

// Start captures once before the first tick, the interval here is an hour
func TestStatsServer_Start_primes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	l := slog.New(slog.DiscardHandler)
	c := config.NewC(l)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "1h", "host": ln.Addr().String()})
	primed := make(chan struct{}, 1)
	var s *statsServer
	ctx := stopAtCleanup(t, &s)
	s, err = newStatsServerFromConfig(ctx, l, c, "", false, func() {
		select {
		case primed <- struct{}{}:
		default:
		}
	})
	require.NoError(t, err)

	go s.Start()
	select {
	case <-primed:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was captured before the first tick")
	}
}

// Graphite has to ship what emitStats set in the same pass, not the pass before
func TestStatsServer_emitStatsRunsBeforeGraphiteExport(t *testing.T) {
	defer metrics.DefaultRegistry.Unregister("emitter.graphite.test")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		b, _ := io.ReadAll(conn)
		received <- string(b)
	}()

	l := slog.New(slog.DiscardHandler)
	c := config.NewC(l)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "1h", "host": ln.Addr().String()})
	gauge := metrics.GetOrRegisterGauge("emitter.graphite.test", nil)
	s, err := newStatsServerFromConfig(t.Context(), l, c, "", false, func() { gauge.Update(42) })
	require.NoError(t, err)

	s.runMu.Lock()
	fns, _ := s.buildRuntime(t.Context(), *s.runCfg)
	s.runMu.Unlock()
	for _, fn := range fns {
		fn()
	}

	select {
	case body := <-received:
		assert.Contains(t, body, ".emitter.graphite.test.value 42 ")
	case <-time.After(5 * time.Second):
		t.Fatal("graphite sent nothing")
	}
}

// stats.interval reloads, and the runtime a reload starts still has emitStats
func TestStatsServer_reloadMovesTheInterval(t *testing.T) {
	var passes atomic.Int64
	l := slog.New(slog.DiscardHandler)
	c := config.NewC(l)
	// Nothing listens here, each export fails at once
	host := "127.0.0.1:" + freeTCPPort(t)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "1h", "host": host})
	var s *statsServer
	ctx := stopAtCleanup(t, &s)
	s, err := newStatsServerFromConfig(ctx, l, c, "", false, func() { passes.Add(1) })
	require.NoError(t, err)
	go s.Start()
	waitFor(t, func() bool { return passes.Load() == 1 })

	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "20ms", "host": host})
	require.NoError(t, s.reload(c, false))
	waitFor(t, func() bool { return passes.Load() >= 6 })

	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "1h", "host": host})
	require.NoError(t, s.reload(c, false))
	// The reload's Stop waited out the 20ms loop. The new runtime's prime may land either side of this read, it is the
	// only pass left to come
	stopped := passes.Load()
	time.Sleep(300 * time.Millisecond)
	assert.LessOrEqual(t, passes.Load()-stopped, int64(1), "the 20ms loop kept running after the reload")
}

// A reload's new runtime never captures while the old one is still in a pass, go-metrics keeps its GC capture state
// in unguarded globals
func TestStatsServer_reloadWaitsForTheLastPass(t *testing.T) {
	var active, most atomic.Int64
	l := slog.New(slog.DiscardHandler)
	c := config.NewC(l)
	host := "127.0.0.1:" + freeTCPPort(t)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "10ms", "host": host})
	var s *statsServer
	ctx := stopAtCleanup(t, &s)
	s, err := newStatsServerFromConfig(ctx, l, c, "", false, func() {
		n := active.Add(1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		// Long enough that a reload almost always lands mid pass
		time.Sleep(50 * time.Millisecond)
		active.Add(-1)
	})
	require.NoError(t, err)
	go s.Start()

	for i := range 6 {
		setStatsConfig(c, map[string]any{"type": "graphite", "interval": fmt.Sprintf("%dms", 11-i%2), "host": host})
		require.NoError(t, s.reload(c, false))
		time.Sleep(30 * time.Millisecond)
	}
	assert.Equal(t, int64(1), most.Load())
}

// Nothing captures once Stop returns, a pass in progress is waited out
func TestStatsServer_Stop_waitsForThePass(t *testing.T) {
	var inPass atomic.Bool
	entered := make(chan struct{}, 1)
	l := slog.New(slog.DiscardHandler)
	c := config.NewC(l)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "1h", "host": "127.0.0.1:" + freeTCPPort(t)})
	var s *statsServer
	ctx := stopAtCleanup(t, &s)
	s, err := newStatsServerFromConfig(ctx, l, c, "", false, func() {
		inPass.Store(true)
		select {
		case entered <- struct{}{}:
		default:
		}
		time.Sleep(100 * time.Millisecond)
		inPass.Store(false)
	})
	require.NoError(t, err)

	go s.Start()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("never captured")
	}
	s.Stop()
	assert.False(t, inPass.Load(), "Stop returned with a pass still running")
}

// A Start that arrives while Stop waits out the last pass doesn't capture alongside it
func TestStatsServer_Start_duringStopWaitsForThePass(t *testing.T) {
	var active, most atomic.Int64
	entered := make(chan struct{}, 1)
	l := slog.New(slog.DiscardHandler)
	c := config.NewC(l)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "1h", "host": "127.0.0.1:" + freeTCPPort(t)})
	var s *statsServer
	ctx := stopAtCleanup(t, &s)
	s, err := newStatsServerFromConfig(ctx, l, c, "", false, func() {
		n := active.Add(1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		select {
		case entered <- struct{}{}:
		default:
		}
		time.Sleep(200 * time.Millisecond)
		active.Add(-1)
	})
	require.NoError(t, err)

	go s.Start()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("never captured")
	}
	stopped := make(chan struct{})
	go func() {
		s.Stop()
		close(stopped)
	}()
	// Stop holds runMu for its whole wait, the next Start has to arrive after it took it
	waitFor(t, func() bool {
		if s.runMu.TryLock() {
			s.runMu.Unlock()
			return false
		}
		return true
	})
	go s.Start()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}
	waitFor(t, func() bool { return len(entered) == 1 })
	assert.Equal(t, int64(1), most.Load(), "a Start captured alongside the pass Stop was waiting out")
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

	_, server := s.buildRuntime(t.Context(), cfg)
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

// TestWrapPromHandler_ZeroTimeoutPassesThrough asserts that the wrap
// is truly a noop when handlerTimeout is 0 - the returned handler is
// the same function value as the input, so a future edit that
// accidentally wraps with a zero timeout is caught.
func TestWrapPromHandler_ZeroTimeoutPassesThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	innerPC := reflect.ValueOf(inner).Pointer()

	got := wrapPromHandler(inner, 0)
	gotFn, ok := got.(http.HandlerFunc)
	require.True(t, ok, "wrapPromHandler with handlerTimeout=0 must return the input handler type")
	require.Equal(t, innerPC, reflect.ValueOf(gotFn).Pointer(),
		"wrapPromHandler must return its input unchanged when handlerTimeout is 0")

	gotNeg := wrapPromHandler(inner, -1*time.Second)
	gotNegFn, ok := gotNeg.(http.HandlerFunc)
	require.True(t, ok, "wrapPromHandler with negative handlerTimeout must return the input handler type")
	require.Equal(t, innerPC, reflect.ValueOf(gotNegFn).Pointer(),
		"wrapPromHandler must return its input unchanged when handlerTimeout is negative")
}

// TestWrapPromHandler_FiresOn503 asserts the integration: a real
// httptest listener, a deliberately slow handler, GET via the standard
// HTTP client, and a 503 + the canned timeout body. Gated by
// testing.Short because it sleeps ~150ms total.
func TestWrapPromHandler_FiresOn503(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: real listener + 150ms wait for timeout handler to fire")
	}
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep well past the handlerTimeout to guarantee the wrap fires.
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("would-have-been-the-real-body"))
	})
	wrapped := wrapPromHandler(slow, 50*time.Millisecond)
	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"a slow handler must surface as 503 via TimeoutHandler")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), promScrapeTimeoutBody,
		"the canned timeout body must reach the client")
	assert.NotContains(t, string(body), "would-have-been-the-real-body",
		"the slow handler's body must NOT leak through the wrap")
}

// TestWrapPromHandler_NoWrap_ResponseFlowsThrough asserts that when
// handlerTimeout is 0 the real response body reaches the client even
// when the handler is slightly slow. Cheap (no sleep needed) and proves
// the conditional in wrapPromHandler did the right thing end-to-end.
func TestWrapPromHandler_NoWrap_ResponseFlowsThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("real-body"))
	})
	wrapped := wrapPromHandler(inner, 0)
	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "real-body", string(body),
		"with handlerTimeout=0 the real response body must reach the client")
}

// TestStatsServer_Slowloris_ReadHeaderTimeout proves the slowloris
// defense end-to-end: configure a tight ReadHeaderTimeout, start the
// real listener, open a raw TCP connection, write a partial header
// line, and assert the server closes the connection before our read
// deadline. Gated by testing.Short because it waits ~250ms for the
// server-side timeout to fire.
func TestStatsServer_Slowloris_ReadHeaderTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: real listener + 250ms wait for ReadHeaderTimeout to fire")
	}
	port := freeTCPPort(t)
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{
		"type":                "prometheus",
		"interval":            "1s",
		"listen":              "127.0.0.1:" + port,
		"path":                "/metrics",
		"read_header_timeout": "200ms",
	})
	require.NoError(t, s.reload(c, true))

	done := make(chan struct{})
	go func() {
		s.Start()
		close(done)
	}()
	t.Cleanup(func() {
		s.Stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("stats server did not stop")
		}
	})
	waitForListening(t, "127.0.0.1:"+port)

	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	require.NoError(t, err)
	defer conn.Close()

	// Write a request line + one header but no terminating CRLF, then
	// stop. A non-defended server would block here forever; this server
	// must tear down the connection within ReadHeaderTimeout (200ms).
	_, err = conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost: localhost"))
	require.NoError(t, err)

	// Give the server slightly more than ReadHeaderTimeout to react.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(1*time.Second)))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	require.Error(t, readErr,
		"server must close the partial-header connection within ReadHeaderTimeout")
}
