package nebula

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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

// Each export has to see what the emitters set in the same pass
func TestStatsServer_emittersRunBeforeExport(t *testing.T) {
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

// A scrape that lands the moment the listener is up already sees the emitters' values (issue #907)
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

// Graphite has to ship what the emitters set in the same pass, not the pass before
func TestStatsServer_emittersRunBeforeGraphiteExport(t *testing.T) {
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

// stats.interval reloads, and the runtime a reload starts still has the emitters
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
	time.Sleep(200 * time.Millisecond)
	settled := passes.Load()
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, settled, passes.Load(), "the 20ms loop kept running after the reload")
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
