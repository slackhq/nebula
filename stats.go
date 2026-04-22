package nebula

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	graphite "github.com/cyberdelia/go-metrics-graphite"
	mp "github.com/nbrownus/go-metrics-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/config"
)

// statsServer owns nebula's stats subsystem: the periodic metric capture
// goroutine and (for prometheus) an HTTP listener. It mirrors the lifecycle
// shape of dnsServer: constructor wires the reload callback, reload records
// config, Start builds and runs the runtime, Stop tears it down.
type statsServer struct {
	l            *slog.Logger
	ctx          context.Context
	buildVersion string
	configTest   bool

	// enabled mirrors "stats configured to a real backend". Start consults
	// it so callers don't need to know the gating rules.
	enabled atomic.Bool

	runMu  sync.Mutex
	runCfg *statsConfig
	run    *statsRuntime // non-nil while a runtime is live
}

// statsRuntime is the live state owned by a single Start invocation. Start
// stashes a pointer under runMu; Stop and Start's own exit path use pointer
// equality to tell "my runtime" apart from one that replaced it after a
// reload.
type statsRuntime struct {
	cancel   context.CancelFunc
	listener *http.Server // nil for graphite
}

// statsConfig is the snapshot of stats-related config that drives the runtime.
// It is comparable with == so reload can detect "no change" cheaply.
type statsConfig struct {
	typ      string
	interval time.Duration
	graphite graphiteConfig
	prom     promConfig
}

type graphiteConfig struct {
	protocol string
	host     string
	// resolvedAddr is the string form of host resolved at config-load time.
	// Including it in the struct means a SIGHUP picks up DNS changes even
	// when stats.host hasn't been edited.
	resolvedAddr string
	prefix       string
}

type promConfig struct {
	listen    string
	path      string
	namespace string
	subsystem string
}

// newStatsServerFromConfig builds a statsServer, applies the initial config,
// and registers a reload callback. The reload callback is registered before
// the initial config is applied so a SIGHUP can later enable, fix, or disable
// stats even if the initial application failed.
//
// Start is safe to call unconditionally: it no-ops when stats are disabled.
// The returned pointer is always non-nil, even on error.
func newStatsServerFromConfig(ctx context.Context, l *slog.Logger, c *config.C, buildVersion string, configTest bool) (*statsServer, error) {
	s := &statsServer{
		l:            l,
		ctx:          ctx,
		buildVersion: buildVersion,
		configTest:   configTest,
	}

	c.RegisterReloadCallback(func(c *config.C) {
		if err := s.reload(c, false); err != nil {
			s.l.Error("Failed to reload stats from config", "error", err)
		}
	})

	if err := s.reload(c, true); err != nil {
		return s, err
	}
	return s, nil
}

// reload records the latest config. On the initial call it only records it;
// Control.Start is what launches the first runtime via statsStart. On later
// calls it reconciles the running runtime with the new config:
//
//   - newly enabled -> spawn Start
//   - newly disabled -> Stop the runtime
//   - config changed (still enabled) -> Stop the old, Start the new
//   - no change -> no-op
func (s *statsServer) reload(c *config.C, initial bool) error {
	newCfg, err := loadStatsConfig(c)
	if err != nil {
		return err
	}
	enabled := newCfg.typ != "" && newCfg.typ != "none"

	s.runMu.Lock()
	sameCfg := s.runCfg != nil && *s.runCfg == newCfg
	s.runCfg = &newCfg
	running := s.run != nil
	s.runMu.Unlock()

	s.enabled.Store(enabled)

	if initial || sameCfg {
		return nil
	}

	if running {
		s.Stop()
	}
	if enabled && !s.configTest {
		go s.Start()
	}
	return nil
}

// Start builds the runtime from the latest config, spawns the capture loop,
// and blocks until Stop is called or ctx fires. For prometheus it also serves
// the HTTP listener. For graphite it blocks on the capture loop's context.
// Safe to call when stats are disabled or already running (both no-op).
func (s *statsServer) Start() {
	if !s.enabled.Load() || s.configTest {
		return
	}

	s.runMu.Lock()
	if s.ctx.Err() != nil || s.run != nil || s.runCfg == nil {
		s.runMu.Unlock()
		return
	}
	cfg := *s.runCfg
	captureFns, listener := s.buildRuntime(cfg)
	runCtx, cancel := context.WithCancel(s.ctx)
	rt := &statsRuntime{cancel: cancel, listener: listener}
	s.run = rt
	s.runMu.Unlock()

	go captureStatsLoop(runCtx, cfg.interval, captureFns)

	cleanExit := true
	if listener == nil {
		// Graphite: no HTTP listener to serve; block until teardown.
		<-runCtx.Done()
	} else {
		cleanExit = s.serveListener(listener)
	}

	// Clear our runtime only if nothing has replaced it. Stop races through
	// here too but leaves s.run == nil, so the pointer check skips.
	s.runMu.Lock()
	if s.run == rt {
		rt.cancel()
		s.run = nil
		// A listener that exited with an error (e.g., bind conflict) leaves
		// runCfg cached as if it were applied. Drop it so a SIGHUP with the
		// same config re-triggers Start once the user fixes the underlying
		// problem.
		if !cleanExit {
			s.runCfg = nil
		}
	}
	s.runMu.Unlock()
}

// serveListener runs ListenAndServe and ensures ctx cancellation unblocks it.
// Returns true if the listener exited cleanly (Stop, ctx cancellation, or any
// other http.ErrServerClosed path), false on an unexpected error.
func (s *statsServer) serveListener(listener *http.Server) bool {
	// Per-invocation watcher: ctx cancellation triggers a listener shutdown
	// which in turn unblocks ListenAndServe. Closing `done` on exit keeps
	// the watcher from outliving this call.
	done := make(chan struct{})
	go func() {
		select {
		case <-s.ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := listener.Shutdown(shutdownCtx); err != nil {
				s.l.Warn("Failed to shut down prometheus stats listener", "error", err)
			}
		case <-done:
		}
	}()
	defer close(done)

	s.l.Info("Starting prometheus stats listener", "addr", listener.Addr)
	err := listener.ListenAndServe()
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return true
	}
	s.l.Error("Prometheus stats listener exited", "error", err)
	return false
}

// Stop tears down the active runtime, if any. Idempotent.
func (s *statsServer) Stop() {
	s.runMu.Lock()
	rt := s.run
	s.run = nil
	s.runMu.Unlock()
	if rt == nil {
		return
	}
	rt.cancel()
	if rt.listener != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := rt.listener.Shutdown(shutdownCtx); err != nil {
			s.l.Warn("Failed to shut down prometheus stats listener", "error", err)
		}
		cancel()
	}
}

// buildRuntime produces the capture functions and, for prometheus, an un-served
// http.Server from cfg. cfg has already been validated by loadStatsConfig.
func (s *statsServer) buildRuntime(cfg statsConfig) ([]func(), *http.Server) {
	// rcrowley/go-metrics guards these registrations with a private sync.Once,
	// so subsequent reloads are no-ops.
	metrics.RegisterDebugGCStats(metrics.DefaultRegistry)
	metrics.RegisterRuntimeMemStats(metrics.DefaultRegistry)

	captureFns := []func(){
		func() { metrics.CaptureDebugGCStatsOnce(metrics.DefaultRegistry) },
		func() { metrics.CaptureRuntimeMemStatsOnce(metrics.DefaultRegistry) },
	}

	switch cfg.typ {
	case "graphite":
		// loadStatsConfig already resolved and validated the address; re-parse
		// the resolved form (no DNS lookup) to get a *net.TCPAddr.
		addr, _ := net.ResolveTCPAddr(cfg.graphite.protocol, cfg.graphite.resolvedAddr)
		gcfg := graphite.Config{
			Addr:          addr,
			Registry:      metrics.DefaultRegistry,
			FlushInterval: cfg.interval,
			DurationUnit:  time.Nanosecond,
			Prefix:        cfg.graphite.prefix,
			Percentiles:   []float64{0.5, 0.75, 0.95, 0.99, 0.999},
		}
		captureFns = append(captureFns, func() {
			if err := graphite.Once(gcfg); err != nil {
				s.l.Error("Graphite export failed", "error", err)
			}
		})
		s.l.Info("Starting graphite stats",
			"interval", cfg.interval,
			"prefix", cfg.graphite.prefix,
			"addr", addr,
		)
		return captureFns, nil

	case "prometheus":
		pr := prometheus.NewRegistry()
		pClient := mp.NewPrometheusProvider(metrics.DefaultRegistry, cfg.prom.namespace, cfg.prom.subsystem, pr, cfg.interval)
		captureFns = append(captureFns, func() {
			if err := pClient.UpdatePrometheusMetricsOnce(); err != nil {
				s.l.Error("Prometheus metrics update failed", "error", err)
			}
		})

		g := prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: cfg.prom.namespace,
			Subsystem: cfg.prom.subsystem,
			Name:      "info",
			Help:      "Version information for the Nebula binary",
			ConstLabels: prometheus.Labels{
				"version":      s.buildVersion,
				"goversion":    runtime.Version(),
				"boringcrypto": strconv.FormatBool(boringEnabled()),
			},
		})
		pr.MustRegister(g)
		g.Set(1)

		// promhttp.HandlerOpts.ErrorLog needs a stdlib-shaped Println logger,
		// so bridge our slog.Logger back to a *log.Logger that emits at Error.
		errLog := slog.NewLogLogger(s.l.Handler(), slog.LevelError)
		mux := http.NewServeMux()
		mux.Handle(cfg.prom.path, promhttp.HandlerFor(pr, promhttp.HandlerOpts{ErrorLog: errLog}))
		return captureFns, &http.Server{Addr: cfg.prom.listen, Handler: mux}
	}
	return captureFns, nil
}

// captureStatsLoop runs each fn on every tick of d until ctx is cancelled.
func captureStatsLoop(ctx context.Context, d time.Duration, fns []func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, fn := range fns {
				fn()
			}
		}
	}
}

func loadStatsConfig(c *config.C) (statsConfig, error) {
	cfg := statsConfig{
		typ: c.GetString("stats.type", ""),
	}
	if cfg.typ == "" || cfg.typ == "none" {
		return cfg, nil
	}

	cfg.interval = c.GetDuration("stats.interval", 0)
	if cfg.interval == 0 {
		return cfg, fmt.Errorf("stats.interval was an invalid duration: %s", c.GetString("stats.interval", ""))
	}

	switch cfg.typ {
	case "graphite":
		cfg.graphite.protocol = c.GetString("stats.protocol", "tcp")
		cfg.graphite.host = c.GetString("stats.host", "")
		if cfg.graphite.host == "" {
			return cfg, errors.New("stats.host can not be empty")
		}
		addr, err := net.ResolveTCPAddr(cfg.graphite.protocol, cfg.graphite.host)
		if err != nil {
			return cfg, fmt.Errorf("error while setting up graphite sink: %s", err)
		}
		cfg.graphite.resolvedAddr = addr.String()
		cfg.graphite.prefix = c.GetString("stats.prefix", "nebula")
	case "prometheus":
		cfg.prom.listen = c.GetString("stats.listen", "")
		if cfg.prom.listen == "" {
			return cfg, errors.New("stats.listen should not be empty")
		}
		cfg.prom.path = c.GetString("stats.path", "")
		if cfg.prom.path == "" {
			return cfg, errors.New("stats.path should not be empty")
		}
		cfg.prom.namespace = c.GetString("stats.namespace", "")
		cfg.prom.subsystem = c.GetString("stats.subsystem", "")
	default:
		return cfg, fmt.Errorf("stats.type was not understood: %s", cfg.typ)
	}

	return cfg, nil
}
