package nebula

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

// statsServer owns nebula's stats subsystem: the periodic metric capture
// goroutine and (for prometheus) an HTTP listener. It mirrors the lifecycle
// shape of dnsServer: constructor wires the reload callback and a ctx watcher,
// reload reconciles state with the latest config, Start runs any blocking
// listener, Stop tears the runtime down.
type statsServer struct {
	l            *logrus.Logger
	ctx          context.Context
	buildVersion string
	configTest   bool

	// enabled mirrors "stats configured to a real backend". Start consults
	// it so callers don't need to know the gating rules.
	enabled atomic.Bool

	runMu     sync.Mutex
	runCfg    *statsConfig
	runCancel context.CancelFunc // cancels the active capture loop
	listener  *http.Server       // active prometheus listener, nil otherwise
}

// statsConfig is the snapshot of stats-related config that drives the runtime.
// It is comparable with == so reload can detect "no change" cheaply.
type statsConfig struct {
	typ      string
	interval time.Duration

	// graphite
	protocol string
	host     string
	// resolvedAddr is the string form of host resolved at config-load time.
	// Including it in the struct means a SIGHUP picks up DNS changes even
	// when stats.host hasn't been edited.
	resolvedAddr string
	prefix       string

	// prometheus
	listen    string
	path      string
	namespace string
	subsystem string
}

// newStatsServerFromConfig builds a statsServer, applies the initial config,
// and registers a reload callback. A goroutine watches ctx so the runtime
// shuts down cleanly when nebula stops. The reload callback is registered
// before the initial config is applied, so a SIGHUP can later enable, fix,
// or disable stats even if the initial application failed.
//
// The statsServer internally gates on stats.type / interval / etc; Start is
// safe to call unconditionally, it no-ops when stats aren't enabled or there
// is no listener to run. The returned pointer is always non-nil, even on
// error.
func newStatsServerFromConfig(ctx context.Context, l *logrus.Logger, c *config.C, buildVersion string, configTest bool) (*statsServer, error) {
	s := &statsServer{
		l:            l,
		ctx:          ctx,
		buildVersion: buildVersion,
		configTest:   configTest,
	}

	c.RegisterReloadCallback(func(c *config.C) {
		if err := s.reload(c, false); err != nil {
			l.WithError(err).Error("Failed to reload stats from config")
		}
	})

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	if err := s.reload(c, true); err != nil {
		return s, err
	}
	return s, nil
}

// reload applies the latest config and reconciles the running state with it.
// If the relevant config didn't change it does nothing. Otherwise it tears
// down the current runtime and builds a new one from the new config. On a
// non-initial reload it also restarts the listener goroutine; on initial
// reload Control.Start is what launches the first listener via statsStart.
func (s *statsServer) reload(c *config.C, initial bool) error {
	newCfg, err := loadStatsConfig(c)
	if err != nil {
		return err
	}

	s.runMu.Lock()
	defer s.runMu.Unlock()

	if s.runCfg != nil && *s.runCfg == newCfg {
		return nil
	}

	s.unlockedTearDown()
	s.runCfg = &newCfg

	if newCfg.typ == "" || newCfg.typ == "none" {
		return nil
	}

	if s.configTest {
		// Validate only; don't spawn or bind.
		return nil
	}

	listener, err := s.unlockedStartRuntime(newCfg)
	if err != nil {
		return err
	}
	s.listener = listener
	s.enabled.Store(true)

	if !initial && listener != nil {
		// Replace the listener goroutine that exited when we tore down the
		// previous runtime.
		go s.Start()
	}
	return nil
}

// unlockedStartRuntime spawns the capture loop and (for prometheus) returns a
// configured but un-served http.Server. Caller holds runMu and must record
// s.runCancel.
func (s *statsServer) unlockedStartRuntime(cfg statsConfig) (*http.Server, error) {
	// rcrowley/go-metrics guards these registrations with a private sync.Once,
	// so subsequent reloads are no-ops.
	metrics.RegisterDebugGCStats(metrics.DefaultRegistry)
	metrics.RegisterRuntimeMemStats(metrics.DefaultRegistry)

	captureFns := []func(){
		func() { metrics.CaptureDebugGCStatsOnce(metrics.DefaultRegistry) },
		func() { metrics.CaptureRuntimeMemStatsOnce(metrics.DefaultRegistry) },
	}

	var listener *http.Server

	switch cfg.typ {
	case "graphite":
		// loadStatsConfig already resolved and validated the address; re-parse
		// the resolved form (no DNS lookup) to get a *net.TCPAddr.
		addr, err := net.ResolveTCPAddr(cfg.protocol, cfg.resolvedAddr)
		if err != nil {
			return nil, fmt.Errorf("error while setting up graphite sink: %s", err)
		}
		gcfg := graphite.Config{
			Addr:          addr,
			Registry:      metrics.DefaultRegistry,
			FlushInterval: cfg.interval,
			DurationUnit:  time.Nanosecond,
			Prefix:        cfg.prefix,
			Percentiles:   []float64{0.5, 0.75, 0.95, 0.99, 0.999},
		}
		captureFns = append(captureFns, func() {
			if err := graphite.Once(gcfg); err != nil {
				s.l.WithError(err).Error("Graphite export failed")
			}
		})
		s.l.WithFields(logrus.Fields{
			"interval": cfg.interval,
			"prefix":   cfg.prefix,
			"addr":     addr,
		}).Info("Starting graphite stats")

	case "prometheus":
		pr := prometheus.NewRegistry()
		pClient := mp.NewPrometheusProvider(metrics.DefaultRegistry, cfg.namespace, cfg.subsystem, pr, cfg.interval)
		captureFns = append(captureFns, func() {
			if err := pClient.UpdatePrometheusMetricsOnce(); err != nil {
				s.l.WithError(err).Error("Prometheus metrics update failed")
			}
		})

		g := prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: cfg.namespace,
			Subsystem: cfg.subsystem,
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

		mux := http.NewServeMux()
		mux.Handle(cfg.path, promhttp.HandlerFor(pr, promhttp.HandlerOpts{ErrorLog: s.l}))
		listener = &http.Server{Addr: cfg.listen, Handler: mux}

	default:
		return nil, fmt.Errorf("stats.type was not understood: %s", cfg.typ)
	}

	runCtx, cancel := context.WithCancel(s.ctx)
	go captureStatsLoop(runCtx, cfg.interval, captureFns)
	s.runCancel = cancel
	return listener, nil
}

// unlockedTearDown stops the active capture loop and shuts down any active
// listener. Caller holds runMu.
func (s *statsServer) unlockedTearDown() {
	s.enabled.Store(false)
	if s.runCancel != nil {
		s.runCancel()
		s.runCancel = nil
	}
	if s.listener != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := s.listener.Shutdown(shutdownCtx); err != nil {
			s.l.WithError(err).Warn("Failed to shut down prometheus stats listener")
		}
		cancel()
		s.listener = nil
	}
}

// Start runs the prometheus listener until Stop is called or the listener
// errors. For graphite or disabled stats it returns immediately - the capture
// loop runs independently. Safe to call when stats are disabled. This is what
// Control.statsStart points at.
func (s *statsServer) Start() {
	if !s.enabled.Load() {
		return
	}

	s.runMu.Lock()
	listener := s.listener
	s.runMu.Unlock()

	if listener == nil {
		return
	}

	s.l.WithField("addr", listener.Addr).Info("Starting prometheus stats listener")
	if err := listener.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.l.WithError(err).Error("Prometheus stats listener exited")
	}
}

// Stop tears down the active runtime. Idempotent.
func (s *statsServer) Stop() {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	s.unlockedTearDown()
	s.runCfg = nil
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
		cfg.protocol = c.GetString("stats.protocol", "tcp")
		cfg.host = c.GetString("stats.host", "")
		if cfg.host == "" {
			return cfg, errors.New("stats.host can not be empty")
		}
		addr, err := net.ResolveTCPAddr(cfg.protocol, cfg.host)
		if err != nil {
			return cfg, fmt.Errorf("error while setting up graphite sink: %s", err)
		}
		cfg.resolvedAddr = addr.String()
		cfg.prefix = c.GetString("stats.prefix", "nebula")
	case "prometheus":
		cfg.listen = c.GetString("stats.listen", "")
		if cfg.listen == "" {
			return cfg, errors.New("stats.listen should not be empty")
		}
		cfg.path = c.GetString("stats.path", "")
		if cfg.path == "" {
			return cfg, errors.New("stats.path should not be empty")
		}
		cfg.namespace = c.GetString("stats.namespace", "")
		cfg.subsystem = c.GetString("stats.subsystem", "")
	default:
		return cfg, fmt.Errorf("stats.type was not understood: %s", cfg.typ)
	}

	return cfg, nil
}
