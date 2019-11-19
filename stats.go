package nebula

import (
	"errors"
	"fmt"
	"github.com/cyberdelia/go-metrics-graphite"
	mp "github.com/nbrownus/go-metrics-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rcrowley/go-metrics"
	"log"
	"net"
	"net/http"
	"time"
)

func startStats(c *Config) error {
	mType := c.GetString("stats.type", "")
	if mType == "" || mType == "none" {
		return nil
	}

	interval := c.GetDuration("stats.interval", 0)
	if interval == 0 {
		return fmt.Errorf("stats.interval was an invalid duration: %s", c.GetString("stats.interval", ""))
	}

	switch mType {
	case "graphite":
		startGraphiteStats(interval, c)
	case "prometheus":
		startPrometheusStats(interval, c)
	default:
		return fmt.Errorf("stats.type was not understood: %s", mType)
	}

	metrics.RegisterDebugGCStats(metrics.DefaultRegistry)
	metrics.RegisterRuntimeMemStats(metrics.DefaultRegistry)

	go metrics.CaptureDebugGCStats(metrics.DefaultRegistry, interval)
	go metrics.CaptureRuntimeMemStats(metrics.DefaultRegistry, interval)

	return nil
}

func startGraphiteStats(i time.Duration, c *Config) error {
	proto := c.GetString("stats.protocol", "tcp")
	host := c.GetString("stats.host", "")
	if host == "" {
		return errors.New("stats.host can not be empty")
	}

	prefix := c.GetString("stats.prefix", "nebula")
	addr, err := net.ResolveTCPAddr(proto, host)
	if err != nil {
		return fmt.Errorf("error while setting up graphite sink: %s", err)
	}

	l.Infof("Starting graphite. Interval: %s, prefix: %s, addr: %s", i, prefix, addr)
	go graphite.Graphite(metrics.DefaultRegistry, i, prefix, addr)
	return nil
}

func startPrometheusStats(i time.Duration, c *Config) error {
	namespace := c.GetString("stats.namespace", "")
	subsystem := c.GetString("stats.subsystem", "")

	listen := c.GetString("stats.listen", "")
	if listen == "" {
		return fmt.Errorf("stats.listen should not be emtpy")
	}

	path := c.GetString("stats.path", "")
	if path == "" {
		return fmt.Errorf("stats.path should not be emtpy")
	}

	pr := prometheus.NewRegistry()
	pClient := mp.NewPrometheusProvider(metrics.DefaultRegistry, namespace, subsystem, pr, i)
	go pClient.UpdatePrometheusMetrics()

	go func() {
		l.Infof("Prometheus stats listening on %s at %s", listen, path)
		http.Handle(path, promhttp.HandlerFor(pr, promhttp.HandlerOpts{ErrorLog: l}))
		log.Fatal(http.ListenAndServe(listen, nil))
	}()

	return nil
}
