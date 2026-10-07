package nebula

// This file is a trimmed, inlined copy of the graphite exporter from
// github.com/cyberdelia/go-metrics-graphite, retaining only the Config type and
// the Once entrypoint that Nebula uses. The upstream package has been
// unmaintained for 10+ years, so it was vendored here to drop the dependency.
// See https://github.com/slackhq/nebula/issues/1831.
//
// Copyright 2015 Timothée Peignier. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rcrowley/go-metrics"
)

// graphiteConfigExport provides a container with configuration parameters for
// the Graphite exporter.
type graphiteConfigExport struct {
	Registry      metrics.Registry // Registry to be exported
	FlushInterval time.Duration    // Flush interval
	DurationUnit  time.Duration    // Time conversion unit for durations
	Prefix        string           // Prefix to be prepended to metric names
	Percentiles   []float64        // Percentiles to export from timers and histograms
}

// graphiteFormat appends every metric in the registry to w in graphite's
// plaintext format, stamped with at.
func graphiteFormat(w *bytes.Buffer, c graphiteConfigExport, at time.Time) {
	now := at.Unix()
	du := float64(c.DurationUnit)
	flushSeconds := float64(c.FlushInterval) / float64(time.Second)
	c.Registry.Each(func(name string, i any) {
		switch metric := i.(type) {
		case metrics.Counter:
			count := metric.Count()
			fmt.Fprintf(w, "%s.%s.count %d %d\n", c.Prefix, name, count, now)
			fmt.Fprintf(w, "%s.%s.count_ps %.2f %d\n", c.Prefix, name, float64(count)/flushSeconds, now)
		case metrics.Gauge:
			fmt.Fprintf(w, "%s.%s.value %d %d\n", c.Prefix, name, metric.Value(), now)
		case metrics.GaugeFloat64:
			fmt.Fprintf(w, "%s.%s.value %f %d\n", c.Prefix, name, metric.Value(), now)
		case metrics.Histogram:
			h := metric.Snapshot()
			ps := h.Percentiles(c.Percentiles)
			fmt.Fprintf(w, "%s.%s.count %d %d\n", c.Prefix, name, h.Count(), now)
			fmt.Fprintf(w, "%s.%s.min %d %d\n", c.Prefix, name, h.Min(), now)
			fmt.Fprintf(w, "%s.%s.max %d %d\n", c.Prefix, name, h.Max(), now)
			fmt.Fprintf(w, "%s.%s.mean %.2f %d\n", c.Prefix, name, h.Mean(), now)
			fmt.Fprintf(w, "%s.%s.std-dev %.2f %d\n", c.Prefix, name, h.StdDev(), now)
			for psIdx, psKey := range c.Percentiles {
				key := strings.Replace(strconv.FormatFloat(psKey*100.0, 'f', -1, 64), ".", "", 1)
				fmt.Fprintf(w, "%s.%s.%s-percentile %.2f %d\n", c.Prefix, name, key, ps[psIdx], now)
			}
		case metrics.Meter:
			m := metric.Snapshot()
			fmt.Fprintf(w, "%s.%s.count %d %d\n", c.Prefix, name, m.Count(), now)
			fmt.Fprintf(w, "%s.%s.one-minute %.2f %d\n", c.Prefix, name, m.Rate1(), now)
			fmt.Fprintf(w, "%s.%s.five-minute %.2f %d\n", c.Prefix, name, m.Rate5(), now)
			fmt.Fprintf(w, "%s.%s.fifteen-minute %.2f %d\n", c.Prefix, name, m.Rate15(), now)
			fmt.Fprintf(w, "%s.%s.mean %.2f %d\n", c.Prefix, name, m.RateMean(), now)
		case metrics.Timer:
			t := metric.Snapshot()
			ps := t.Percentiles(c.Percentiles)
			count := t.Count()
			fmt.Fprintf(w, "%s.%s.count %d %d\n", c.Prefix, name, count, now)
			fmt.Fprintf(w, "%s.%s.count_ps %.2f %d\n", c.Prefix, name, float64(count)/flushSeconds, now)
			fmt.Fprintf(w, "%s.%s.min %d %d\n", c.Prefix, name, t.Min()/int64(du), now)
			fmt.Fprintf(w, "%s.%s.max %d %d\n", c.Prefix, name, t.Max()/int64(du), now)
			fmt.Fprintf(w, "%s.%s.mean %.2f %d\n", c.Prefix, name, t.Mean()/du, now)
			fmt.Fprintf(w, "%s.%s.std-dev %.2f %d\n", c.Prefix, name, t.StdDev()/du, now)
			for psIdx, psKey := range c.Percentiles {
				key := strings.Replace(strconv.FormatFloat(psKey*100.0, 'f', -1, 64), ".", "", 1)
				fmt.Fprintf(w, "%s.%s.%s-percentile %.2f %d\n", c.Prefix, name, key, ps[psIdx]/du, now)
			}
			fmt.Fprintf(w, "%s.%s.one-minute %.2f %d\n", c.Prefix, name, t.Rate1(), now)
			fmt.Fprintf(w, "%s.%s.five-minute %.2f %d\n", c.Prefix, name, t.Rate5(), now)
			fmt.Fprintf(w, "%s.%s.fifteen-minute %.2f %d\n", c.Prefix, name, t.Rate15(), now)
			fmt.Fprintf(w, "%s.%s.mean-rate %.2f %d\n", c.Prefix, name, t.RateMean(), now)
		}
	})
}

// graphiteStallTimeout is how long a connect, or one chunk's write, may take before the send gives up. The whole export
// has no limit, a host that keeps reading gets all of it. One that has stopped, or drains less than a write's worth of
// its socket buffer in that time, is dropped and the next export tries again.
const graphiteStallTimeout = 30 * time.Second

// graphiteWriteChunk is how much is written between pushing the write deadline forward
const graphiteWriteChunk = 64 << 10

// graphiteSender formats and ships exports to graphite on its own goroutine, so
// a slow or dead host never holds up a capture pass. It formats as soon as a pass
// asks, into one buffer it reuses.
type graphiteSender struct {
	addr    *net.TCPAddr
	cfg     graphiteConfigExport
	l       *slog.Logger
	timeout time.Duration
	wake    chan time.Time
	stalled atomic.Bool
	buf     bytes.Buffer
	// sent, when set, hears how each send ended. Only tests set it
	sent func(error)
}

func newGraphiteSender(addr *net.TCPAddr, cfg graphiteConfigExport, l *slog.Logger) *graphiteSender {
	return &graphiteSender{addr: addr, cfg: cfg, l: l, timeout: graphiteStallTimeout, wake: make(chan time.Time, 1)}
}

// request asks for an export stamped with the current time, without waiting. A request still waiting on a send in
// progress is replaced, so a host that can't keep up gets the newest values and skips the rest.
func (s *graphiteSender) request() {
	at := time.Now()
	for {
		select {
		case s.wake <- at:
			return
		default:
		}
		select {
		case <-s.wake:
		default:
		}
	}
}

// run exports on each request until ctx is done. A failed send is logged and the next export goes out on a fresh
// connection. A send that outlasts the interval is still let finish, with one warning per stall that exports are being
// dropped.
func (s *graphiteSender) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case at := <-s.wake:
			if ctx.Err() != nil {
				return
			}
			slow := time.AfterFunc(s.cfg.FlushInterval, func() {
				if !s.stalled.Swap(true) {
					s.l.Warn("Graphite export is taking longer than the stats interval, exports are being dropped",
						"addr", s.addr, "interval", s.cfg.FlushInterval)
				}
			})
			s.buf.Reset()
			graphiteFormat(&s.buf, s.cfg, at)
			err := graphiteSend(ctx, s.addr, s.buf.Bytes(), s.timeout)
			if slow.Stop() && err == nil && s.stalled.Swap(false) {
				s.l.Info("Graphite exports are keeping up again", "addr", s.addr)
			}
			if err != nil && ctx.Err() == nil {
				s.l.Error("Graphite export failed", "error", err)
			}
			if s.sent != nil {
				s.sent(err)
			}
		}
	}
}

func graphiteSend(ctx context.Context, addr *net.TCPAddr, b []byte, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return err
	}
	defer conn.Close()
	// A stop or reload abandons a send in progress rather than waiting out the timeout
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	for len(b) > 0 {
		n := min(len(b), graphiteWriteChunk)
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		if _, err := conn.Write(b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
