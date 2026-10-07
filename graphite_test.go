package nebula

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// graphiteHost accepts connections and hands each one to the test
type graphiteHost struct {
	ln    net.Listener
	conns chan net.Conn

	mu     sync.Mutex
	closed bool
	open   []net.Conn
}

// newGraphiteHost accepts connections for the test. A non-zero window shrinks each connection's receive buffer, so a
// sender that is not read from blocks after a little whatever the host's TCP tuning. Only for tests that need a stall,
// a small window makes reading very slow on Linux.
func newGraphiteHost(t *testing.T, window int) *graphiteHost {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h := &graphiteHost{ln: ln, conns: make(chan net.Conn, 8)}
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = ln.Close()
		h.mu.Lock()
		h.closed = true
		for _, c := range h.open {
			_ = c.Close()
		}
		h.mu.Unlock()
		close(done)
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			if h.closed {
				h.mu.Unlock()
				_ = c.Close()
				return
			}
			h.open = append(h.open, c)
			h.mu.Unlock()
			if tc, ok := c.(*net.TCPConn); ok && window > 0 {
				_ = tc.SetReadBuffer(window)
			}
			select {
			case h.conns <- c:
			case <-done:
				return
			}
		}
	}()
	return h
}

func (h *graphiteHost) addr(t *testing.T) *net.TCPAddr {
	a, err := net.ResolveTCPAddr("tcp", h.ln.Addr().String())
	require.NoError(t, err)
	return a
}

func (h *graphiteHost) next(t *testing.T, wait time.Duration) net.Conn {
	t.Helper()
	select {
	case c := <-h.conns:
		return c
	case <-time.After(wait):
		t.Fatal("no connection")
		return nil
	}
}

// Enough to fill the socket buffers on any platform, so a write to a host that stops reading blocks
var bigGraphiteExport = bytes.Repeat([]byte("nebula.stalled.value 1 0\n"), 1<<20)

// The point of all this: a graphite host that stopped reading never holds up a capture pass
func TestStatsServer_graphiteNeverBlocksCapture(t *testing.T) {
	// Enough distinct metrics that a synchronous send of one export would fill the socket buffers and block
	for i := range 200000 {
		name := fmt.Sprintf("graphite.capture.test.%d", i)
		metrics.GetOrRegisterGauge(name, nil).Update(int64(i))
		t.Cleanup(func() { metrics.DefaultRegistry.Unregister(name) })
	}
	h := newGraphiteHost(t, 4096)

	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "1h", "host": h.ln.Addr().String()})
	cfg, err := loadStatsConfig(c)
	require.NoError(t, err)

	s.runMu.Lock()
	fns, _ := s.buildRuntime(t.Context(), cfg)
	s.runMu.Unlock()

	done := make(chan struct{})
	go func() {
		// One export is already far more than the socket buffers hold
		for _, fn := range fns {
			fn()
		}
		close(done)
	}()
	// Formatting 200k gauges comes first and takes a while on a slow runner, that is not what this checks
	h.next(t, 30*time.Second) // accepted, never read
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a capture pass waited on graphite")
	}
}

// The stall timeout is about progress. A host that reads slowly gets the whole export however long it takes, one that
// stops reading is dropped
func TestGraphiteSend_slowHostIsNotAStall(t *testing.T) {
	// Linux wakes a blocked writer only after a good part of its send buffer drains, so progress comes in bursts. A
	// second leaves room for that, 30s in production leaves plenty
	timeout := time.Second
	// Well past what socket buffers hold on either platform, so the send has to wait on the reader
	export := bytes.Repeat([]byte("nebula.slow.value 1 0\n"), 12<<20/22)

	h := newGraphiteHost(t, 0)
	addr := h.addr(t)
	sent := make(chan error, 1)
	var took time.Duration
	go func() {
		start := time.Now()
		err := graphiteSend(t.Context(), addr, export, timeout)
		took = time.Since(start)
		sent <- err
	}()

	// 256KB every 50ms, well inside the timeout but far longer than it overall
	c := h.next(t, 5*time.Second)
	total := 0
	buf := make([]byte, 256<<10)
	for {
		n, err := io.ReadFull(c, buf)
		total += n
		if err != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	select {
	case err := <-sent:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the send did not return")
	}
	assert.Equal(t, len(export), total)
	assert.Greater(t, took, timeout, "the send itself should outlast the timeout")
}

func TestGraphiteSend_stalledHostTimesOut(t *testing.T) {
	h := newGraphiteHost(t, 0)
	done := make(chan error, 1)
	addr := h.addr(t)
	go func() { done <- graphiteSend(t.Context(), addr, bigGraphiteExport, 300*time.Millisecond) }()
	h.next(t, 5*time.Second) // accepted, never read

	select {
	case err := <-done:
		var ne net.Error
		require.ErrorAs(t, err, &ne)
		assert.True(t, ne.Timeout(), "want a timeout, got %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the send is still stuck on a host that stopped reading")
	}
}

func TestGraphiteFormat(t *testing.T) {
	r := metrics.NewRegistry()
	metrics.GetOrRegisterGauge("g", r).Update(7)
	metrics.GetOrRegisterCounter("c", r).Inc(3)

	var w bytes.Buffer
	graphiteFormat(&w, graphiteConfigExport{Registry: r, FlushInterval: time.Second, DurationUnit: time.Nanosecond, Prefix: "nebula"})
	out := w.String()
	assert.Contains(t, out, "nebula.g.value 7 ")
	assert.Contains(t, out, "nebula.c.count 3 ")
	assert.Contains(t, out, "nebula.c.count_ps 3.00 ")
}

func graphiteSenderConfig(r metrics.Registry) graphiteConfigExport {
	return graphiteConfigExport{Registry: r, FlushInterval: time.Second, DurationUnit: time.Nanosecond, Prefix: "nebula"}
}

// Enough metrics that one export overflows the socket buffers on any platform, so a send to a host that stops
// reading blocks
func bigGraphiteRegistry() metrics.Registry {
	r := metrics.NewRegistry()
	for i := range 200000 {
		metrics.GetOrRegisterGauge(fmt.Sprintf("big.gauge.%d", i), r).Update(int64(i))
	}
	return r
}

func TestGraphiteSender_sends(t *testing.T) {
	r := metrics.NewRegistry()
	metrics.GetOrRegisterGauge("a", r).Update(1)
	h := newGraphiteHost(t, 0)
	s := newGraphiteSender(h.addr(t), graphiteSenderConfig(r), slog.New(slog.DiscardHandler))
	go s.run(t.Context())

	s.request()
	b, err := io.ReadAll(h.next(t, 5*time.Second))
	require.NoError(t, err)
	assert.Contains(t, string(b), "nebula.a.value 1 ")
}

// While a send is stuck on a host that stopped reading, requests never wait and collapse into one export, which
// carries the values current when it runs and goes out on a fresh connection once the stuck one fails
func TestGraphiteSender_stuckSendBlocksNothing(t *testing.T) {
	r := bigGraphiteRegistry()
	marker := metrics.GetOrRegisterGauge("marker", r)
	marker.Update(1)
	h := newGraphiteHost(t, 4096)
	s := newGraphiteSender(h.addr(t), graphiteSenderConfig(r), slog.New(slog.DiscardHandler))
	sent := make(chan error, 8)
	s.sent = func(err error) { sent <- err }
	go s.run(t.Context())

	s.request()
	// Formatting the big registry comes first, give a slow runner room
	stuck := h.next(t, 30*time.Second)
	select {
	case err := <-sent:
		t.Fatalf("the first send should be stuck on a host that is not reading, it ended with %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	marker.Update(2)
	requested := make(chan struct{})
	go func() {
		for range 100 {
			s.request()
		}
		close(requested)
	}()
	select {
	case <-requested:
	case <-time.After(5 * time.Second):
		t.Fatal("a request waited on a stuck send")
	}

	// Only the marker from here on, so the next export is small and reads back quickly through the small window
	r.Each(func(name string, _ any) {
		if name != "marker" {
			r.Unregister(name)
		}
	})
	require.NoError(t, stuck.Close())
	b, err := io.ReadAll(h.next(t, 30*time.Second))
	require.NoError(t, err)
	assert.Contains(t, string(b), "nebula.marker.value 2 ")
	assert.NotContains(t, string(b), "nebula.marker.value 1 ", "each export starts from an empty buffer")

	select {
	case <-h.conns:
		t.Fatal("the requests made during the stuck send should have been one export")
	case <-time.After(500 * time.Millisecond):
	}
}

// A stop or reload abandons a stuck send rather than waiting out its timeout
func TestGraphiteSender_stopAbandonsStuckSend(t *testing.T) {
	h := newGraphiteHost(t, 4096)
	s := newGraphiteSender(h.addr(t), graphiteSenderConfig(bigGraphiteRegistry()), slog.New(slog.DiscardHandler))
	sent := make(chan error, 1)
	s.sent = func(err error) { sent <- err }
	ctx, cancel := context.WithCancel(t.Context())
	go s.run(ctx)

	s.request()
	h.next(t, 30*time.Second)
	select {
	case err := <-sent:
		t.Fatalf("the send should be stuck on a host that is not reading, it ended with %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-sent:
		require.Error(t, err, "a stuck send ends by being abandoned, not by finishing")
	case <-time.After(5 * time.Second):
		t.Fatal("the sender is still stuck after its runtime stopped")
	}
}

// The sender buildRuntime starts stops with the runtime. One left running would keep sending after a reload replaced it
func TestStatsServer_graphiteSenderStopsWithRuntime(t *testing.T) {
	h := newGraphiteHost(t, 0)
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "1h", "host": h.ln.Addr().String()})
	cfg, err := loadStatsConfig(c)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	s.runMu.Lock()
	fns, _ := s.buildRuntime(ctx, cfg)
	s.runMu.Unlock()
	capture := func() {
		for _, fn := range fns {
			fn()
		}
	}

	capture()
	_, err = io.ReadAll(h.next(t, 5*time.Second))
	require.NoError(t, err)

	cancel()
	// The sender may still take this request, the dial fails on the cancelled ctx either way.
	// TestGraphiteSender_runReturnsOnCancel covers the goroutine exiting
	capture()
	select {
	case <-h.conns:
		t.Fatal("the sender kept sending after its runtime stopped")
	case <-time.After(500 * time.Millisecond):
	}
}

func TestGraphiteSender_runReturnsOnCancel(t *testing.T) {
	h := newGraphiteHost(t, 0)
	s := newGraphiteSender(h.addr(t), graphiteConfigExport{Registry: metrics.NewRegistry()}, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		s.run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run kept going after its ctx was done")
	}
}
