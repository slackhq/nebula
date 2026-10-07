package nebula

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/test"
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

// readExport reads what one send wrote, bounded so a send that never finishes fails the test rather than hanging it
func readExport(t *testing.T, c net.Conn) []byte {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(10*time.Second)))
	b, err := io.ReadAll(c)
	require.NoError(t, err)
	return b
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

// lockedBuffer is a log destination a test can read while the code under test writes to it from another goroutine
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func testGraphiteConfig(addr *net.TCPAddr, r metrics.Registry) graphiteConfigExport {
	return graphiteConfigExport{Addr: addr, Registry: r, FlushInterval: time.Second, DurationUnit: time.Nanosecond, Prefix: "nebula"}
}

// Enough metrics that one export overflows the socket buffers on any platform, so a send to a host that stops
// reading blocks
func bigGraphiteRegistry(r metrics.Registry, t *testing.T) {
	for i := range 200000 {
		name := fmt.Sprintf("big.gauge.%d", i)
		metrics.GetOrRegisterGauge(name, r).Update(int64(i))
		t.Cleanup(func() { r.Unregister(name) })
	}
}

func TestGraphiteOnce_sends(t *testing.T) {
	r := metrics.NewRegistry()
	metrics.GetOrRegisterGauge("g", r).Update(7)
	metrics.GetOrRegisterCounter("c", r).Inc(3)
	h := newGraphiteHost(t, 0)

	require.NoError(t, graphiteOnce(t.Context(), testGraphiteConfig(h.addr(t), r), time.Minute))
	b := readExport(t, h.next(t, 5*time.Second))
	assert.Contains(t, string(b), "nebula.g.value 7 ")
	assert.Contains(t, string(b), "nebula.c.count 3 ")
	assert.Contains(t, string(b), "nebula.c.count_ps 3.00 ")
}

// A host that accepts and never reads is given up on, and the failed write is reported
func TestGraphiteOnce_stalledHostTimesOut(t *testing.T) {
	r := metrics.NewRegistry()
	bigGraphiteRegistry(r, t)
	h := newGraphiteHost(t, 4096)
	done := make(chan error, 1)
	go func() { done <- graphiteOnce(t.Context(), testGraphiteConfig(h.addr(t), r), 300*time.Millisecond) }()
	h.next(t, 5*time.Second) // accepted, never read

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the send did not give up on a host that stopped reading")
	}
}

// The timeout covers the whole send, a host that keeps reading but too slowly is still given up on
func TestGraphiteOnce_timeoutCoversTheWholeSend(t *testing.T) {
	r := metrics.NewRegistry()
	bigGraphiteRegistry(r, t)
	h := newGraphiteHost(t, 0)
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- graphiteOnce(t.Context(), testGraphiteConfig(h.addr(t), r), 500*time.Millisecond) }()
	c := h.next(t, 5*time.Second)
	stopReading := make(chan struct{})
	defer close(stopReading)
	// 32KB every 10ms keeps every write well inside the timeout, the whole export takes seconds
	go func() {
		buf := make([]byte, 32<<10)
		for {
			select {
			case <-stopReading:
				return
			case <-time.After(10 * time.Millisecond):
			}
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.Less(t, time.Since(start), 5*time.Second)
	case <-time.After(10 * time.Second):
		t.Fatal("a host that kept reading slowly held the send past its timeout")
	}
}

func TestGraphiteOnce_cancelledCtxDoesNotConnect(t *testing.T) {
	h := newGraphiteHost(t, 0)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.Error(t, graphiteOnce(ctx, testGraphiteConfig(h.addr(t), metrics.NewRegistry()), time.Minute))
	select {
	case <-h.conns:
		t.Fatal("connected on a cancelled ctx")
	case <-time.After(200 * time.Millisecond):
	}
}

// A stop or reload abandons a stuck send rather than waiting out its timeout
func TestGraphiteOnce_cancelAbandonsSend(t *testing.T) {
	r := metrics.NewRegistry()
	bigGraphiteRegistry(r, t)
	h := newGraphiteHost(t, 4096)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- graphiteOnce(ctx, testGraphiteConfig(h.addr(t), r), time.Minute) }()
	h.next(t, 5*time.Second)
	select {
	case err := <-done:
		t.Fatalf("the send should be stuck on a host that is not reading, it ended with %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the send is still stuck after its ctx was cancelled")
	}
}

// buildRuntime hands graphite the configured prefix and interval
func TestStatsServer_graphiteExportUsesConfig(t *testing.T) {
	const name = "graphite.wiring.test"
	metrics.GetOrRegisterCounter(name, nil).Inc(8)
	t.Cleanup(func() { metrics.DefaultRegistry.Unregister(name) })
	h := newGraphiteHost(t, 0)
	s, c := newTestStatsServer(t)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "4s", "prefix": "pfx", "host": h.ln.Addr().String()})
	cfg, err := loadStatsConfig(c)
	require.NoError(t, err)

	s.runMu.Lock()
	fns, _ := s.buildRuntime(t.Context(), cfg)
	s.runMu.Unlock()
	for _, fn := range fns {
		fn()
	}
	b := readExport(t, h.next(t, 5*time.Second))
	assert.Contains(t, string(b), "pfx."+name+".count 8 ")
	assert.Contains(t, string(b), "pfx."+name+".count_ps 2.00 ")
}

func TestStatsServer_graphiteFailureIsLogged(t *testing.T) {
	logs := &lockedBuffer{}
	s, c := newTestStatsServer(t)
	s.l = test.NewLoggerWithOutput(logs)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "1h", "host": "127.0.0.1:" + freeTCPPort(t)})
	cfg, err := loadStatsConfig(c)
	require.NoError(t, err)

	s.runMu.Lock()
	fns, _ := s.buildRuntime(t.Context(), cfg)
	s.runMu.Unlock()
	for _, fn := range fns {
		fn()
	}
	assert.Contains(t, logs.String(), "Graphite export failed")
}

// Stop abandons the running export, so it goes through Start rather than handing buildRuntime a ctx, and a stop is
// not logged as a failure
func TestStatsServer_stopAbandonsGraphiteSend(t *testing.T) {
	bigGraphiteRegistry(metrics.DefaultRegistry, t)
	h := newGraphiteHost(t, 4096)
	logs := &lockedBuffer{}
	s, c := newTestStatsServer(t)
	s.l = test.NewLoggerWithOutput(logs)
	setStatsConfig(c, map[string]any{"type": "graphite", "interval": "50ms", "host": h.ln.Addr().String()})
	require.NoError(t, s.reload(c, true))

	started := make(chan struct{})
	go func() {
		s.Start()
		close(started)
	}()
	stuck := h.next(t, 30*time.Second)
	s.Stop()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop")
	}

	// A closed sender resets the connection once it sees this, one still sending just buffers it. Either way the
	// read below doesn't have to drain the export through the small window to find out
	_, err := stuck.Write([]byte("x"))
	require.NoError(t, err)
	require.NoError(t, stuck.SetReadDeadline(time.Now().Add(10*time.Second)))
	n, err := io.Copy(io.Discard, stuck)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the send kept the connection after Stop, read %d bytes", n)
	}
	assert.Less(t, n, int64(1<<20), "the send kept going after Stop")
	// The capture loop logs on its own goroutine after Start has returned, give it the chance
	assert.Never(t, func() bool { return strings.Contains(logs.String(), "Graphite export failed") }, 500*time.Millisecond, 10*time.Millisecond, "a stop is not a failure")
}
