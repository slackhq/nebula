package firewall

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The tests below pin the log format produced by ConntrackCacheTicker.Get
// so the slog migration cannot silently change what operators grep for.
// The ticker's internal state (cache + cacheTick) is poked directly to
// avoid racing a goroutine-driven tick in tests.

// stripTimeHandler delegates to inner after zeroing r.Time so built-in
// slog handlers skip emitting time, letting tests pin output verbatim.
// Inlined here instead of using the shared test-helper package because the
// firewall package can't import test (test/tun.go pulls in routing, which
// imports firewall).
type stripTimeHandler struct{ inner slog.Handler }

func (h stripTimeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}
func (h stripTimeHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Time = time.Time{}
	return h.inner.Handle(ctx, r)
}
func (h stripTimeHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return stripTimeHandler{inner: h.inner.WithAttrs(a)}
}
func (h stripTimeHandler) WithGroup(n string) slog.Handler {
	return stripTimeHandler{inner: h.inner.WithGroup(n)}
}

func newTextLogger(w *bytes.Buffer, level slog.Level) *slog.Logger {
	return slog.New(stripTimeHandler{inner: slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})})
}

func newJSONLogger(w *bytes.Buffer, level slog.Level) *slog.Logger {
	return slog.New(stripTimeHandler{inner: slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})})
}

func newFixedTicker(t *testing.T, l *slog.Logger, cacheLen int) *ConntrackCacheTicker {
	t.Helper()
	c := &ConntrackCacheTicker{
		l:     l,
		cache: make(ConntrackCache, cacheLen),
	}
	for i := 0; i < cacheLen; i++ {
		c.cache[Packet{LocalPort: uint16(i) + 1}] = struct{}{}
	}
	c.cacheTick.Store(1) // cacheV starts at 0, so Get() takes the reset path
	return c
}

func TestConntrackCacheTicker_Get_TextFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	l := newTextLogger(buf, slog.LevelDebug)

	c := newFixedTicker(t, l, 3)
	c.Get()

	assert.Equal(t, "level=DEBUG msg=\"resetting conntrack cache\" len=3\n", buf.String())
}

func TestConntrackCacheTicker_Get_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	l := newJSONLogger(buf, slog.LevelDebug)

	c := newFixedTicker(t, l, 2)
	c.Get()

	assert.JSONEq(t, `{"level":"DEBUG","msg":"resetting conntrack cache","len":2}`, strings.TrimSpace(buf.String()))
}

func TestConntrackCacheTicker_Get_QuietBelowDebug(t *testing.T) {
	buf := &bytes.Buffer{}
	l := newTextLogger(buf, slog.LevelInfo)

	c := newFixedTicker(t, l, 5)
	c.Get()

	assert.Empty(t, buf.String())
}

func TestConntrackCacheTicker_Get_QuietWhenCacheEmpty(t *testing.T) {
	buf := &bytes.Buffer{}
	l := newTextLogger(buf, slog.LevelDebug)

	c := newFixedTicker(t, l, 0)
	c.Get()

	assert.Empty(t, buf.String())
}
