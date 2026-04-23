package firewall

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The tests below pin the log format produced by ConntrackCacheTicker.Get
// so the slog migration cannot silently change what operators grep for.
// The ticker's internal state (cache + cacheTick) is poked directly to
// avoid racing a goroutine-driven tick in tests.

// stripTime drops the time attribute so assertions can pin the line verbatim.
func stripTime(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
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
	l := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: stripTime,
	}))

	c := newFixedTicker(t, l, 3)
	c.Get()

	assert.Equal(t, "level=DEBUG msg=\"resetting conntrack cache\" len=3\n", buf.String())
}

func TestConntrackCacheTicker_Get_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	l := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: stripTime,
	}))

	c := newFixedTicker(t, l, 2)
	c.Get()

	assert.JSONEq(t, `{"level":"DEBUG","msg":"resetting conntrack cache","len":2}`, strings.TrimSpace(buf.String()))
}

func TestConntrackCacheTicker_Get_QuietBelowDebug(t *testing.T) {
	buf := &bytes.Buffer{}
	l := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: stripTime,
	}))

	c := newFixedTicker(t, l, 5)
	c.Get()

	assert.Empty(t, buf.String())
}

func TestConntrackCacheTicker_Get_QuietWhenCacheEmpty(t *testing.T) {
	buf := &bytes.Buffer{}
	l := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: stripTime,
	}))

	c := newFixedTicker(t, l, 0)
	c.Get()

	assert.Empty(t, buf.String())
}
