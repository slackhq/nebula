package firewall

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/slackhq/nebula/logging"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

// The tests below pin the log format produced by ConntrackCacheTicker.Get
// so changes cannot silently break what operators are grepping for. The
// ticker's internal state (cache + cacheTick) is poked directly to avoid
// racing a goroutine-driven tick in tests.

func newFixedTicker(t *testing.T, l *slog.Logger, cacheLen int) *ConntrackCacheTicker {
	t.Helper()
	c := &ConntrackCacheTicker{
		l:     l,
		cache: make(ConntrackCache, cacheLen),
	}
	for i := 0; i < cacheLen; i++ {
		c.cache[PacketKey{LocalPort: uint16(i) + 1}] = struct{}{}
	}
	c.cacheTick.Store(1) // cacheV starts at 0, so Get() takes the reset path
	return c
}

func TestConntrackCacheTicker_Get_TextFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	l := test.NewLoggerWithOutputAndLevel(buf, logging.LevelTrace)

	c := newFixedTicker(t, l, 3)
	c.Get()

	assert.Equal(t, "level=DEBUG-4 msg=\"resetting conntrack cache\" len=3\n", buf.String())
}

func TestConntrackCacheTicker_Get_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	l := test.NewJSONLoggerWithOutput(buf, logging.LevelTrace)

	c := newFixedTicker(t, l, 2)
	c.Get()

	assert.JSONEq(t, `{"level":"DEBUG-4","msg":"resetting conntrack cache","len":2}`, strings.TrimSpace(buf.String()))
}

func TestConntrackCacheTicker_Get_QuietBelowTrace(t *testing.T) {
	buf := &bytes.Buffer{}
	l := test.NewLoggerWithOutputAndLevel(buf, slog.LevelDebug)

	c := newFixedTicker(t, l, 5)
	c.Get()

	assert.Empty(t, buf.String())
}

func TestConntrackCacheTicker_Get_QuietWhenCacheEmpty(t *testing.T) {
	buf := &bytes.Buffer{}
	l := test.NewLoggerWithOutputAndLevel(buf, logging.LevelTrace)

	c := newFixedTicker(t, l, 0)
	c.Get()

	assert.Empty(t, buf.String())
}
