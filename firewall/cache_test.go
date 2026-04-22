package firewall

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/logbridge"
	"github.com/stretchr/testify/assert"
)

// The tests below pin the log format produced by ConntrackCacheTicker.Get
// so the slog migration cannot silently change what operators grep for.
// The ticker's internal state (cache + cacheTick) is poked directly to
// avoid racing a goroutine-driven tick in tests.

func newFixedTicker(t *testing.T, lr *logrus.Logger, cacheLen int) *ConntrackCacheTicker {
	t.Helper()
	c := &ConntrackCacheTicker{
		l:     logbridge.FromLogrus(lr),
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
	lr := logrus.New()
	lr.Out = buf
	lr.Formatter = &logrus.TextFormatter{DisableColors: true, DisableTimestamp: true}
	lr.SetLevel(logrus.DebugLevel)

	c := newFixedTicker(t, lr, 3)
	c.Get()

	assert.Equal(t, "level=debug msg=\"resetting conntrack cache\" len=3\n", buf.String())
}

func TestConntrackCacheTicker_Get_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	lr := logrus.New()
	lr.Out = buf
	lr.Formatter = &logrus.JSONFormatter{DisableTimestamp: true}
	lr.SetLevel(logrus.DebugLevel)

	c := newFixedTicker(t, lr, 2)
	c.Get()

	assert.JSONEq(t, `{"level":"debug","msg":"resetting conntrack cache","len":2}`, strings.TrimSpace(buf.String()))
}

func TestConntrackCacheTicker_Get_QuietBelowDebug(t *testing.T) {
	buf := &bytes.Buffer{}
	lr := logrus.New()
	lr.Out = buf
	lr.Formatter = &logrus.TextFormatter{DisableColors: true, DisableTimestamp: true}
	lr.SetLevel(logrus.InfoLevel)

	c := newFixedTicker(t, lr, 5)
	c.Get()

	assert.Empty(t, buf.String())
}

func TestConntrackCacheTicker_Get_QuietWhenCacheEmpty(t *testing.T) {
	buf := &bytes.Buffer{}
	lr := logrus.New()
	lr.Out = buf
	lr.Formatter = &logrus.TextFormatter{DisableColors: true, DisableTimestamp: true}
	lr.SetLevel(logrus.DebugLevel)

	c := newFixedTicker(t, lr, 0)
	c.Get()

	assert.Empty(t, buf.String())
}
