package nebula

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPunchyFromConfig(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)

	// Test defaults
	p := NewPunchyFromConfig(test.NewLogger(), c, nil)
	assert.False(t, p.punch.Load())
	assert.False(t, p.respond.Load())
	assert.Equal(t, time.Second, time.Duration(p.delay.Load()))
	assert.Equal(t, 5*time.Second, time.Duration(p.respondDelay.Load()))

	// punchy deprecation
	c.Settings["punchy"] = true
	p = NewPunchyFromConfig(test.NewLogger(), c, nil)
	assert.True(t, p.punch.Load())

	// punchy.punch
	c.Settings["punchy"] = map[string]any{"punch": true}
	p = NewPunchyFromConfig(test.NewLogger(), c, nil)
	assert.True(t, p.punch.Load())

	// punch_back deprecation
	c.Settings["punch_back"] = true
	p = NewPunchyFromConfig(test.NewLogger(), c, nil)
	assert.True(t, p.respond.Load())

	// punchy.respond
	c.Settings["punchy"] = map[string]any{"respond": true}
	c.Settings["punch_back"] = false
	p = NewPunchyFromConfig(test.NewLogger(), c, nil)
	assert.True(t, p.respond.Load())

	// punchy.delay
	c.Settings["punchy"] = map[string]any{"delay": "1m"}
	p = NewPunchyFromConfig(test.NewLogger(), c, nil)
	assert.Equal(t, time.Minute, time.Duration(p.delay.Load()))

	// punchy.respond_delay
	c.Settings["punchy"] = map[string]any{"respond_delay": "1m"}
	p = NewPunchyFromConfig(test.NewLogger(), c, nil)
	assert.Equal(t, time.Minute, time.Duration(p.respondDelay.Load()))
}

func TestPunchy_reload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	delay, _ := time.ParseDuration("1m")
	require.NoError(t, c.LoadString(`
punchy:
  punch: false
  delay: 1m
  respond: false
`))
	p := NewPunchyFromConfig(test.NewLogger(), c, nil)
	assert.False(t, p.punch.Load())
	assert.Equal(t, delay, time.Duration(p.delay.Load()))
	assert.False(t, p.respond.Load())

	newDelay, _ := time.ParseDuration("10m")
	require.NoError(t, c.ReloadConfigString(`
punchy:
  punch: true
  delay: 10m
  respond: true
`))
	p.reload(c, false)
	assert.True(t, p.punch.Load())
	assert.Equal(t, newDelay, time.Duration(p.delay.Load()))
	assert.True(t, p.respond.Load())
}

// The tests below pin the shape of each log line Punchy produces so changes
// cannot silently break whatever operators are grepping for. The assertions
// are on the structured message + attrs (e.g. "punchy.respond changed" with
// a respond=true field) rather than a formatted string. Tests filter by
// message rather than asserting total entry counts so unrelated info lines
// are tolerated without being locked into the format.

type capturedEntry struct {
	Level slog.Level
	Msg   string
	Attrs map[string]any
}

// capturingHandler is a slog.Handler that records each Record it receives so
// tests can assert on the level, message, and attribute map of individual log
// lines without coupling to any specific text format.
type capturingHandler struct {
	entries []capturedEntry
}

func (h *capturingHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	e := capturedEntry{
		Level: r.Level,
		Msg:   r.Message,
		Attrs: make(map[string]any),
	}
	r.Attrs(func(a slog.Attr) bool {
		e.Attrs[a.Key] = a.Value.Resolve().Any()
		return true
	})
	h.entries = append(h.entries, e)
	return nil
}

func (h *capturingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(_ string) slog.Handler      { return h }

func newCapturingPunchyLogger(t *testing.T) (*slog.Logger, *capturingHandler) {
	t.Helper()
	hook := &capturingHandler{}
	return slog.New(hook), hook
}

func findEntry(t *testing.T, entries []capturedEntry, msg string) capturedEntry {
	t.Helper()
	for _, e := range entries {
		if e.Msg == msg {
			return e
		}
	}
	t.Fatalf("no entry with message %q among %d entries", msg, len(entries))
	return capturedEntry{}
}

func TestPunchy_LogFormat_InitialEnabled(t *testing.T) {
	l, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {punch: true}`))

	NewPunchyFromConfig(l, c, nil)

	entry := findEntry(t, hook.entries, "punchy enabled")
	assert.Equal(t, slog.LevelInfo, entry.Level)
	assert.Empty(t, entry.Attrs)
}

func TestPunchy_LogFormat_InitialDisabled(t *testing.T) {
	l, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {punch: false}`))

	NewPunchyFromConfig(l, c, nil)

	entry := findEntry(t, hook.entries, "punchy disabled")
	assert.Equal(t, slog.LevelInfo, entry.Level)
	assert.Empty(t, entry.Attrs)
}

func TestPunchy_LogFormat_ReloadPunch(t *testing.T) {
	l, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {punch: false}`))
	NewPunchyFromConfig(l, c, nil)
	hook.entries = nil

	require.NoError(t, c.ReloadConfigString(`punchy: {punch: true}`))

	entry := findEntry(t, hook.entries, "punchy.punch changed")
	assert.Equal(t, slog.LevelInfo, entry.Level)
	assert.Equal(t, map[string]any{"punch": true}, entry.Attrs)
}

func TestPunchy_LogFormat_ReloadRespond(t *testing.T) {
	l, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {respond: false}`))
	NewPunchyFromConfig(l, c, nil)
	hook.entries = nil

	require.NoError(t, c.ReloadConfigString(`punchy: {respond: true}`))

	entry := findEntry(t, hook.entries, "punchy.respond changed")
	assert.Equal(t, slog.LevelInfo, entry.Level)
	assert.Equal(t, map[string]any{"respond": true}, entry.Attrs)
}

func TestPunchy_LogFormat_ReloadDelay(t *testing.T) {
	l, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {delay: 1s}`))
	NewPunchyFromConfig(l, c, nil)
	hook.entries = nil

	require.NoError(t, c.ReloadConfigString(`punchy: {delay: 10s}`))

	entry := findEntry(t, hook.entries, "punchy.delay changed")
	assert.Equal(t, slog.LevelInfo, entry.Level)
	assert.Equal(t, map[string]any{"delay": 10 * time.Second}, entry.Attrs)
}

func TestPunchy_LogFormat_ReloadTargetAllRemotes(t *testing.T) {
	l, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {target_all_remotes: false}`))
	NewPunchyFromConfig(l, c, nil)
	hook.entries = nil

	require.NoError(t, c.ReloadConfigString(`punchy: {target_all_remotes: true}`))

	entry := findEntry(t, hook.entries, "punchy.target_all_remotes changed")
	assert.Equal(t, slog.LevelInfo, entry.Level)
	assert.Equal(t, map[string]any{"target_all_remotes": true}, entry.Attrs)
}

func TestPunchy_LogFormat_ReloadRespondDelay(t *testing.T) {
	l, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {respond_delay: 5s}`))
	NewPunchyFromConfig(l, c, nil)
	hook.entries = nil

	require.NoError(t, c.ReloadConfigString(`punchy: {respond_delay: 15s}`))

	entry := findEntry(t, hook.entries, "punchy.respond_delay changed")
	assert.Equal(t, slog.LevelInfo, entry.Level)
	assert.Equal(t, map[string]any{"respond_delay": 15 * time.Second}, entry.Attrs)
}
