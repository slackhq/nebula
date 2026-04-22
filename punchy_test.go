package nebula

import (
	"io"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/logbridge"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPunchyFromConfig(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)

	// Test defaults
	p := NewPunchyFromConfig(test.NewSlogLogger(), c)
	assert.False(t, p.GetPunch())
	assert.False(t, p.GetRespond())
	assert.Equal(t, time.Second, p.GetDelay())
	assert.Equal(t, 5*time.Second, p.GetRespondDelay())

	// punchy deprecation
	c.Settings["punchy"] = true
	p = NewPunchyFromConfig(test.NewSlogLogger(), c)
	assert.True(t, p.GetPunch())

	// punchy.punch
	c.Settings["punchy"] = map[string]any{"punch": true}
	p = NewPunchyFromConfig(test.NewSlogLogger(), c)
	assert.True(t, p.GetPunch())

	// punch_back deprecation
	c.Settings["punch_back"] = true
	p = NewPunchyFromConfig(test.NewSlogLogger(), c)
	assert.True(t, p.GetRespond())

	// punchy.respond
	c.Settings["punchy"] = map[string]any{"respond": true}
	c.Settings["punch_back"] = false
	p = NewPunchyFromConfig(test.NewSlogLogger(), c)
	assert.True(t, p.GetRespond())

	// punchy.delay
	c.Settings["punchy"] = map[string]any{"delay": "1m"}
	p = NewPunchyFromConfig(test.NewSlogLogger(), c)
	assert.Equal(t, time.Minute, p.GetDelay())

	// punchy.respond_delay
	c.Settings["punchy"] = map[string]any{"respond_delay": "1m"}
	p = NewPunchyFromConfig(test.NewSlogLogger(), c)
	assert.Equal(t, time.Minute, p.GetRespondDelay())
}

func TestPunchy_reload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	delay, _ := time.ParseDuration("1m")
	require.NoError(t, c.LoadString(`
punchy:
  delay: 1m
  respond: false
`))
	p := NewPunchyFromConfig(test.NewSlogLogger(), c)
	assert.Equal(t, delay, p.GetDelay())
	assert.False(t, p.GetRespond())

	newDelay, _ := time.ParseDuration("10m")
	require.NoError(t, c.ReloadConfigString(`
punchy:
  delay: 10m
  respond: true
`))
	p.reload(c, false)
	assert.Equal(t, newDelay, p.GetDelay())
	assert.True(t, p.GetRespond())
}

// The tests below pin the shape of each log line Punchy produces, so the
// slog migration cannot silently change what operators grep for. The
// messages are intentionally different from the pre-migration logrus Infof
// output (e.g. "punchy.respond changed to true" became
// "punchy.respond changed" with a structured respond=true field); this test
// locks in the new structured shape.
//
// Punchy.reload also emits a spurious "Changing punchy.punch with reload is
// not supported" warning whenever any key under punchy changes, because of
// the c.HasChanged("punchy") fallback kept for the deprecated top-level
// punchy form. The tests filter by message rather than asserting total
// entry counts so that warning is tolerated without being locked into
// the format.

type capturingHook struct {
	entries []*logrus.Entry
}

func (h *capturingHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h *capturingHook) Fire(e *logrus.Entry) error {
	dup := *e
	dup.Data = logrus.Fields{}
	for k, v := range e.Data {
		dup.Data[k] = v
	}
	h.entries = append(h.entries, &dup)
	return nil
}

func newCapturingPunchyLogger(t *testing.T) (*logrus.Logger, *capturingHook) {
	t.Helper()
	lr := logrus.New()
	lr.SetOutput(io.Discard)
	lr.SetLevel(logrus.DebugLevel)
	hook := &capturingHook{}
	lr.AddHook(hook)
	return lr, hook
}

func findEntry(t *testing.T, entries []*logrus.Entry, msg string) *logrus.Entry {
	t.Helper()
	for _, e := range entries {
		if e.Message == msg {
			return e
		}
	}
	t.Fatalf("no entry with message %q among %d entries", msg, len(entries))
	return nil
}

func TestPunchy_LogFormat_InitialEnabled(t *testing.T) {
	lr, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {punch: true}`))

	NewPunchyFromConfig(logbridge.FromLogrus(lr), c)

	entry := findEntry(t, hook.entries, "punchy enabled")
	assert.Equal(t, logrus.InfoLevel, entry.Level)
	assert.Empty(t, entry.Data)
}

func TestPunchy_LogFormat_InitialDisabled(t *testing.T) {
	lr, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {punch: false}`))

	NewPunchyFromConfig(logbridge.FromLogrus(lr), c)

	entry := findEntry(t, hook.entries, "punchy disabled")
	assert.Equal(t, logrus.InfoLevel, entry.Level)
	assert.Empty(t, entry.Data)
}

func TestPunchy_LogFormat_ReloadPunchUnsupported(t *testing.T) {
	lr, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {punch: false}`))
	NewPunchyFromConfig(logbridge.FromLogrus(lr), c)
	hook.entries = nil

	require.NoError(t, c.ReloadConfigString(`punchy: {punch: true}`))

	entry := findEntry(t, hook.entries, "Changing punchy.punch with reload is not supported, ignoring.")
	assert.Equal(t, logrus.WarnLevel, entry.Level)
	assert.Empty(t, entry.Data)
}

func TestPunchy_LogFormat_ReloadRespond(t *testing.T) {
	lr, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {respond: false}`))
	NewPunchyFromConfig(logbridge.FromLogrus(lr), c)
	hook.entries = nil

	require.NoError(t, c.ReloadConfigString(`punchy: {respond: true}`))

	entry := findEntry(t, hook.entries, "punchy.respond changed")
	assert.Equal(t, logrus.InfoLevel, entry.Level)
	assert.Equal(t, logrus.Fields{"respond": true}, entry.Data)
}

func TestPunchy_LogFormat_ReloadDelay(t *testing.T) {
	lr, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {delay: 1s}`))
	NewPunchyFromConfig(logbridge.FromLogrus(lr), c)
	hook.entries = nil

	require.NoError(t, c.ReloadConfigString(`punchy: {delay: 10s}`))

	entry := findEntry(t, hook.entries, "punchy.delay changed")
	assert.Equal(t, logrus.InfoLevel, entry.Level)
	assert.Equal(t, logrus.Fields{"delay": 10 * time.Second}, entry.Data)
}

func TestPunchy_LogFormat_ReloadTargetAllRemotes(t *testing.T) {
	lr, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {target_all_remotes: false}`))
	NewPunchyFromConfig(logbridge.FromLogrus(lr), c)
	hook.entries = nil

	require.NoError(t, c.ReloadConfigString(`punchy: {target_all_remotes: true}`))

	entry := findEntry(t, hook.entries, "punchy.target_all_remotes changed")
	assert.Equal(t, logrus.InfoLevel, entry.Level)
	assert.Equal(t, logrus.Fields{"target_all_remotes": true}, entry.Data)
}

func TestPunchy_LogFormat_ReloadRespondDelay(t *testing.T) {
	lr, hook := newCapturingPunchyLogger(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`punchy: {respond_delay: 5s}`))
	NewPunchyFromConfig(logbridge.FromLogrus(lr), c)
	hook.entries = nil

	require.NoError(t, c.ReloadConfigString(`punchy: {respond_delay: 15s}`))

	entry := findEntry(t, hook.entries, "punchy.respond_delay changed")
	assert.Equal(t, logrus.InfoLevel, entry.Level)
	assert.Equal(t, logrus.Fields{"respond_delay": 15 * time.Second}, entry.Data)
}
