package nebula

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
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
`).Err)
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

	require.NoError(t, c.ReloadConfigString(`punchy: {punch: true}`).Err)

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

	require.NoError(t, c.ReloadConfigString(`punchy: {respond: true}`).Err)

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

	require.NoError(t, c.ReloadConfigString(`punchy: {delay: 10s}`).Err)

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

	require.NoError(t, c.ReloadConfigString(`punchy: {target_all_remotes: true}`).Err)

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

	require.NoError(t, c.ReloadConfigString(`punchy: {respond_delay: 15s}`).Err)

	entry := findEntry(t, hook.entries, "punchy.respond_delay changed")
	assert.Equal(t, slog.LevelInfo, entry.Level)
	assert.Equal(t, map[string]any{"respond_delay": 15 * time.Second}, entry.Attrs)
}

func TestPunchyReloadRestartRequired(t *testing.T) {
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString("stats:\n  lighthouse_metrics: false\n"))
	NewPunchyFromConfig(test.NewLogger(), c, nil)

	res := c.ReloadConfigString("stats:\n  lighthouse_metrics: true\n")
	require.NoError(t, res.Err)
	assert.True(t, res.RestartRequired)
}

// errNoRoute is the unreachable error every platform classifies the same way
var errNoRoute = udp.ErrInvalidIPv6RemoteForSocket

// recordingConn records where every write went and what kind of message it was, and fails the ones to an address in
// fail
type recordingConn struct {
	udp.NoopConn
	fail  map[netip.AddrPort]error
	wrote []netip.AddrPort
	// types is the message type of each write, a punch has none
	types []header.MessageType
}

func (c *recordingConn) WriteTo(b []byte, addr netip.AddrPort) error {
	c.wrote = append(c.wrote, addr)
	var h header.H
	if h.Parse(b) == nil {
		c.types = append(c.types, h.Type)
	}
	return c.fail[addr]
}

func (c *recordingConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort, failed func(int, error)) (int, error) {
	written := 0
	for i := range bufs {
		if err := c.WriteTo(bufs[i], addrs[i]); err != nil {
			failed(i, err)
			continue
		}
		written++
	}
	return written, nil
}

type noLighthouses struct{}

func (noLighthouses) IsAnyLighthouseAddr([]netip.Addr) bool { return false }

var (
	punchTargetV4 = netip.MustParseAddrPort("10.0.0.3:4242")
	punchTargetV6 = netip.MustParseAddrPort("[fd00::3]:4242")
)

// newPunchTarget is a tunnel on its IPv6 remote that also knows the peer's IPv4 one
func newPunchTarget() *HostInfo {
	vpnAddr := netip.MustParseAddr("10.128.0.3")
	hostinfo := &HostInfo{
		vpnAddrs: []netip.Addr{vpnAddr},
		remotes:  NewRemoteList([]netip.Addr{vpnAddr}, nil),
	}
	hostinfo.remotes.LearnRemote(vpnAddr, punchTargetV4)
	hostinfo.SetRemote(punchTargetV6)
	return hostinfo
}

func newPunchyForTest(t *testing.T, settings map[string]any, conn udp.Conn) *Punchy {
	c := config.NewC(test.NewLogger())
	c.Settings["punchy"] = settings
	p := NewPunchyFromConfig(test.NewLogger(), c, conn)

	hm := newHostMap(test.NewLogger())
	hm.preferredRanges.Store(&[]netip.Prefix{})
	p.hm = hm
	p.lh = noLighthouses{}
	return p
}

func TestPunchy_SendPunchReportsCurrentRemote(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV6: errNoRoute}}
		p := newPunchyForTest(t, map[string]any{"punch": false}, conn)

		remote, err := p.SendPunch(newPunchTarget())
		assert.False(t, remote.IsValid())
		require.NoError(t, err)
		assert.Empty(t, conn.wrote)
	})

	t.Run("current remote", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV6: errNoRoute}}
		p := newPunchyForTest(t, map[string]any{"punch": true}, conn)

		remote, err := p.SendPunch(newPunchTarget())
		assert.Equal(t, punchTargetV6, remote)
		require.ErrorIs(t, err, errNoRoute)
		assert.Equal(t, []netip.AddrPort{punchTargetV6}, conn.wrote)
	})

	t.Run("all remotes, current fails", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV6: errNoRoute}}
		p := newPunchyForTest(t, map[string]any{"punch": true, "target_all_remotes": true}, conn)

		remote, err := p.SendPunch(newPunchTarget())
		assert.Equal(t, punchTargetV6, remote)
		require.ErrorIs(t, err, errNoRoute)
		assert.ElementsMatch(t, []netip.AddrPort{punchTargetV4, punchTargetV6}, conn.wrote)
	})

	t.Run("all remotes, only another fails", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV4: errNoRoute}}
		p := newPunchyForTest(t, map[string]any{"punch": true, "target_all_remotes": true}, conn)

		remote, err := p.SendPunch(newPunchTarget())
		assert.Equal(t, punchTargetV6, remote)
		require.NoError(t, err, "a failure on a remote we are not using says nothing about the current one")
		assert.ElementsMatch(t, []netip.AddrPort{punchTargetV4, punchTargetV6}, conn.wrote)
	})
}
