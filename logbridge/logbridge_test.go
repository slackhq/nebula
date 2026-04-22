package logbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"testing/slogtest"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type capture struct {
	entries []*logrus.Entry
}

func (c *capture) Levels() []logrus.Level { return logrus.AllLevels }

func (c *capture) Fire(e *logrus.Entry) error {
	dup := *e
	dup.Data = logrus.Fields{}
	for k, v := range e.Data {
		dup.Data[k] = v
	}
	c.entries = append(c.entries, &dup)
	return nil
}

func newTestLogger(level logrus.Level) (*logrus.Logger, *capture) {
	l := logrus.New()
	l.SetOutput(io.Discard)
	l.SetLevel(level)
	cap := &capture{}
	l.AddHook(cap)
	return l, cap
}

func TestLevelMapping(t *testing.T) {
	l, cap := newTestLogger(logrus.TraceLevel)
	s := FromLogrus(l)

	s.Log(context.Background(), LevelTrace, "trace msg")
	s.Debug("debug msg")
	s.Info("info msg")
	s.Warn("warn msg")
	s.Error("error msg")

	require.Len(t, cap.entries, 5)
	assert.Equal(t, logrus.TraceLevel, cap.entries[0].Level)
	assert.Equal(t, "trace msg", cap.entries[0].Message)
	assert.Equal(t, logrus.DebugLevel, cap.entries[1].Level)
	assert.Equal(t, logrus.InfoLevel, cap.entries[2].Level)
	assert.Equal(t, logrus.WarnLevel, cap.entries[3].Level)
	assert.Equal(t, logrus.ErrorLevel, cap.entries[4].Level)
}

func TestEnabledHonorsLogrusLevel(t *testing.T) {
	l, cap := newTestLogger(logrus.WarnLevel)
	s := FromLogrus(l)

	s.Debug("filtered")
	s.Info("filtered")
	s.Warn("kept")
	s.Error("kept")

	require.Len(t, cap.entries, 2)
	assert.Equal(t, "kept", cap.entries[0].Message)
	assert.Equal(t, logrus.WarnLevel, cap.entries[0].Level)
	assert.Equal(t, logrus.ErrorLevel, cap.entries[1].Level)
}

func TestAttrsBecomeFields(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	s := FromLogrus(l)

	err := errors.New("boom")
	s.LogAttrs(context.Background(), slog.LevelInfo, "hello",
		slog.String("vpnIp", "10.0.0.1"),
		slog.Int("port", 4242),
		slog.Any("err", err),
	)

	require.Len(t, cap.entries, 1)
	assert.Equal(t, "hello", cap.entries[0].Message)
	assert.Equal(t, "10.0.0.1", cap.entries[0].Data["vpnIp"])
	assert.Equal(t, int64(4242), cap.entries[0].Data["port"])
	assert.Same(t, err, cap.entries[0].Data["err"])
}

func TestWithAttrsPersistsAcrossCalls(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	s := FromLogrus(l).With("subsystem", "handshake")

	s.Info("one")
	s.Info("two", "extra", 7)

	require.Len(t, cap.entries, 2)
	assert.Equal(t, "handshake", cap.entries[0].Data["subsystem"])
	assert.NotContains(t, cap.entries[0].Data, "extra")
	assert.Equal(t, "handshake", cap.entries[1].Data["subsystem"])
	assert.Equal(t, int64(7), cap.entries[1].Data["extra"])
}

func TestWithGroupPrefixesKeys(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	s := FromLogrus(l).WithGroup("peer").With("id", 42)

	s.Info("got packet", "bytes", 1200)

	require.Len(t, cap.entries, 1)
	assert.Equal(t, int64(42), cap.entries[0].Data["peer.id"])
	assert.Equal(t, int64(1200), cap.entries[0].Data["peer.bytes"])
}

func TestNestedGroupsFlatten(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	s := FromLogrus(l)

	s.LogAttrs(context.Background(), slog.LevelInfo, "nested",
		slog.Group("outer",
			slog.Int("a", 1),
			slog.Group("inner", slog.String("b", "x")),
		),
	)

	require.Len(t, cap.entries, 1)
	assert.Equal(t, int64(1), cap.entries[0].Data["outer.a"])
	assert.Equal(t, "x", cap.entries[0].Data["outer.inner.b"])
}

func TestEmptyAttrSkipped(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	s := FromLogrus(l)

	s.LogAttrs(context.Background(), slog.LevelInfo, "msg",
		slog.Attr{},
		slog.String("k", "v"),
	)

	require.Len(t, cap.entries, 1)
	assert.Len(t, cap.entries[0].Data, 1)
	assert.Equal(t, "v", cap.entries[0].Data["k"])
}

// TestEmptyKeyNonGroupSkipped covers the slog.Handler rule that an Attr with
// an empty key and a non-zero value has no sensible flat representation and
// must not appear in output. The zero-Attr check alone wouldn't catch this
// because the value is non-zero.
func TestEmptyKeyNonGroupSkipped(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	s := FromLogrus(l)

	s.LogAttrs(context.Background(), slog.LevelInfo, "msg",
		slog.Attr{Key: "", Value: slog.StringValue("x")},
		slog.String("k", "v"),
	)

	require.Len(t, cap.entries, 1)
	assert.Len(t, cap.entries[0].Data, 1)
	assert.Equal(t, "v", cap.entries[0].Data["k"])
	assert.NotContains(t, cap.entries[0].Data, "")
}

// TestEmptyGroupSkipped covers the rule that a group with no attrs must be
// omitted entirely (not even its key should appear).
func TestEmptyGroupSkipped(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	s := FromLogrus(l)

	s.LogAttrs(context.Background(), slog.LevelInfo, "msg",
		slog.String("a", "b"),
		slog.Group("empty"),
		slog.String("e", "f"),
	)

	require.Len(t, cap.entries, 1)
	assert.Equal(t, "b", cap.entries[0].Data["a"])
	assert.Equal(t, "f", cap.entries[0].Data["e"])
	for k := range cap.entries[0].Data {
		assert.False(t, strings.HasPrefix(k, "empty"), "unexpected empty-group key %q", k)
	}
}

// TestInlineGroup covers the rule that a group with an empty key inlines its
// attrs at the current level.
func TestInlineGroup(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	s := FromLogrus(l)

	s.LogAttrs(context.Background(), slog.LevelInfo, "msg",
		slog.String("a", "b"),
		slog.Group("", slog.String("c", "d")),
		slog.String("e", "f"),
	)

	require.Len(t, cap.entries, 1)
	assert.Equal(t, "b", cap.entries[0].Data["a"])
	assert.Equal(t, "d", cap.entries[0].Data["c"])
	assert.Equal(t, "f", cap.entries[0].Data["e"])
}

// TestWithAttrsDoesNotMutate guards against a future refactor that forgets
// to copy the fields map and ends up aliasing the receiver's state.
func TestWithAttrsDoesNotMutate(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	parent := FromLogrus(l).With("shared", "parent")
	child := parent.With("only", "child")

	parent.Info("p")
	child.Info("c")

	require.Len(t, cap.entries, 2)
	assert.Equal(t, "parent", cap.entries[0].Data["shared"])
	assert.NotContains(t, cap.entries[0].Data, "only")
	assert.Equal(t, "parent", cap.entries[1].Data["shared"])
	assert.Equal(t, "child", cap.entries[1].Data["only"])
}

// TestWithGroupDoesNotMutate is the group-prefix analogue of the WithAttrs
// immutability test.
func TestWithGroupDoesNotMutate(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	parent := FromLogrus(l).With("shared", "x")
	child := parent.WithGroup("peer").With("id", 1)

	parent.Info("p", "flat", 2)
	child.Info("c")

	require.Len(t, cap.entries, 2)
	// Parent still writes flat keys, no "peer." prefix leaked into it.
	assert.Equal(t, int64(2), cap.entries[0].Data["flat"])
	assert.NotContains(t, cap.entries[0].Data, "peer.id")
	// Child has both the inherited attr and the grouped one.
	assert.Equal(t, "x", cap.entries[1].Data["shared"])
	assert.Equal(t, int64(1), cap.entries[1].Data["peer.id"])
}

// TestSlogtestCompliance runs the stdlib slogtest suite against the bridge.
// The suite asserts on the full slog.Handler contract. We use Run (subtests)
// rather than TestHandler so failures are pinpointed.
//
// The "zero-time" case is skipped because logrus's Entry.log unconditionally
// sets entry.Time = time.Now() when the time is zero, so the bridge cannot
// suppress the time field no matter what we do on our side. This is one of
// the documented bridge deviations. All other cases pass with an
// unflattening parser that reverses the dot-joined group representation.
func TestSlogtestCompliance(t *testing.T) {
	var buf bytes.Buffer

	newHandler := func(t *testing.T) slog.Handler {
		if strings.HasSuffix(t.Name(), "/zero-time") {
			t.Skip("logrus Entry.log rewrites zero entry.Time to time.Now(); bridge cannot omit the time field")
		}
		buf.Reset()
		lr := logrus.New()
		lr.Out = &buf
		lr.Formatter = &logrus.JSONFormatter{}
		lr.SetLevel(logrus.DebugLevel)
		return NewHandler(lr)
	}

	result := func(t *testing.T) map[string]any {
		line := bytes.TrimSpace(buf.Bytes())
		var flat map[string]any
		if err := json.Unmarshal(line, &flat); err != nil {
			t.Fatalf("parse JSON %q: %v", line, err)
		}
		return unflattenKeys(flat)
	}

	slogtest.Run(t, newHandler, result)
}

// unflattenKeys reverses the bridge's dot-joined flat-key representation
// of slog groups so slogtest's inGroup checks see nested map[string]any.
// "peer.id" becomes {"peer": {"id": ...}}. Does not touch the reserved
// logrus keys (time, level, msg), which never contain dots.
func unflattenKeys(flat map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range flat {
		parts := strings.Split(k, ".")
		cur := out
		for _, p := range parts[:len(parts)-1] {
			next, ok := cur[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				cur[p] = next
			}
			cur = next
		}
		cur[parts[len(parts)-1]] = v
	}
	return out
}

type resolvable string

func (r resolvable) LogValue() slog.Value { return slog.StringValue("resolved:" + string(r)) }

func TestLogValuerResolved(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	s := FromLogrus(l)

	s.LogAttrs(context.Background(), slog.LevelInfo, "msg",
		slog.Any("v", resolvable("hi")),
	)

	require.Len(t, cap.entries, 1)
	assert.Equal(t, "resolved:hi", cap.entries[0].Data["v"])
}

func TestRecordTimePropagates(t *testing.T) {
	l, cap := newTestLogger(logrus.InfoLevel)
	h := NewHandler(l)

	want := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	r := slog.NewRecord(want, slog.LevelInfo, "msg", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	require.Len(t, cap.entries, 1)
	assert.True(t, want.Equal(cap.entries[0].Time), "expected %v got %v", want, cap.entries[0].Time)
}

func TestEnabledMethod(t *testing.T) {
	l, _ := newTestLogger(logrus.InfoLevel)
	h := NewHandler(l)

	ctx := context.Background()
	assert.False(t, h.Enabled(ctx, LevelTrace))
	assert.False(t, h.Enabled(ctx, slog.LevelDebug))
	assert.True(t, h.Enabled(ctx, slog.LevelInfo))
	assert.True(t, h.Enabled(ctx, slog.LevelWarn))
	assert.True(t, h.Enabled(ctx, slog.LevelError))
}
