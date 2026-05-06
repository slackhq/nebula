package test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/slackhq/nebula/logging"
)

// NewLogger returns a *slog.Logger suitable for use in tests. Output goes to
// io.Discard by default; set TEST_LOGS=1 (info), 2 (debug), or 3 (trace) to
// stream output to stderr for local debugging.
func NewLogger() *slog.Logger {
	v := os.Getenv("TEST_LOGS")
	if v == "" {
		return slog.New(slog.DiscardHandler)
	}

	level := slog.LevelInfo
	switch v {
	case "2":
		level = slog.LevelDebug
	case "3":
		level = logging.LevelTrace
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// NewLoggerWithOutput returns a *slog.Logger whose text output is captured by
// w. Timestamps are suppressed so tests can assert on exact output without
// baking the current time into expected strings.
func NewLoggerWithOutput(w io.Writer) *slog.Logger {
	return slog.New(&stripTimeHandler{inner: slog.NewTextHandler(w, nil)})
}

// NewLoggerWithOutputAndLevel is NewLoggerWithOutput with an explicit level
// so tests can exercise Enabled-gated paths.
func NewLoggerWithOutputAndLevel(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(&stripTimeHandler{inner: slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})})
}

// NewJSONLoggerWithOutput returns a *slog.Logger emitting JSON to w with
// timestamps suppressed, for tests that pin the JSON shape.
func NewJSONLoggerWithOutput(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(&stripTimeHandler{inner: slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})})
}

// stripTimeHandler zeros each record's time before delegating so slog's
// built-in handlers skip emitting the time attribute. Used to avoid
// timestamp-dependent assertions in tests without resorting to ReplaceAttr.
type stripTimeHandler struct {
	inner slog.Handler
}

func (h *stripTimeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *stripTimeHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Time = time.Time{}
	return h.inner.Handle(ctx, r)
}

func (h *stripTimeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &stripTimeHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *stripTimeHandler) WithGroup(name string) slog.Handler {
	return &stripTimeHandler{inner: h.inner.WithGroup(name)}
}
