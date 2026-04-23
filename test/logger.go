package test

import (
	"io"
	"log/slog"
	"os"
)

// logLevelTrace mirrors nebula.LogLevelTrace. Duplicated to keep this package
// free of an import cycle on the nebula package.
const logLevelTrace = slog.Level(-8)

// NewLogger returns a *slog.Logger suitable for use in tests. Output goes to
// io.Discard by default; set TEST_LOGS=1 (info), 2 (debug), or 3 (trace) to
// stream output to stderr for local debugging.
func NewLogger() *slog.Logger {
	v := os.Getenv("TEST_LOGS")
	if v == "" {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	level := slog.LevelInfo
	switch v {
	case "2":
		level = slog.LevelDebug
	case "3":
		level = logLevelTrace
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// NewLoggerWithOutput returns a *slog.Logger whose text output is captured by
// w. Tests asserting on output format should compose their own handler if
// they need timestamp suppression or other tweaks.
func NewLoggerWithOutput(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil))
}
