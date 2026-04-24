package main

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/slackhq/nebula/logging"
)

// newPlatformLogger returns a *slog.Logger that routes every log record
// through the Windows service logger so records end up in the Windows
// Event Log. All the heavy lifting (level management, format swap,
// timestamp toggle, WithAttrs/WithGroup) comes from logging.NewHandler;
// this file only contributes:
//
//   - an io.Writer that forwards each formatted line to the service
//     logger at the current record's Event Log severity, and
//   - a thin severityTag that embeds *logging.Handler and overrides
//     only Handle / WithAttrs / WithGroup, so Event Viewer's severity
//     column and severity-based filters keep working the way they did
//     before the slog migration.
//
// Format (text vs json) is carried by the embedded *logging.Handler, so
// logging.format: json in config still produces JSON lines in Event
// Viewer, same as the pre-slog logrus setup.
func newPlatformLogger() *slog.Logger {
	w := &eventLogWriter{}
	return slog.New(&severityTag{Handler: logging.NewHandler(w), w: w})
}

// eventLogWriter forwards slog-formatted lines to the Windows service
// logger at the severity most recently stashed by severityTag.Handle.
// The mutex serializes the stash + inner.Handle + Write cycle per record
// across all concurrent goroutines; slog's builtin text/json handlers
// each hold their own mutex around Write, but that only protects the
// Write call itself, not our stash-then-handle sequence.
type eventLogWriter struct {
	mu    sync.Mutex
	level slog.Level
}

func (w *eventLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	switch {
	case w.level >= slog.LevelError:
		return len(p), logger.Error(line)
	case w.level >= slog.LevelWarn:
		return len(p), logger.Warning(line)
	default:
		return len(p), logger.Info(line)
	}
}

// severityTag embeds *logging.Handler to pick up everything it does for
// free (Enabled, SetLevel, GetLevel, SetFormat, GetFormat,
// SetDisableTimestamp) and overrides only Handle / WithAttrs / WithGroup
// so each record's slog.Level is stashed on the writer before formatting
// and so derived handlers stay wrapped as severityTag rather than
// downgrading to bare *logging.Handler.
type severityTag struct {
	*logging.Handler
	w *eventLogWriter
}

func (s *severityTag) Handle(ctx context.Context, r slog.Record) error {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	s.w.level = r.Level
	return s.Handler.Handle(ctx, r)
}

func (s *severityTag) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return s
	}
	return &severityTag{Handler: s.Handler.WithAttrs(attrs).(*logging.Handler), w: s.w}
}

func (s *severityTag) WithGroup(name string) slog.Handler {
	if name == "" {
		return s
	}
	return &severityTag{Handler: s.Handler.WithGroup(name).(*logging.Handler), w: s.w}
}
