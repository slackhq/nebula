package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// newPlatformLogger returns a *slog.Logger that routes every log record
// through the Windows service logger so records end up in the Windows Event
// Viewer. Formatting is delegated to slog's builtin text or JSON handler
// (controlled by logging.format) writing into a shared buffer; the
// formatted line is then forwarded to the service logger at a severity
// matching the record's level. The handler exposes SetLevel/SetFormat
// structurally so configLogger and the SSH debug commands honor
// logging.level and logging.format on startup and SIGHUP.
func newPlatformLogger() *slog.Logger {
	root := &serviceHandlerRoot{format: "text"}
	root.level.Set(slog.LevelInfo)
	return slog.New(&serviceHandler{root: root, inner: root.buildInner()})
}

// serviceHandlerRoot owns the per-logger mutable state shared across
// WithAttrs/WithGroup derivations: the LevelVar, the output buffer used by
// every Handle call (serialized under buf.mu), and the currently configured
// format string.
type serviceHandlerRoot struct {
	level slog.LevelVar

	// mu serializes Handle's reset+serialize+route cycle against itself and
	// against rebuilds triggered by SetFormat.
	mu  sync.Mutex
	buf bytes.Buffer

	// format is protected by mu.
	format string
}

// buildInner constructs a fresh slog.Handler that writes into the shared
// buf, honoring the current format. mu must be held.
func (r *serviceHandlerRoot) buildInner() slog.Handler {
	opts := &slog.HandlerOptions{Level: &r.level}
	switch r.format {
	case "json":
		return slog.NewJSONHandler(&r.buf, opts)
	default:
		return slog.NewTextHandler(&r.buf, opts)
	}
}

// serviceHandler defers record formatting to a slog builtin handler and
// routes the formatted line to the Windows service logger by severity.
type serviceHandler struct {
	root  *serviceHandlerRoot
	inner slog.Handler // writes to root.buf; carries accumulated WithAttrs/WithGroup state
}

func (sh *serviceHandler) Enabled(_ context.Context, l slog.Level) bool {
	return sh.root.level.Level() <= l
}

func (sh *serviceHandler) Handle(ctx context.Context, r slog.Record) error {
	sh.root.mu.Lock()
	defer sh.root.mu.Unlock()
	sh.root.buf.Reset()
	if err := sh.inner.Handle(ctx, r); err != nil {
		return err
	}
	line := strings.TrimRight(sh.root.buf.String(), "\n")
	switch {
	case r.Level >= slog.LevelError:
		return logger.Error(line)
	case r.Level >= slog.LevelWarn:
		return logger.Warning(line)
	default:
		return logger.Info(line)
	}
}

func (sh *serviceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return sh
	}
	return &serviceHandler{root: sh.root, inner: sh.inner.WithAttrs(attrs)}
}

func (sh *serviceHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return sh
	}
	return &serviceHandler{root: sh.root, inner: sh.inner.WithGroup(name)}
}

// SetLevel lets configLogger and the SSH commands honor logging.level. The
// LevelVar lives on the shared root so derived handlers pick up changes.
func (sh *serviceHandler) SetLevel(lvl slog.Level) { sh.root.level.Set(lvl) }

// GetLevel is the structural counterpart used by sshLogLevel.
func (sh *serviceHandler) GetLevel() slog.Level { return sh.root.level.Level() }

// SetFormat rebuilds this handler's inner so future records serialize using
// the new format. Called on startup and on SIGHUP. Derived handlers created
// BEFORE a format change continue to use the prior format, which is fine
// for the common case where configLogger runs before subsystems construct
// their loggers; format reload after subsystems have derived is uncommon on
// Windows service deployments.
func (sh *serviceHandler) SetFormat(format string) error {
	switch format {
	case "text", "json":
	default:
		return fmt.Errorf("unknown log format `%s`. possible formats: %s", format, []string{"text", "json"})
	}
	sh.root.mu.Lock()
	defer sh.root.mu.Unlock()
	sh.root.format = format
	sh.inner = sh.root.buildInner()
	return nil
}

// GetFormat is the structural counterpart used by sshLogFormat.
func (sh *serviceHandler) GetFormat() string {
	sh.root.mu.Lock()
	defer sh.root.mu.Unlock()
	return sh.root.format
}
