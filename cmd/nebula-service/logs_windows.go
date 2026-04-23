package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
)

// newPlatformLogger returns a *slog.Logger that routes every log record
// through the Windows service logger so records end up in the Windows Event
// Viewer. Formatting is delegated to slog's builtin text or JSON handler
// writing into a shared buffer; the formatted line is then forwarded to the
// service logger at a severity matching the record's level. Both a text
// and a json handler are pre-derived at each WithAttrs/WithGroup call so a
// SetFormat flip propagates instantly without rebuilding anything.
func newPlatformLogger() *slog.Logger {
	root := &serviceHandlerRoot{}
	root.level.Set(slog.LevelInfo)
	opts := &slog.HandlerOptions{Level: &root.level}
	return slog.New(&serviceHandler{
		root: root,
		text: slog.NewTextHandler(&root.buf, opts),
		json: slog.NewJSONHandler(&root.buf, opts),
	})
}

// serviceHandlerRoot holds the per-logger mutable state shared across
// WithAttrs/WithGroup derivations. The buffer is shared because Handle
// serializes on mu before each serialize + route + reset cycle.
type serviceHandlerRoot struct {
	level    slog.LevelVar
	jsonMode atomic.Bool

	mu  sync.Mutex
	buf bytes.Buffer
}

// serviceHandler dispatches each record to either a text or a json
// slog.Handler (both write into the shared buffer), then forwards the
// formatted line to the Windows service logger at the matching severity.
type serviceHandler struct {
	root *serviceHandlerRoot
	text slog.Handler
	json slog.Handler
}

func (sh *serviceHandler) Enabled(_ context.Context, l slog.Level) bool {
	return sh.root.level.Level() <= l
}

func (sh *serviceHandler) Handle(ctx context.Context, r slog.Record) error {
	sh.root.mu.Lock()
	defer sh.root.mu.Unlock()
	sh.root.buf.Reset()

	var err error
	if sh.root.jsonMode.Load() {
		err = sh.json.Handle(ctx, r)
	} else {
		err = sh.text.Handle(ctx, r)
	}
	if err != nil {
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
	return &serviceHandler{
		root: sh.root,
		text: sh.text.WithAttrs(attrs),
		json: sh.json.WithAttrs(attrs),
	}
}

func (sh *serviceHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return sh
	}
	return &serviceHandler{
		root: sh.root,
		text: sh.text.WithGroup(name),
		json: sh.json.WithGroup(name),
	}
}

// SetLevel lets configLogger and SSH commands honor logging.level.
func (sh *serviceHandler) SetLevel(lvl slog.Level) { sh.root.level.Set(lvl) }

// GetLevel is the structural counterpart used by sshLogLevel.
func (sh *serviceHandler) GetLevel() slog.Level { return sh.root.level.Level() }

// SetFormat flips which inner handler Handle dispatches to. The change
// propagates to every derived handler immediately; no rebuild is required.
func (sh *serviceHandler) SetFormat(format string) error {
	switch format {
	case "text":
		sh.root.jsonMode.Store(false)
	case "json":
		sh.root.jsonMode.Store(true)
	default:
		return fmt.Errorf("unknown log format `%s`. possible formats: %s", format, []string{"text", "json"})
	}
	return nil
}

// GetFormat is the structural counterpart used by sshLogFormat.
func (sh *serviceHandler) GetFormat() string {
	if sh.root.jsonMode.Load() {
		return "json"
	}
	return "text"
}
