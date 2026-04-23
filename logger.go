package nebula

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/config"
)

// LogLevelTrace matches logrus.TraceLevel so "trace" in logging.level still
// enables the noisiest logs. slog itself has no builtin trace level.
const LogLevelTrace = slog.Level(-8)

// ReconfigurableHandler is the slog.Handler returned by NewLogger. It
// supports atomic format and level changes at runtime, and its inner handler
// can be replaced wholesale to plug in platform-specific log sinks such as
// the Windows Event Viewer. All derived handlers (produced via
// WithAttrs/WithGroup) share the same root so reload-driven changes
// propagate to every logger in the process.
type ReconfigurableHandler struct {
	root *handlerRoot
	// mods is the ordered chain of WithAttrs/WithGroup ops to replay onto the
	// current inner handler every time a record is handled.
	mods []func(slog.Handler) slog.Handler
}

type handlerRoot struct {
	w     io.Writer
	level slog.LevelVar
	inner atomic.Pointer[slog.Handler]

	// mu guards format, timestampFormat, disableTimestamp, and pinned.
	// Level uses its own atomic via slog.LevelVar.
	mu               sync.Mutex
	format           string
	timestampFormat  string
	disableTimestamp bool
	// pinned is set by ReplaceInner and prevents configLogger rebuilds from
	// clobbering a platform-specific inner handler. Level changes still
	// propagate because they go through the shared LevelVar.
	pinned bool
}

// NewLogger returns a *slog.Logger whose level and format can later be
// reconfigured by configLogger or by the SSH debug commands. The default
// configuration is info-level text output so log calls made before
// configLogger runs still produce output.
func NewLogger(w io.Writer) *slog.Logger {
	root := &handlerRoot{
		w:               w,
		format:          "text",
		timestampFormat: time.RFC3339,
	}
	root.level.Set(slog.LevelInfo)
	root.rebuild()
	return slog.New(&ReconfigurableHandler{root: root})
}

// rebuild constructs a fresh inner handler from the current format and
// timestamp settings and stores it atomically. It is a no-op when a platform
// handler has been pinned via ReplaceInner.
func (r *handlerRoot) rebuild() {
	r.mu.Lock()
	if r.pinned {
		r.mu.Unlock()
		return
	}
	format := r.format
	timestampFormat := r.timestampFormat
	disableTimestamp := r.disableTimestamp
	r.mu.Unlock()

	replaceAttr := func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			if disableTimestamp {
				return slog.Attr{}
			}
			if a.Value.Kind() == slog.KindTime {
				return slog.String(slog.TimeKey, a.Value.Time().Format(timestampFormat))
			}
		}
		return a
	}
	opts := &slog.HandlerOptions{Level: &r.level, ReplaceAttr: replaceAttr}

	var h slog.Handler
	switch format {
	case "json":
		h = slog.NewJSONHandler(r.w, opts)
	default:
		h = slog.NewTextHandler(r.w, opts)
	}
	r.inner.Store(&h)
}

func (rh *ReconfigurableHandler) current() slog.Handler {
	h := *rh.root.inner.Load()
	for _, mod := range rh.mods {
		h = mod(h)
	}
	return h
}

// Enabled reports whether the current level admits l. Always uses the root
// LevelVar so derived handlers see level changes immediately.
func (rh *ReconfigurableHandler) Enabled(_ context.Context, l slog.Level) bool {
	return rh.root.level.Level() <= l
}

// Handle dispatches r to the current inner handler after replaying any
// WithAttrs/WithGroup modifications that produced this derived handler.
func (rh *ReconfigurableHandler) Handle(ctx context.Context, r slog.Record) error {
	return rh.current().Handle(ctx, r)
}

func (rh *ReconfigurableHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return rh
	}
	mods := make([]func(slog.Handler) slog.Handler, len(rh.mods)+1)
	copy(mods, rh.mods)
	mods[len(rh.mods)] = func(h slog.Handler) slog.Handler { return h.WithAttrs(attrs) }
	return &ReconfigurableHandler{root: rh.root, mods: mods}
}

func (rh *ReconfigurableHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return rh
	}
	mods := make([]func(slog.Handler) slog.Handler, len(rh.mods)+1)
	copy(mods, rh.mods)
	mods[len(rh.mods)] = func(h slog.Handler) slog.Handler { return h.WithGroup(name) }
	return &ReconfigurableHandler{root: rh.root, mods: mods}
}

// SetLevel updates the log level, affecting every logger derived from this
// root. Thanks to slog.LevelVar no handler rebuild is needed.
func (rh *ReconfigurableHandler) SetLevel(level slog.Level) {
	rh.root.level.Set(level)
}

// GetLevel returns the current log level.
func (rh *ReconfigurableHandler) GetLevel() slog.Level {
	return rh.root.level.Level()
}

// SetFormat swaps the output format atomically. Valid formats are "text" and
// "json". It is a no-op when a platform handler has been pinned via
// ReplaceInner.
func (rh *ReconfigurableHandler) SetFormat(format string) error {
	switch format {
	case "text", "json":
	default:
		return fmt.Errorf("unknown log format `%s`. possible formats: %s", format, []string{"text", "json"})
	}
	rh.root.mu.Lock()
	rh.root.format = format
	rh.root.mu.Unlock()
	rh.root.rebuild()
	return nil
}

// GetFormat returns the currently configured output format.
func (rh *ReconfigurableHandler) GetFormat() string {
	rh.root.mu.Lock()
	defer rh.root.mu.Unlock()
	return rh.root.format
}

// ReplaceInner swaps the inner handler with h and marks the root as pinned,
// so subsequent calls to configLogger and SetFormat leave the inner handler
// alone. Level changes continue to propagate via the shared LevelVar. Used
// by platform hooks (e.g., Windows event log) that provide a bespoke sink.
func (rh *ReconfigurableHandler) ReplaceInner(h slog.Handler) {
	rh.root.mu.Lock()
	rh.root.pinned = true
	rh.root.mu.Unlock()
	rh.root.inner.Store(&h)
}

// HandlerOf returns the ReconfigurableHandler underlying l, if l was created
// by NewLogger (or any derivative). Callers use this to adjust level/format
// at runtime or to replace the inner handler.
func HandlerOf(l *slog.Logger) (*ReconfigurableHandler, bool) {
	rh, ok := l.Handler().(*ReconfigurableHandler)
	return rh, ok
}

// configLogger reads logging.level/format/timestamp settings from c and
// applies them to l. l must be a logger returned by NewLogger; otherwise
// configLogger returns an error.
func configLogger(l *slog.Logger, c *config.C) error {
	rh, ok := HandlerOf(l)
	if !ok {
		return fmt.Errorf("logger is not reconfigurable")
	}

	lvl, err := parseLogLevel(strings.ToLower(c.GetString("logging.level", "info")))
	if err != nil {
		return err
	}

	format := strings.ToLower(c.GetString("logging.format", "text"))
	switch format {
	case "text", "json":
	default:
		return fmt.Errorf("unknown log format `%s`. possible formats: %s", format, []string{"text", "json"})
	}

	timestampFormat := c.GetString("logging.timestamp_format", "")
	if timestampFormat == "" {
		timestampFormat = time.RFC3339
	}

	rh.root.mu.Lock()
	rh.root.format = format
	rh.root.timestampFormat = timestampFormat
	rh.root.disableTimestamp = c.GetBool("logging.disable_timestamp", false)
	rh.root.mu.Unlock()

	rh.root.level.Set(lvl)
	rh.root.rebuild()
	return nil
}

func parseLogLevel(s string) (slog.Level, error) {
	switch s {
	case "trace":
		return LogLevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	case "fatal", "panic":
		// logrus had these; slog collapses them into error.
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("not a valid logging level: %q", s)
	}
}

// logLevelName returns a human-readable name for a slog.Level matching the
// strings accepted by parseLogLevel.
func logLevelName(l slog.Level) string {
	switch {
	case l <= LogLevelTrace:
		return "trace"
	case l <= slog.LevelDebug:
		return "debug"
	case l <= slog.LevelInfo:
		return "info"
	case l <= slog.LevelWarn:
		return "warn"
	default:
		return "error"
	}
}
