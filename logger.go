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

// LogLevelTrace is a custom slog level below Debug, used when logging.level
// is "trace". slog has no builtin trace level; the value is one step below
// slog.LevelDebug in slog's 4-point spacing.
const LogLevelTrace = slog.Level(-8)

// NewLogger returns a *slog.Logger whose level, format, and timestamp
// emission can be reconfigured by configLogger on startup and on SIGHUP.
// The default configuration is info-level text output so log calls made
// before configLogger runs still produce output. Timestamps follow slog's
// default RFC3339Nano format; set logging.disable_timestamp in config to
// suppress them.
//
// configLogger and the SSH debug commands discover the reconfig surface via
// structural type-assertion on l.Handler(), so replacement implementations
// (tests, platform-specific sinks) need only implement the subset of
// {SetLevel(slog.Level), SetFormat(string) error, SetDisableTimestamp(bool)}
// they care about. Callers that do not need reconfig can pass a plain
// *slog.Logger to nebula.Main; configLogger becomes a no-op for handlers it
// does not recognize.
func NewLogger(w io.Writer) *slog.Logger {
	root := &handlerRoot{
		w:      w,
		format: "text",
	}
	root.level.Set(slog.LevelInfo)
	root.rebuild()
	return slog.New(&reconfigurableHandler{root: root})
}

// reconfigurableHandler is a slog.Handler whose underlying handler can be
// swapped atomically. All derived handlers (produced via WithAttrs/WithGroup)
// share the same root so reload-driven changes propagate to every logger in
// the process.
type reconfigurableHandler struct {
	root *handlerRoot
	// mods is the ordered chain of WithAttrs/WithGroup ops to replay onto the
	// current inner handler every time a record is handled.
	mods []func(slog.Handler) slog.Handler
}

type handlerRoot struct {
	w     io.Writer
	level slog.LevelVar
	inner atomic.Pointer[slog.Handler]

	// mu guards format. Level uses its own atomic via slog.LevelVar, and
	// disableTimestamp uses atomic.Bool so Handle can consult it on every
	// record without taking a mutex on the log path.
	mu               sync.Mutex
	format           string
	disableTimestamp atomic.Bool
}

// rebuild constructs a fresh inner handler from the current format and
// level settings and stores it atomically.
func (r *handlerRoot) rebuild() {
	r.mu.Lock()
	format := r.format
	r.mu.Unlock()

	opts := &slog.HandlerOptions{Level: &r.level}

	var h slog.Handler
	switch format {
	case "json":
		h = slog.NewJSONHandler(r.w, opts)
	default:
		h = slog.NewTextHandler(r.w, opts)
	}
	r.inner.Store(&h)
}

func (rh *reconfigurableHandler) current() slog.Handler {
	h := *rh.root.inner.Load()
	for _, mod := range rh.mods {
		h = mod(h)
	}
	return h
}

func (rh *reconfigurableHandler) Enabled(_ context.Context, l slog.Level) bool {
	return rh.root.level.Level() <= l
}

func (rh *reconfigurableHandler) Handle(ctx context.Context, r slog.Record) error {
	if rh.root.disableTimestamp.Load() {
		r.Time = time.Time{}
	}
	return rh.current().Handle(ctx, r)
}

func (rh *reconfigurableHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return rh
	}
	mods := make([]func(slog.Handler) slog.Handler, len(rh.mods)+1)
	copy(mods, rh.mods)
	mods[len(rh.mods)] = func(h slog.Handler) slog.Handler { return h.WithAttrs(attrs) }
	return &reconfigurableHandler{root: rh.root, mods: mods}
}

func (rh *reconfigurableHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return rh
	}
	mods := make([]func(slog.Handler) slog.Handler, len(rh.mods)+1)
	copy(mods, rh.mods)
	mods[len(rh.mods)] = func(h slog.Handler) slog.Handler { return h.WithGroup(name) }
	return &reconfigurableHandler{root: rh.root, mods: mods}
}

// SetLevel satisfies the structural level-setter interface used by
// configLogger and sshLogLevel. Changes propagate to every derived logger
// via the shared LevelVar.
func (rh *reconfigurableHandler) SetLevel(level slog.Level) {
	rh.root.level.Set(level)
}

// GetLevel is the structural counterpart used by sshLogLevel to report the
// current level.
func (rh *reconfigurableHandler) GetLevel() slog.Level {
	return rh.root.level.Level()
}

// SetFormat satisfies the structural format-setter interface. Valid formats
// are "text" and "json". The inner handler is rebuilt and swapped.
func (rh *reconfigurableHandler) SetFormat(format string) error {
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

// GetFormat is the structural counterpart used by sshLogFormat.
func (rh *reconfigurableHandler) GetFormat() string {
	rh.root.mu.Lock()
	defer rh.root.mu.Unlock()
	return rh.root.format
}

// SetDisableTimestamp satisfies the optional timestamp-toggle interface
// used by configLogger.
func (rh *reconfigurableHandler) SetDisableTimestamp(v bool) {
	rh.root.disableTimestamp.Store(v)
}

// configLogger reads logging.level, logging.format, and (optionally)
// logging.disable_timestamp from c and applies them to l. The reconfig
// surface is discovered via structural type-assertion on l.Handler(), so
// foreign handlers silently opt out of whichever capabilities they do not
// implement.
func configLogger(l *slog.Logger, c *config.C) error {
	h := l.Handler()

	lvl, err := parseLogLevel(strings.ToLower(c.GetString("logging.level", "info")))
	if err != nil {
		return err
	}
	if ls, ok := h.(interface{ SetLevel(slog.Level) }); ok {
		ls.SetLevel(lvl)
	}

	format := strings.ToLower(c.GetString("logging.format", "text"))
	if fs, ok := h.(interface{ SetFormat(string) error }); ok {
		if err := fs.SetFormat(format); err != nil {
			return err
		}
	}

	if ts, ok := h.(interface{ SetDisableTimestamp(bool) }); ok {
		ts.SetDisableTimestamp(c.GetBool("logging.disable_timestamp", false))
	}
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
		// Accepted for backwards compatibility with older configs. slog has
		// no fatal or panic level; both map to error.
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
