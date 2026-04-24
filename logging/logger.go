// Package logging wires the nebula runtime-reconfigurable slog handler used
// by nebula.Main and the nebula CLI binaries. Callers build a logger with
// NewLogger, then call ApplyConfig at startup and from a config reload
// callback to push logging.level, logging.format, and
// logging.disable_timestamp changes onto the logger without rebuilding it.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"
)

// Config is the subset of *config.C that ApplyConfig reads. Declaring it
// here keeps the logging package from depending on config directly, which
// would cycle through the shared test helpers (test.NewLogger imports
// logging, and config's tests import test). *config.C satisfies this
// interface structurally with no adapter.
type Config interface {
	GetString(key, def string) string
	GetBool(key string, def bool) bool
}

// LevelTrace is a custom slog level below Debug, used when logging.level is
// "trace". slog has no builtin trace level; the value is one step below
// slog.LevelDebug in slog's 4-point spacing.
const LevelTrace = slog.Level(-8)

// NewLogger returns a *slog.Logger whose level, format, and timestamp
// emission can be reconfigured at runtime via ApplyConfig and the SSH debug
// commands. The default configuration is info-level text output so log
// calls made before ApplyConfig runs still produce output. Timestamps
// follow slog's default RFC3339Nano format; set logging.disable_timestamp
// in config to suppress them.
//
// ApplyConfig and the SSH commands discover the reconfig surface via
// structural type-assertion on l.Handler(), so replacement implementations
// (tests, platform-specific sinks) need only implement the subset of
// {SetLevel(slog.Level), SetFormat(string) error, SetDisableTimestamp(bool)}
// they care about. Callers that pass a plain *slog.Logger without these
// methods get a silent no-op; reconfiguration is always opt-in.
func NewLogger(w io.Writer) *slog.Logger {
	return slog.New(NewHandler(w))
}

// NewHandler builds the *Handler that NewLogger wraps. Exported for
// platform-specific sinks (notably cmd/nebula-service/logs_windows.go)
// that want to wrap the handler with extra behavior, such as tagging each
// record with its Event Log severity, while still benefiting from all the
// level / format / timestamp / WithAttrs machinery implemented here.
func NewHandler(w io.Writer) *Handler {
	root := &handlerRoot{}
	root.level.Set(slog.LevelInfo)
	opts := &slog.HandlerOptions{Level: &root.level}
	return &Handler{
		root: root,
		text: slog.NewTextHandler(w, opts),
		json: slog.NewJSONHandler(w, opts),
	}
}

// handlerRoot carries the reconfiguration state shared by every logger
// derived from a NewHandler call. All fields are consulted on the log
// path and updated lock-free.
type handlerRoot struct {
	level            slog.LevelVar
	disableTimestamp atomic.Bool
	// jsonMode picks which of the pre-derived inner handlers Handler.Handle
	// dispatches to. Flipping it propagates instantly to every derived logger
	// without rebuilding or chain-replaying anything.
	jsonMode atomic.Bool
}

// Handler is the slog.Handler returned by NewHandler. It holds two
// pre-derived slog handlers -- one text, one json -- both built from the
// same accumulated WithAttrs/WithGroup state. Handle picks which one to
// dispatch to based on handlerRoot.jsonMode, so a SetFormat call takes
// effect immediately across the whole process without having to rebuild
// any derived loggers.
type Handler struct {
	root *handlerRoot
	text slog.Handler
	json slog.Handler
}

func (h *Handler) Enabled(_ context.Context, l slog.Level) bool {
	return h.root.level.Level() <= l
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.root.disableTimestamp.Load() {
		r.Time = time.Time{}
	}
	if h.root.jsonMode.Load() {
		return h.json.Handle(ctx, r)
	}
	return h.text.Handle(ctx, r)
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return &Handler{
		root: h.root,
		text: h.text.WithAttrs(attrs),
		json: h.json.WithAttrs(attrs),
	}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &Handler{
		root: h.root,
		text: h.text.WithGroup(name),
		json: h.json.WithGroup(name),
	}
}

// SetLevel updates the effective log level. Propagates to every derived
// logger via the shared LevelVar.
func (h *Handler) SetLevel(level slog.Level) { h.root.level.Set(level) }

// GetLevel reports the current log level.
func (h *Handler) GetLevel() slog.Level { return h.root.level.Level() }

// SetFormat flips the output format atomically. Valid formats are "text"
// and "json". Every derived logger sees the new format on its next Handle
// call; no rebuild or registration is required.
func (h *Handler) SetFormat(format string) error {
	switch format {
	case "text":
		h.root.jsonMode.Store(false)
	case "json":
		h.root.jsonMode.Store(true)
	default:
		return fmt.Errorf("unknown log format `%s`. possible formats: %s", format, []string{"text", "json"})
	}
	return nil
}

// GetFormat reports the currently selected format name.
func (h *Handler) GetFormat() string {
	if h.root.jsonMode.Load() {
		return "json"
	}
	return "text"
}

// SetDisableTimestamp toggles whether Handle zeroes r.Time before
// dispatching (slog's builtin text/json handlers skip emitting the time
// attribute on a zero time).
func (h *Handler) SetDisableTimestamp(v bool) { h.root.disableTimestamp.Store(v) }

// ApplyConfig reads logging.level, logging.format, and (optionally)
// logging.disable_timestamp from c and applies them to l. The reconfig
// surface is discovered via structural type-assertion on l.Handler(), so
// foreign handlers silently opt out of whichever capabilities they do not
// implement.
//
// nebula.Main does NOT call this function on your behalf; callers that want
// config-driven log level / format / timestamp updates invoke it at
// startup and register it as a reload callback themselves. This keeps the
// library from mutating an embedder's logger without their say-so.
func ApplyConfig(l *slog.Logger, c Config) error {
	h := l.Handler()

	lvl, err := ParseLevel(strings.ToLower(c.GetString("logging.level", "info")))
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

// ParseLevel converts a config-string level name ("trace", "debug", "info",
// "warn"/"warning", "error", "fatal"/"panic") to a slog.Level. "fatal" and
// "panic" are accepted for backwards compatibility with pre-slog configs
// and both map to slog.LevelError.
func ParseLevel(s string) (slog.Level, error) {
	switch s {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	case "fatal", "panic":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("not a valid logging level: %q", s)
	}
}

// LevelName returns a human-readable name for a slog.Level matching the
// strings accepted by ParseLevel.
func LevelName(l slog.Level) string {
	switch {
	case l <= LevelTrace:
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
