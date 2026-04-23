package nebula

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/config"
)

// LogLevelTrace is a custom slog level below Debug, used when logging.level
// is "trace". slog has no builtin trace level; the value is one step below
// slog.LevelDebug in slog's 4-point spacing.
const LogLevelTrace = slog.Level(-8)

// NewLogger returns a *slog.Logger whose level, format, and timestamp
// emission can be reconfigured at runtime via configLogger and the SSH
// debug commands. The default configuration is info-level text output so
// log calls made before configLogger runs still produce output. Timestamps
// follow slog's default RFC3339Nano format; set logging.disable_timestamp
// in config to suppress them.
//
// configLogger and the SSH commands discover the reconfig surface via
// structural type-assertion on l.Handler(), so replacement implementations
// (tests, platform-specific sinks) need only implement the subset of
// {SetLevel(slog.Level), SetFormat(string) error, SetDisableTimestamp(bool)}
// they care about. Callers that do not need reconfig can pass a plain
// *slog.Logger to nebula.Main; configLogger becomes a no-op for handlers it
// does not recognize.
func NewLogger(w io.Writer) *slog.Logger {
	root := &handlerRoot{}
	root.level.Set(slog.LevelInfo)
	opts := &slog.HandlerOptions{Level: &root.level}
	return slog.New(&nebulaHandler{
		root: root,
		text: slog.NewTextHandler(w, opts),
		json: slog.NewJSONHandler(w, opts),
	})
}

// handlerRoot carries the reconfiguration state shared by every logger
// derived from a NewLogger call. All fields are consulted on the log path
// and updated lock-free.
type handlerRoot struct {
	level            slog.LevelVar
	disableTimestamp atomic.Bool
	// jsonMode picks which of the pre-derived inner handlers nebulaHandler.Handle
	// dispatches to. Flipping it propagates instantly to every derived logger
	// without rebuilding or chain-replaying anything.
	jsonMode atomic.Bool
}

// nebulaHandler is the slog.Handler returned by NewLogger. It holds two
// pre-derived slog handlers -- one text, one json -- both built from the
// same accumulated WithAttrs/WithGroup state. Handle picks which one to
// dispatch to based on handlerRoot.jsonMode, so a SetFormat call takes
// effect immediately across the whole process without having to rebuild
// any derived loggers.
type nebulaHandler struct {
	root *handlerRoot
	text slog.Handler
	json slog.Handler
}

func (h *nebulaHandler) Enabled(_ context.Context, l slog.Level) bool {
	return h.root.level.Level() <= l
}

func (h *nebulaHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.root.disableTimestamp.Load() {
		r.Time = time.Time{}
	}
	if h.root.jsonMode.Load() {
		return h.json.Handle(ctx, r)
	}
	return h.text.Handle(ctx, r)
}

func (h *nebulaHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return &nebulaHandler{
		root: h.root,
		text: h.text.WithAttrs(attrs),
		json: h.json.WithAttrs(attrs),
	}
}

func (h *nebulaHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &nebulaHandler{
		root: h.root,
		text: h.text.WithGroup(name),
		json: h.json.WithGroup(name),
	}
}

// SetLevel updates the effective log level. Propagates to every derived
// logger via the shared LevelVar.
func (h *nebulaHandler) SetLevel(level slog.Level) { h.root.level.Set(level) }

// GetLevel reports the current log level.
func (h *nebulaHandler) GetLevel() slog.Level { return h.root.level.Level() }

// SetFormat flips the output format atomically. Valid formats are "text"
// and "json". Every derived logger sees the new format on its next Handle
// call; no rebuild or registration is required.
func (h *nebulaHandler) SetFormat(format string) error {
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
func (h *nebulaHandler) GetFormat() string {
	if h.root.jsonMode.Load() {
		return "json"
	}
	return "text"
}

// SetDisableTimestamp toggles whether Handle zeroes r.Time before
// dispatching (slog's builtin text/json handlers skip emitting the time
// attribute on a zero time).
func (h *nebulaHandler) SetDisableTimestamp(v bool) { h.root.disableTimestamp.Store(v) }

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
