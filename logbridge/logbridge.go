// Package logbridge provides a slog.Handler that forwards records to a
// logrus.Logger. It lets code migrate to *slog.Logger one subsystem at a
// time while the top-level configuration still produces a *logrus.Logger.
// Once all call sites are on slog the bridge can be deleted and
// configuration can move to a native slog handler.
//
// The bridge observes the slog.Handler contract with two intentional
// deviations, both forced by the shape of logrus:
//
//   - Groups are flattened to dot-joined keys on a logrus.Fields map
//     rather than preserved as nested structures. A call like
//     logger.WithGroup("peer").With("id", 42) emits the field "peer.id",
//     not {"peer": {"id": 42}}. logrus.Fields is map[string]interface{}
//     with no nesting support, so this is as close as the bridge can
//     get. Downstream log consumers that rely on nested structure should
//     be aware.
//
//   - slog.Record.PC (source location) is dropped. Enabling logrus's
//     own caller reporter will attribute lines to this bridge instead
//     of the user's call site; synthesizing a "source" field from r.PC
//     is left to a future iteration.
package logbridge

import (
	"context"
	"log/slog"

	"github.com/sirupsen/logrus"
)

// LevelTrace maps to logrus.TraceLevel. slog has no built-in trace level
// so we define one below slog.LevelDebug. Callers that want trace output
// through the bridge should log at this level.
const LevelTrace = slog.Level(-8)

// FromLogrus returns a *slog.Logger whose handler forwards records to l.
// The returned logger honors l's current level and formatter.
func FromLogrus(l *logrus.Logger) *slog.Logger {
	return slog.New(NewHandler(l))
}

// NewHandler returns a slog.Handler that forwards to l.
func NewHandler(l *logrus.Logger) slog.Handler {
	return &handler{l: l}
}

type handler struct {
	l           *logrus.Logger
	fields      logrus.Fields
	groupPrefix string
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return h.l.IsLevelEnabled(toLogrusLevel(level))
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	fields := make(logrus.Fields, len(h.fields)+r.NumAttrs())
	for k, v := range h.fields {
		fields[k] = v
	}
	r.Attrs(func(a slog.Attr) bool {
		addAttr(fields, h.groupPrefix, a)
		return true
	})

	entry := h.l.WithFields(fields)
	if !r.Time.IsZero() {
		entry = entry.WithTime(r.Time)
	}
	entry.Log(toLogrusLevel(r.Level), r.Message)
	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	newFields := make(logrus.Fields, len(h.fields)+len(attrs))
	for k, v := range h.fields {
		newFields[k] = v
	}
	for _, a := range attrs {
		addAttr(newFields, h.groupPrefix, a)
	}
	return &handler{l: h.l, fields: newFields, groupPrefix: h.groupPrefix}
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &handler{l: h.l, fields: h.fields, groupPrefix: h.groupPrefix + name + "."}
}

// addAttr flattens a slog.Attr into a logrus.Fields map, prefixing keys
// with prefix. Groups are expanded recursively using dot-joined keys
// since logrus fields are flat.
func addAttr(fields logrus.Fields, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		if len(group) == 0 {
			return
		}
		subPrefix := prefix
		if a.Key != "" {
			subPrefix = prefix + a.Key + "."
		}
		for _, sub := range group {
			addAttr(fields, subPrefix, sub)
		}
		return
	}
	// slog.Handler contract: empty-key groups inline their children, but
	// an empty-key non-group attr has no sensible flat representation
	// and is dropped rather than emitted as fields[""].
	if a.Key == "" {
		return
	}
	fields[prefix+a.Key] = a.Value.Any()
}

func toLogrusLevel(l slog.Level) logrus.Level {
	switch {
	case l <= LevelTrace:
		return logrus.TraceLevel
	case l < slog.LevelInfo:
		return logrus.DebugLevel
	case l < slog.LevelWarn:
		return logrus.InfoLevel
	case l < slog.LevelError:
		return logrus.WarnLevel
	default:
		return logrus.ErrorLevel
	}
}
