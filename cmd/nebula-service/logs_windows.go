package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/kardianos/service"
	"github.com/slackhq/nebula"
)

// HookLogger routes every log record through the service logger so that
// output ends up in the Windows Event Viewer. configLogger-driven level
// changes continue to take effect via the shared LevelVar, but format and
// timestamp config is ignored since the service logger receives pre-built
// lines.
func HookLogger(l *slog.Logger) {
	rh, ok := nebula.HandlerOf(l)
	if !ok {
		return
	}
	rh.ReplaceInner(&serviceHandler{sl: logger})
}

// serviceHandler formats each record into a simple "msg key=value" line and
// forwards it to the Windows service logger at the appropriate severity.
type serviceHandler struct {
	sl     service.Logger
	attrs  []slog.Attr
	prefix string
}

func (sh *serviceHandler) Enabled(_ context.Context, _ slog.Level) bool {
	// The outer ReconfigurableHandler gates on the shared LevelVar; by the
	// time a record reaches us, it is already admitted.
	return true
}

func (sh *serviceHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	if sh.prefix != "" {
		sb.WriteString(sh.prefix)
		sb.WriteString(" ")
	}
	sb.WriteString(r.Message)
	for _, a := range sh.attrs {
		writeAttr(&sb, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&sb, a)
		return true
	})
	line := sb.String()
	switch {
	case r.Level >= slog.LevelError:
		return sh.sl.Error(line)
	case r.Level >= slog.LevelWarn:
		return sh.sl.Warning(line)
	default:
		return sh.sl.Info(line)
	}
}

func (sh *serviceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(sh.attrs)+len(attrs))
	merged = append(merged, sh.attrs...)
	merged = append(merged, attrs...)
	return &serviceHandler{sl: sh.sl, attrs: merged, prefix: sh.prefix}
}

func (sh *serviceHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return sh
	}
	prefix := sh.prefix
	if prefix != "" {
		prefix += "."
	}
	prefix += name
	return &serviceHandler{sl: sh.sl, attrs: sh.attrs, prefix: prefix}
}

func writeAttr(sb *strings.Builder, a slog.Attr) {
	sb.WriteString(" ")
	sb.WriteString(a.Key)
	sb.WriteString("=")
	fmt.Fprintf(sb, "%v", a.Value.Resolve().Any())
}
