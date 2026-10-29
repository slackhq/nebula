package config

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
)

// ReloadResult describes how a reload went. Problems are logged where they happen, Log writes a one line summary.
type ReloadResult struct {
	// Err is set when the new config could not be read or parsed, no callbacks ran
	Err error
	// Failed is true when a callback could not apply part of the new config
	Failed bool
	// RestartRequired is true once any reload has needed a restart, and stays true until the process restarts
	RestartRequired bool
	// RestartKeys are the keys this reload changed that only apply on a restart
	RestartKeys []string
}

// Summary returns a one line summary of the reload and the level to log it at.
func (r ReloadResult) Summary() (slog.Level, string) {
	switch {
	case r.Err != nil && r.RestartRequired:
		return slog.LevelError, "Config reload failed, the new config did not load and a restart is still required"
	case r.Err != nil:
		return slog.LevelError, "Config reload failed, the new config did not load"
	case r.Failed && r.RestartRequired:
		return slog.LevelError, "Config reload completed with errors and requires a restart to fully apply, review the logs"
	case r.Failed:
		return slog.LevelError, "Config reload completed with errors, review the logs"
	case r.RestartRequired:
		return slog.LevelWarn, "Config reload was completed but requires a restart to fully apply"
	default:
		return slog.LevelInfo, "Config reload complete"
	}
}

// String is the summary with Err and RestartKeys included, for output other than the log.
func (r ReloadResult) String() string {
	_, msg := r.Summary()
	if r.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, r.Err)
	}
	if len(r.RestartKeys) > 0 {
		msg = fmt.Sprintf("%s, keys %v", msg, r.RestartKeys)
	}
	return msg
}

// Log writes Summary to l.
func (r ReloadResult) Log(l *slog.Logger) {
	level, msg := r.Summary()
	if len(r.RestartKeys) > 0 {
		l.Log(context.Background(), level, msg, "keys", r.RestartKeys)
		return
	}
	l.Log(context.Background(), level, msg)
}

// Reload is passed to each reload callback to report how applying the new config went.
type Reload struct {
	c       *C
	failed  bool
	restart bool
	// Changed keys that only apply on a restart, from every callback
	keys []string
}

// Failed marks the reload as failed, the caller logs why. Safe to call on a nil Reload, which is what the initial load
// passes.
func (r *Reload) Failed() {
	if r != nil {
		r.failed = true
	}
}

// RestartRequired marks the reload as needing a restart, the caller logs why. Safe to call on a nil Reload.
func (r *Reload) RestartRequired() {
	if r != nil {
		r.restart = true
	}
}

// RestartRequiredIfChanged marks the reload as needing a restart if any of keys changed, and adds them to RestartKeys.
// Use it for keys that are only read at startup. Safe to call on a nil Reload.
func (r *Reload) RestartRequiredIfChanged(keys ...string) {
	if r == nil {
		return
	}
	for _, k := range keys {
		if r.c.HasChanged(k) && !slices.Contains(r.keys, k) {
			r.keys = append(r.keys, k)
			r.restart = true
		}
	}
}
