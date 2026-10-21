package localapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
)

// Endpoints holds all local endpoints.
type Endpoints struct {
	Control *Server
	Info    *InfoServer
}

// Stop closes both endpoints and removes their sockets.
func (e *Endpoints) Stop() {
	e.Info.Stop()
	e.Control.Stop()
}

// Wire brings up the local APIs for a running nebula: WireControl with reg and WireInfo
// with info, which are what the two sockets each need. The daemon entry points want
// both, so this is one call and one Stop for them; an embedder that wants one socket
// alone calls that one's function.
//
// Every entry point that runs nebula as a daemon calls this, so the endpoints behave the
// same whether nebula was started from a shell or by a service manager. It deliberately
// does not live in nebula.Main: the control socket is on by default, so an embedder
// inside an app sandbox would have to know to turn off a socket it cannot use. Wiring it
// at the daemon entry points means embedders get the command registry and no listener.
//
// Call it after Control.Start, so the listeners only exist once the interface is up.
func Wire(ctx context.Context, l *slog.Logger, c *config.C, reg *commands.Registry, info http.Handler) *Endpoints {
	return &Endpoints{
		Control: WireControl(ctx, l, c, reg),
		Info:    WireInfo(ctx, l, c, info),
	}
}

// WireControl brings up the control socket, serving reg, and keeps it following the
// config across reloads: pointed at the configured path, or down when the config turns
// it off.
//
// Every failure below is a warning, bar one. Nebula is expected to keep forwarding
// packets whether or not anyone can reach it; but a name that another process holds is
// not a misconfiguration, it is a process that will be answering nebula ctl in the
// daemon's place, and that is logged as an error.
func WireControl(ctx context.Context, l *slog.Logger, c *config.C, reg *commands.Registry) *Server {
	return wireControl(ctx, l.With("subsystem", "localapi"), c, reg)
}

// WireInfo brings up the info API when the config asks for one, serving h, the daemon's
// handler for it (Control.InfoHandler), and keeps it following the config across
// reloads: enabling it, disabling it, moving its socket and changing its mode.
func WireInfo(ctx context.Context, l *slog.Logger, c *config.C, h http.Handler) *InfoServer {
	return wireInfo(ctx, l.With("subsystem", "localapi"), c, h)
}

// sharedSocketPath reports the path the config gives to both the control socket and the
// info API, when it gives them one path. The two speak different protocols, so neither
// binds it: each side says so and leaves it, and the operator fixes the config. The
// configured paths are compared, not the ones being served, so the case is caught on
// whichever side reconciles first, when the other side's bind has failed, and when a
// reload moves one socket onto the other's path.
func sharedSocketPath(c *config.C) (string, bool) {
	if !ControlEnabled(c) {
		return "", false
	}

	ctl, err := SocketPathFromConfig(c)
	if err != nil {
		return "", false
	}

	info, err := infoConfigFrom(c)
	if err != nil || !info.Enabled || !samePath(info.Path, ctl) {
		return "", false
	}

	return ctl, true
}

// wireControl brings up the control socket and keeps it pointed at the configured path.
func wireControl(ctx context.Context, l *slog.Logger, c *config.C, reg *commands.Registry) *Server {
	srv := NewServer(l, reg)

	// Registered before the first attempt, so that a path or bind that is bad at startup
	// can be fixed with a config edit and a reload, the same as one that goes bad later,
	// and so that a HUP landing in between is harmless: Rebind on a server already at
	// the path is a no-op.
	reconcile := controlReconciler(ctx, l, c, srv)
	reconcile(c)
	if !ControlEnabled(c) {
		l.Info("Local control socket is disabled", "key", CtlEnabledKey)
	}
	return srv
}

// controlReconciler returns the function that brings the control socket into the state
// the config asks for, and registers it to run on every reload. Every reload is
// reconciled, not only one that changes a key: Rebind with nothing changed is a no-op,
// and a bind that failed for a reason outside the config, a runtime directory not there
// yet, say, is then retried without an edit to the config.
func controlReconciler(ctx context.Context, l *slog.Logger, c *config.C, srv *Server) func(*config.C) {
	reconcile := func(c *config.C) {
		if !ControlEnabled(c) {
			if srv.Path() != "" {
				srv.Stop()
				l.Info("Stopped the local control socket, it is disabled in the reloaded config")
			}
			return
		}

		want, err := SocketPathFromConfig(c)
		if err != nil {
			warnUnusable(l, "local control socket", srv.Path(), err)
			return
		}

		acc, err := controlAccessFrom(c)
		if err != nil {
			warnUnusable(l, "local control socket", srv.Path(), err)
			return
		}

		if p, shared := sharedSocketPath(c); shared {
			l.Warn("Local control socket is configured on the info API's socket path and will not bind it",
				"path", p, "current", srv.Path(), "fix", "set "+InfoSocketKey+" to another path")
			return
		}

		old := srv.Path()
		err = srv.Rebind(ctx, want, acc)
		reportRebind(l, "local control socket", old, want, err, srv.Path())
	}

	onReload(l, c, "local control socket", reconcile)
	return reconcile
}

// onReload registers fn to run on every reload. The callback recovers from its own
// panics rather than relying on the config package, whose callback loop has no isolation
// of its own: a panic there would take the daemon down and skip every callback queued
// behind this one.
func onReload(l *slog.Logger, c *config.C, what string, fn func(*config.C)) {
	c.RegisterReloadCallback(func(c *config.C, _ *config.Reload) {
		defer func() {
			if r := recover(); r != nil {
				l.Error("Recovered from panic reloading the "+what, "panic", r)
			}
		}()
		fn(c)
	})
}

// warnUnusable logs a config the endpoint cannot follow: with nothing serving, the
// endpoint is not available; with something serving, it is kept as it is.
func warnUnusable(l *slog.Logger, what, current string, err error) {
	if current == "" {
		l.Warn("The "+what+" is not available, its config is unusable", "error", err)
		return
	}
	l.Warn("Ignoring unusable "+what+" config from the reload, keeping the current endpoint", "error", err, "current", current)
}

// reportRebind logs what a Rebind did beyond the listening line the bind itself writes:
// nothing for an endpoint left where it was, a move with both paths, and a failure with
// what the operator is left with. old is the path served before the call, "" for none,
// want the one asked for, and now the path served after it, which after a failed move
// is still old.
//
// Nearly every failure is the operator's environment, a missing runtime directory or a
// bad path, and a warning; a name held by another process is an error, since nothing
// else will say that something is sitting where the daemon should be.
func reportRebind(l *slog.Logger, what, old, want string, err error, now string) {
	level := l.Warn
	if errors.Is(err, errEndpointHeld) {
		level = l.Error
	}

	switch {
	case err == nil:
		if old != "" && !samePath(old, want) {
			l.Info("Moved the "+what, "from", old, "to", want)
		}
	case old == "":
		level("Could not start the "+what+", it will not be available until a reload binds it", "error", err, "path", want)
	default:
		level("Could not bind the "+what+" at the requested path", "error", err, "requested", want, "serving", now)
	}
}

// wireInfo brings up the info API when the config asks for one and follows the config
// across reloads: enabling it, disabling it, moving its socket and changing its mode.
//
// Every reload is reconciled, as the control socket's is; see controlReconciler. A
// section that does not parse keeps whatever is running: the operator is told, and the
// programs relying on the endpoint are not cut off by a typo.
func wireInfo(ctx context.Context, l *slog.Logger, c *config.C, h http.Handler) *InfoServer {
	srv := NewInfoServer(l, h)

	reconcile := func(c *config.C) {
		cfg, err := infoConfigFrom(c)
		if err != nil {
			warnUnusable(l, "local info API", srv.Path(), err)
			return
		}

		if !cfg.Enabled {
			if srv.Path() != "" {
				srv.Stop()
				l.Info("Stopped the local info API, it is disabled in the reloaded config")
			}
			return
		}

		// The two endpoints speak different protocols; one socket cannot be both. Caught
		// here, from the configured paths, because listen's own answer, that the socket is
		// in use by another nebula, would send the operator looking for a second process.
		if p, shared := sharedSocketPath(c); shared {
			if cur := srv.Path(); cur != "" {
				l.Warn("Ignoring the local info API's new socket path, it is also the control socket's; keeping the current endpoint",
					"path", p, "current", cur, "fix", "set "+InfoSocketKey+" to another path")
			} else {
				l.Warn("Local info API is not available, its socket path is also the control socket's", "path", p, "fix", "set "+InfoSocketKey+" to another path")
			}
			return
		}

		old := srv.Path()
		err = srv.Rebind(ctx, cfg.Path, cfg.Access)
		reportRebind(l, "local info API", old, cfg.Path, err, srv.Path())
	}

	// Registered before the first attempt, as the control socket's is; see wireControl.
	onReload(l, c, "local info API", reconcile)
	reconcile(c)
	return srv
}

// errEndpointHeld is returned by listen when the endpoint's name is already held by
// some other process, which nebula will not serve alongside: whoever holds it would be
// answering the endpoint's clients. It is only raised on windows, where the default
// name can be held by another administrator's process and an override outside the
// protected namespace by any account's; on unix a path that is still being served is an
// earlier nebula, which clearStale reports as in use. The log line that carries it names
// the endpoint, so the sentence does not.
var errEndpointHeld = errors.New("the pipe's name is held by another process")
