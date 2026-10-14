package localapi

import (
	"context"
	"errors"
	"log/slog"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
)

// Endpoints is every local API Wire brought up, with the one Stop the daemon's exit
// path calls.
type Endpoints struct {
	Control *Server
	Info    *InfoServer
}

// Stop closes both endpoints and removes their sockets.
func (e *Endpoints) Stop() {
	e.Info.Stop()
	e.Control.Stop()
}

// Wire brings up the local APIs for a running nebula and keeps them following the
// config across reloads: the control socket, always, and the info API when the config
// asks for it.
//
// Every entry point that runs nebula as a daemon calls this, so the endpoints behave the
// same whether nebula was started from a shell or by a service manager. It deliberately
// does not live in nebula.Main: the control socket is on by default with no key to
// disable it, so an embedder inside an app sandbox would have no way to decline a socket
// it cannot use. Wiring it at the daemon entry points means embedders get the command
// registry and no listener.
//
// Every failure below is a warning, bar one. Nebula is expected to keep forwarding
// packets whether or not anyone can reach it; but a name that another process holds is
// not a misconfiguration, it is a process that will be answering nebula ctl in the
// daemon's place, and that is logged as an error.
//
// Call it after Control.Start, so the listeners only exist once the interface is up.
func Wire(ctx context.Context, l *slog.Logger, c *config.C, reg *commands.Registry, configPath string) *Endpoints {
	l = l.With("subsystem", "localapi")
	ctl := wireControl(ctx, l, c, reg, configPath)
	return &Endpoints{
		Control: ctl,
		Info:    wireInfo(ctx, l, c, reg, configPath, ctl),
	}
}

// wireControl brings up the control socket and keeps it pointed at the configured path.
func wireControl(ctx context.Context, l *slog.Logger, c *config.C, reg *commands.Registry, configPath string) *Server {
	srv := NewServer(l, reg)

	// Registered before the first attempt, so that a path or bind that is bad at startup
	// can be fixed with a config edit and a reload, the same as one that goes bad later,
	// and so that a HUP landing in between is harmless: Rebind on a server already at
	// the path is a no-op.
	reconcile := followControlConfig(ctx, l, c, srv, configPath)
	reconcile(c)
	return srv
}

// followControlConfig registers the reload callback that keeps the socket where
// local_api.control.socket says it is, moving it when the key changes and bringing one
// up while there is none, and returns it for the first attempt to call.
//
// The key is reloadable because the client finds the socket by reading the config: if the
// two could disagree, the file on disk would name a socket that is not there.
//
// Every reload is reconciled rather than gated on the key having changed. Rebind on a
// server already at the path is a no-op, so that costs nothing; and a bind that failed
// for a reason outside the config, a runtime directory that was not there yet, is fixed
// outside the config too, so the reload that follows the fix is a plain one. That holds
// for a move as much as for the first bind: a daemon left on its old path by a move that
// could not bind is one the client, reading the new path from the same file, cannot
// reach, and the operator's fix is the directory and a reload, not an edit to an
// unrelated line to make the key read as changed.
func followControlConfig(ctx context.Context, l *slog.Logger, c *config.C, srv *Server, configPath string) func(*config.C) {
	reconcile := func(c *config.C) {
		want, err := SocketPathFromConfig(c, configPath)
		if err != nil {
			if srv.Path() == "" {
				l.Warn("Could not determine the local control socket path, control commands will not be available", "error", err)
			} else {
				l.Warn("Ignoring unusable local control socket path from reloaded config", "error", err)
			}
			return
		}

		reportRebind(l, "local control socket", srv.Path(), want, srv.Rebind(ctx, want))
	}

	onReload(l, c, "local control socket", reconcile)
	return reconcile
}

// onReload registers fn to run on every reload. The callback recovers from its own
// panics rather than relying on the config package, whose callback loop has no isolation
// of its own: a panic there would take the daemon down and skip every callback queued
// behind this one.
func onReload(l *slog.Logger, c *config.C, what string, fn func(*config.C)) {
	c.RegisterReloadCallback(func(c *config.C) {
		defer func() {
			if r := recover(); r != nil {
				l.Error("Recovered from panic reloading the "+what, "panic", r)
			}
		}()
		fn(c)
	})
}

// reportRebind logs what a Rebind did beyond the listening line the bind itself writes:
// nothing for an endpoint left where it was, a move with both paths, and a failure with
// what the operator is left with. old is the path served before the call, "" for none,
// and want the one asked for.
func reportRebind(l *slog.Logger, what, old, want string, err error) {
	switch {
	case err == nil:
		if old != "" && old != want {
			l.Info("Moved the "+what, "from", old, "to", want)
		}
	case old == "":
		bindFailure(l, err)("Could not start the "+what+", it will not be available until a reload binds it", "error", err, "path", want)
	default:
		bindFailure(l, err)("Could not move the "+what+", keeping the current one",
			"error", err, "current", old, "requested", want,
		)
	}
}

// wireInfo brings up the info API when the config asks for one and follows the config
// across reloads: enabling it, disabling it, moving its socket and changing its mode.
//
// Every reload is reconciled rather than gated on the section having changed. Rebind on
// a server already where the config says is a no-op, so that costs nothing, and a bind
// that failed for a reason outside the config, a runtime directory that was not there
// yet, is retried by the plain reload that follows the fix, the same as the control
// socket's. A section that does not parse keeps whatever is running: the operator is
// told, and the programs relying on the endpoint are not cut off by a typo.
func wireInfo(ctx context.Context, l *slog.Logger, c *config.C, reg *commands.Registry, configPath string, ctl *Server) *InfoServer {
	srv := NewInfoServer(l, reg)

	// Said once per process rather than on every reload: it is a platform limit, not
	// something the next reload could fix.
	saidUnsupported := false

	reconcile := func(c *config.C) {
		cfg, err := infoConfigFrom(c, configPath)
		if err != nil {
			if srv.Path() == "" {
				l.Warn("Local info API is not available, its config is unusable", "error", err)
			} else {
				l.Warn("Ignoring unusable local info API config, keeping the current endpoint", "error", err)
			}
			return
		}

		if !cfg.Enabled {
			if srv.Path() != "" {
				srv.Stop()
				l.Info("Stopped the local info API, it is disabled in the reloaded config")
			}
			return
		}

		if !infoSupported {
			if !saidUnsupported {
				l.Warn("Local info API is enabled in the config but is not served on this platform yet", "key", InfoEnabledKey)
				saidUnsupported = true
			}
			return
		}

		// The two endpoints speak different protocols; one socket cannot be both. Caught
		// here because listen's own answer, that the socket is in use by another nebula,
		// would send the operator looking for a second process.
		if p := ctl.Path(); p != "" && p == cfg.Path {
			l.Warn("Local info API is not available, its socket is the control socket's", "path", p, "fix", "set "+InfoSocketKey+" to another path")
			return
		}

		old := srv.Path()
		reportRebind(l, "local info API", old, cfg.Path, srv.Rebind(ctx, cfg.Path, cfg.Mode))
	}

	// Registered before the first attempt, as the control socket's is; see wireControl.
	onReload(l, c, "local info API", reconcile)
	reconcile(c)
	return srv
}

// errEndpointHeld is returned by listen when the endpoint's name is already held by
// some other process, which nebula will not serve alongside: whoever holds it would be
// answering nebula ctl. It is only raised on windows, where the derived name can be
// held by another administrator's process and an override outside the protected
// namespace by any account's; on unix a path that is still being served is an earlier
// nebula, which clearStale reports as in use.
var errEndpointHeld = errors.New("the local control socket's name is held by another process")

// bindFailure picks the level a failed bind is logged at. Nearly every failure is the
// operator's environment, a missing runtime directory or a bad path, and a warning; a
// name held by another process is logged as an error, since nothing else will say that
// something is sitting where the daemon should be.
func bindFailure(l *slog.Logger, err error) func(msg string, args ...any) {
	if errors.Is(err, errEndpointHeld) {
		return l.Error
	}
	return l.Warn
}
