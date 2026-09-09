package nebula

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"sync"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/diag"
	"github.com/slackhq/nebula/util"
)

// ctlConfig is the parsed form of the `ctl` config block. It is comparable so that a reload
// can tell "nothing changed" from "the socket moved" with ==.
type ctlConfig struct {
	enabled bool
	socket  string

	// explicit records that the operator named a socket path rather than taking the platform
	// default. It only affects how loudly a failure to listen is reported: an unprivileged
	// nebula that cannot create /run/nebula is a normal deployment, not a problem to shout
	// about on every upgrade, but a path someone chose deliberately failing to bind is.
	explicit bool
}

// ctlServer owns the unix socket `nebula ctl` connects to. It exposes the same command
// registry the ssh console does, minus the ceremony of running an ssh server: the socket is
// local only and guarded by filesystem permissions, so it needs no keys.
//
// The lifecycle mirrors statsServer: the constructor wires the reload callback, reload
// records config and reconciles a running listener, Start builds and serves the runtime, and
// Stop tears it down.
type ctlServer struct {
	l   *slog.Logger
	ctx context.Context
	srv *diag.Server

	runMu  sync.Mutex
	runCfg *ctlConfig
	run    *ctlRuntime
}

// ctlRuntime is the live state owned by a single Start invocation.
type ctlRuntime struct {
	cancel   context.CancelFunc
	listener net.Listener
}

// newCtlServerFromConfig builds a ctlServer, parses the config, and registers a reload
// callback. It deliberately does not start listening: there is no interface yet, and
// Control.Start is what launches the first runtime. The callback is registered before the
// config is parsed so a SIGHUP can fix a bad block even if the first parse failed.
//
// reg is only held, never read, until Start runs. That is what lets this be constructed
// before attachCommands has populated the registry.
func newCtlServerFromConfig(ctx context.Context, l *slog.Logger, c *config.C, reg *diag.Registry) (*ctlServer, error) {
	s := &ctlServer{
		l:   l,
		ctx: ctx,
		srv: diag.NewServer(l, reg),
	}

	c.RegisterReloadCallback(func(c *config.C) {
		if err := s.reload(c, false); err != nil {
			s.l.Error("Failed to reload ctl from config", "error", err)
		}
	})

	if err := s.reload(c, true); err != nil {
		return s, err
	}

	return s, nil
}

// loadCtlConfig parses and validates the `ctl` block. An empty socket path while enabled is
// not an error: it means the platform has no default and the operator did not name one, so
// there is simply nothing to listen on.
func loadCtlConfig(c *config.C) (ctlConfig, error) {
	cfg := ctlConfig{
		enabled:  c.GetBool("ctl.enabled", true),
		socket:   c.GetString("ctl.socket", diag.DefaultSocketPath()),
		explicit: c.IsSet("ctl.socket"),
	}

	if cfg.enabled && cfg.socket != "" && !filepath.IsAbs(cfg.socket) {
		return cfg, util.NewContextualError("ctl.socket must be an absolute path", m{"path": cfg.socket}, nil)
	}

	return cfg, nil
}

// reload parses the config and records it, then reconciles the running listener against it:
//
//   - newly enabled -> spawn Start
//   - newly disabled -> Stop the runtime
//   - socket moved (still enabled) -> Stop the old, Start the new
//   - no change -> no-op
//
// On the initial call it only records configuration; Control.Start is what launches the first
// runtime via ctlStart. There is no interface to serve yet at that point.
func (s *ctlServer) reload(c *config.C, initial bool) error {
	newCfg, err := loadCtlConfig(c)
	if err != nil {
		return err
	}

	s.runMu.Lock()
	sameCfg := s.runCfg != nil && *s.runCfg == newCfg
	s.runCfg = &newCfg
	running := s.run != nil
	s.runMu.Unlock()

	if initial || sameCfg {
		return nil
	}

	if running {
		s.Stop()
	}

	if newCfg.enabled && newCfg.socket != "" {
		go s.Start()
	}

	return nil
}

// Start binds the socket and serves until Stop is called or ctx fires. Safe to call when ctl
// is disabled or already running: both no-op.
func (s *ctlServer) Start() {
	s.runMu.Lock()
	if s.ctx.Err() != nil || s.run != nil || s.runCfg == nil {
		s.runMu.Unlock()
		return
	}
	cfg := *s.runCfg
	s.runMu.Unlock()

	if !cfg.enabled || cfg.socket == "" {
		if cfg.enabled {
			s.l.Info("ctl has no socket path on this platform, `nebula ctl` will not be available",
				"hint", "set ctl.socket to enable it",
			)
		}
		return
	}

	listener, err := diag.Listen(cfg.socket)
	if err != nil {
		// A default path nebula cannot create is an ordinary state for an unprivileged
		// install; a path the operator chose failing to bind is something they want to know
		// about. Either way ctl is optional and nebula carries on without it.
		if cfg.explicit {
			s.l.Error("Failed to listen on the ctl socket", "ctlSocket", cfg.socket, "error", err)
		} else {
			s.l.Info("Not serving the ctl socket, `nebula ctl` will not be available",
				"ctlSocket", cfg.socket,
				"error", err,
				"hint", "set ctl.socket to a path nebula can write, or ctl.enabled to false",
			)
		}

		// Drop the cached config so a SIGHUP retries once the underlying problem is fixed,
		// even when the config itself is unchanged.
		s.runMu.Lock()
		if s.runCfg != nil && *s.runCfg == cfg {
			s.runCfg = nil
		}
		s.runMu.Unlock()
		return
	}

	runCtx, cancel := context.WithCancel(s.ctx)
	rt := &ctlRuntime{cancel: cancel, listener: listener}

	s.runMu.Lock()
	// Losing the race against a Stop or a competing Start means this listener is already
	// obsolete. Close it rather than serving a socket nobody will tear down.
	if s.ctx.Err() != nil || s.run != nil {
		s.runMu.Unlock()
		cancel()
		_ = listener.Close()
		return
	}
	s.run = rt
	s.runMu.Unlock()

	s.l.Info("ctl socket is listening", "ctlSocket", cfg.socket)

	err = s.srv.Serve(runCtx, listener)
	if err != nil {
		s.l.Error("The ctl listener stopped", "ctlSocket", cfg.socket, "error", err)
	}

	// Clear our runtime only if nothing has replaced it.
	s.runMu.Lock()
	if s.run == rt {
		rt.cancel()
		s.run = nil
		if err != nil {
			// An unclean exit leaves runCfg cached as if it were applied, so drop it and let a
			// SIGHUP retry.
			s.runCfg = nil
		}
	}
	s.runMu.Unlock()
}

// Stop closes the listener and unlinks the socket. It deliberately does not touch connections
// that are already being served: `nebula ctl reload` runs every reload callback inline on its
// own connection, including this one, and hanging up on it would truncate the response to a
// reload that actually succeeded.
//
// The socket file is removed by net.UnixListener's unlink-on-close, so there is no os.Remove
// here; doing it by hand would delete a successor's socket after a fast reload.
func (s *ctlServer) Stop() {
	s.runMu.Lock()
	rt := s.run
	s.run = nil
	s.runMu.Unlock()

	if rt == nil {
		return
	}

	rt.cancel()
	if err := rt.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.l.Warn("Failed to close the ctl listener", "error", err)
	}
}
