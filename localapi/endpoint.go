package localapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
)

// endpoint is the lifecycle the two local APIs share: one socket at a path, bound and
// given up under a mutex, moved by binding the new path before the old one is released,
// and stopped when the context that brought it up ends. What is served on the socket,
// and by what, is the embedding server's: it hands rebindLocked a serve function and
// gets back the thing to close.
type endpoint struct {
	l *slog.Logger

	// name is what the endpoint is called in its own log lines and errors, so the two
	// read apart.
	name string

	mu sync.Mutex

	// closer stops the serving when closed: the listener itself, or the server that owns
	// it. It is nil while the endpoint is stopped, which is what stopped means here.
	closer  io.Closer
	path    string
	mode    os.FileMode
	unwatch func() bool
}

// Path returns the socket path currently being served, or "" when stopped.
func (e *endpoint) Path() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.path
}

// rebindLocked brings the endpoint up at path with mode, moves it there, or, when it is
// already there, applies a changed mode. It is the one place a socket is installed and
// the one way an endpoint comes up, so Wire's first attempt and its reload callback are
// the same call, and an endpoint already at path is left as it is: Wire registers the
// callback before the first attempt, so a HUP that lands between the two has the
// callback do the first bind, and the first attempt then finds the socket it was about
// to create already up.
//
// The new socket is bound before the old one is given up: a bad path in a reloaded
// config leaves the operator with the endpoint they already had rather than none. serve
// is handed the new listener once it is certain to be kept and returns what to close to
// stop serving it; what becomes of the old socket's connections is that closer's.
//
// The caller holds e.mu for the whole operation, bind included. Releasing it around
// listen would let a Stop land in between, and this would then install a fresh socket on
// an endpoint that had just shut down, leaving a live socket on disk until the process
// exits. listen does not take e.mu, so holding it costs the other methods one bind's
// wait, at most the stale socket probe, once per reload.
func (e *endpoint) rebindLocked(ctx context.Context, path string, mode os.FileMode, serve func(net.Listener) io.Closer) error {
	if e.closer != nil && e.path == path {
		if e.mode == mode {
			return nil
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("could not change the mode of %s: %w", path, err)
		}
		e.mode = mode
		e.l.Info("Changed the "+e.name+"'s socket mode", "path", path, "mode", modeString(mode))
		return nil
	}

	ln, err := listen(path, mode)
	if err != nil {
		return err
	}

	// A reload that arrives during shutdown must not bring the endpoint back. Stop is
	// not terminal (a Rebind after Stop is allowed, and is how an endpoint whose first
	// bind failed comes up), so whether it is running is no guide; the context is what
	// shutdown cancels, and it is checked here, while nothing else can change the state.
	if err := ctx.Err(); err != nil {
		release(ln, path)
		return fmt.Errorf("not starting the %s, nebula is shutting down: %w", e.name, err)
	}

	old, oldPath := e.closer, e.path
	e.closer = serve(ln)
	e.path = path
	e.mode = mode
	e.watchLocked(ctx)

	// Stop serving the old socket. oldPath differs from path whenever old is set: an
	// endpoint already on the same path returned above.
	if old != nil {
		release(old, oldPath)
	}

	return nil
}

// watchLocked stops the endpoint when ctx is cancelled. One watcher covers a run of the
// endpoint, from the first bind that succeeds until Stop: a daemon whose initial listen
// failed and which later Rebinds onto a good path from a reloaded config still needs its
// socket removed on shutdown, and a Rebind on a running endpoint must not stack a second
// watcher on the same ctx. Stop detaches the watcher, so an endpoint started again
// afterwards is watched on the ctx that started it, and the ctx of an earlier run no
// longer reaches it whenever that one ends. Callers hold e.mu.
func (e *endpoint) watchLocked(ctx context.Context) {
	if e.unwatch != nil {
		return
	}
	e.unwatch = context.AfterFunc(ctx, e.Stop)
}

// Stop closes the endpoint and removes its socket. Work in flight is the closer's
// business: a listener leaves the connections it already accepted to finish, a server
// cuts them off.
//
// The whole of it runs under e.mu, closer and socket included, so a Rebind cannot land
// between the state change and the close and find a path that is still bound by the
// socket it is replacing.
func (e *endpoint) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closer == nil {
		return
	}

	release(e.closer, e.path)
	e.closer = nil
	e.path = ""
	e.mode = 0

	// Set whenever closer is. When this Stop is the watcher's own, stopping a watcher
	// that has already fired is a no-op.
	e.unwatch()
	e.unwatch = nil
}

// release gives up a socket's closer and the node at its path. The node goes first,
// while the socket is still open: for as long as it is, the node is this endpoint's,
// since a starting daemon's stale check refuses to remove a socket that answers. The
// other order opens a window between the close and the unlink in which a new daemon can
// find the node stale, clear it and bind its own at the same path, which the unlink then
// takes from under it, leaving that daemon serving a socket nothing can reach. listen
// turns off the listener's own unlink on close so this is the only unlink.
func release(c io.Closer, path string) {
	removeSocket(path)
	_ = c.Close()
}
