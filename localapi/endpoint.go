package localapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	access  Access
	unwatch func() bool

	// id identifies the node listen created at path, so a reload can tell whether the
	// socket is still there and Stop whether the node it would unlink is still ours.
	id socketID
}

// socketID identifies a socket's node on the filesystem, by device and inode on unix.
// The zero value is no identity: a platform with no node to identify, or one that could
// not be read, and removeSocket then unlinks without looking.
type socketID struct {
	dev, ino uint64
}

// Path returns the socket path currently being served, or "" when stopped.
func (e *endpoint) Path() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.path
}

// rebindLocked brings the endpoint up at path with acc, moves it there, or, when it is
// already there, applies a changed access; with nothing changed it does nothing, which
// is what lets Wire's first attempt and its reload callback be the same call.
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
func (e *endpoint) rebindLocked(ctx context.Context, path string, acc Access, serve func(net.Listener) io.Closer) error {
	reopening := false
	if e.closer != nil && e.path == path {
		if cur, ok := identifySocket(path); ok && cur == e.id {
			if e.access == acc {
				return nil
			}
			err := applyAccess(path, acc)
			if err == nil {
				e.access = acc
				e.l.Info("Changed the "+e.name+"'s socket access", "path", path, "access", acc.String())
				return nil
			}
			if !errors.Is(err, errReopenForAccess) {
				return fmt.Errorf("could not change the access of %s: %w", path, err)
			}

			// The platform fixes access when the endpoint is created, so it is created
			// again. The name cannot be held twice, so the old one goes first, and a bind
			// that then fails leaves the endpoint down rather than on the old access the
			// operator asked to change; that is reported below.
			reopening = true
			old := e.closer
			e.closer, e.path, e.access, e.id = nil, "", Access{}, socketID{}
			_ = old.Close()
		} else {
			// The node at the path is not the one this endpoint bound: something outside
			// nebula removed it, logind clearing /run/user/<uid> on logout or a unit
			// cleaning a RuntimeDirectory= it shares, or replaced it. The listener is still
			// open and nothing can reach it, so it is given up now and the path is bound
			// afresh below; listen's stale check decides whether whatever is there now may
			// be cleared. Given up first, rather than after a successful bind as a move
			// does, so that a bind that fails leaves the endpoint reported as down, which
			// it is, instead of serving a path nothing can reach.
			e.l.Warn("The "+e.name+"'s socket is no longer at its path, binding it again", "path", path)
			old := e.closer
			e.closer, e.path, e.access, e.id = nil, "", Access{}, socketID{}
			_ = old.Close()
		}
	}

	ln, err := listen(path, acc)
	if err != nil {
		if reopening {
			return fmt.Errorf("the %s was closed to change its access and could not be created again: %w", e.name, err)
		}
		return err
	}
	id, _ := identifySocket(path)

	// A reload that arrives during shutdown must not bring the endpoint back. Stop is
	// not terminal (a Rebind after Stop is allowed, and is how an endpoint whose first
	// bind failed comes up), so whether it is running is no guide; the context is what
	// shutdown cancels, and it is checked here, while nothing else can change the state.
	if err := ctx.Err(); err != nil {
		release(ln, path, id)
		return fmt.Errorf("not starting the %s, nebula is shutting down: %w", e.name, err)
	}

	old, oldPath, oldID := e.closer, e.path, e.id
	e.closer = serve(ln)
	e.path = path
	e.access = acc
	e.id = id
	e.watchLocked(ctx)

	// Stop serving the old socket. When it was on this same path its node is already
	// gone, and the node there now is the new socket's, so only the closer goes.
	if old != nil {
		if oldPath == path {
			_ = old.Close()
		} else {
			release(old, oldPath, oldID)
		}
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

	release(e.closer, e.path, e.id)
	e.closer = nil
	e.path = ""
	e.access = Access{}
	e.id = socketID{}

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
// turns off the listener's own unlink on close so this is the only unlink. id is the
// node listen created, and the only node removeSocket will remove: one that replaced it,
// another daemon's socket bound after ours was taken from under us, is left alone.
func release(c io.Closer, path string, id socketID) {
	removeSocket(path, id)
	_ = c.Close()
}
