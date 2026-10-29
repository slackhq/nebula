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

// endpoint is for managing the lifecycle of local API endpoints.
type endpoint struct {
	l *slog.Logger

	// name is what the endpoint is called in its own log lines and errors, so the two
	// read apart.
	name string

	mu sync.Mutex

	// closer stops the serving when closed: the listener itself, or the server that owns
	// it. It is nil while the endpoint is stopped, which is what stopped means here.
	closer     io.Closer
	path       string
	access     Access
	cancelStop func() bool

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

// rebindLocked brings the endpoint into the state the config asks for: serving at path
// with acc. It works from any starting state, and a failure leaves the endpoint as it
// was. serve starts serving on the new listener and returns what to close to stop. The
// caller must hold e.mu.
func (e *endpoint) rebindLocked(ctx context.Context, path string, acc Access, serve func(net.Listener) io.Closer) error {
	if e.closer != nil && samePath(e.path, path) {
		if cur, ok := identifySocket(path); ok && cur == e.id {
			if !accessChanged(e.access, acc) {
				return nil
			}
			err := applyAccess(path, acc)
			if err == nil {
				e.access = acc
				e.l.Info("Changed the "+e.name+"'s socket access", "path", path, "access", acc.String())
				return nil
			}
			if errors.Is(err, errAccessFixed) {
				if e.access.narrowedBy(acc) {
					// Keeping the endpoint would keep admitting who the config no longer
					// names, so it is stopped instead. A restart serves it as configured; so
					// does a reload once every client has let go of the name.
					e.l.Error("Stopped the "+e.name+", its access cannot be narrowed while it is served; restart nebula to serve it as configured",
						"path", path, "served", e.access.String(), "configured", acc.String())
					e.stopLocked()
					return nil
				}
				e.l.Warn("The "+e.name+"'s access cannot be widened while it is served; restart nebula to apply it",
					"path", path, "serving", e.access.String(), "configured", acc.String())
				return nil
			}
			return fmt.Errorf("could not change the access of %s: %w", path, err)
		} else {
			// The node at path is not the one this endpoint bound: something outside nebula
			// removed or replaced it, logind clearing /run/user/<uid> on logout, say. The old
			// listener is unreachable, so the endpoint is stopped before the path is bound
			// again below. Stopping first, rather than after a successful bind as a move
			// does, means a bind that fails leaves the endpoint reported as down, which it
			// is, rather than as serving a path nothing can reach.
			e.l.Warn("The "+e.name+"'s socket is no longer at its path, binding it again", "path", path)
			e.stopLocked()
		}
	}

	ln, err := listen(path, acc)
	if err != nil {
		return err
	}
	id, _ := identifySocket(path)

	// A reload that arrives during shutdown must not bring the endpoint back. Stop is
	// not terminal (a Rebind after Stop is how an endpoint whose first bind failed
	// comes up).
	if err := ctx.Err(); err != nil {
		release(ln, path, id)
		return fmt.Errorf("not starting the %s, nebula is shutting down: %w", e.name, err)
	}

	old, oldPath, oldID := e.closer, e.path, e.id
	e.closer = serve(ln)
	e.path = path
	e.access = acc
	e.id = id
	e.stopOnCancelLocked(ctx)

	// Stop serving the old socket, which the checks above leave only on another path.
	if old != nil {
		release(old, oldPath, oldID)
	}

	return nil
}

// stopOnCancelLocked arranges for the endpoint to stop when ctx is cancelled. It is
// armed once per run of the endpoint, from a successful bind until Stop, so a Rebind on
// a running endpoint does not arm it twice, and a later run is tied to the ctx that
// started it rather than an earlier one. Callers hold e.mu.
func (e *endpoint) stopOnCancelLocked(ctx context.Context) {
	if e.cancelStop != nil {
		return
	}
	e.cancelStop = context.AfterFunc(ctx, e.Stop)
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
	e.stopLocked()
}

// stopLocked is Stop for a caller that holds e.mu. It leaves the endpoint as a fresh
// one, so the next bind starts a new run.
func (e *endpoint) stopLocked() {
	if e.closer == nil {
		return
	}
	release(e.closer, e.path, e.id)
	e.closer, e.path, e.access, e.id = nil, "", Access{}, socketID{}
	if e.cancelStop != nil {
		e.cancelStop()
		e.cancelStop = nil
	}
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
