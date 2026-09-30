package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/slackhq/nebula/commands"
)

const (
	// defaultMaxConns caps concurrent connections. Exceeding it is rejected rather than
	// queued: a queue turns a load problem into a latency problem and hides it.
	defaultMaxConns = 8

	// readTimeout bounds how long a client may take to send its request line.
	readTimeout = 10 * time.Second

	// writeTimeout bounds a single write. A client that stops reading is dropped rather
	// than waited on, so a paused terminal cannot pin daemon resources.
	writeTimeout = 30 * time.Second

	// defaultSlowAfter is how long a command may run before the daemon says so. A
	// command holds a connection slot until it returns, and one that never returns
	// holds it for good; after enough of those the socket answers only "busy". The
	// warning is what tells an operator that from load, and names the command.
	defaultSlowAfter = 30 * time.Second
)

// Server serves the read only portion of a command registry over a local socket.
type Server struct {
	l   *slog.Logger
	src *commands.Registry

	maxConns  int
	slowAfter time.Duration

	mu      sync.Mutex
	ln      net.Listener
	path    string
	running bool
	unwatch func() bool

	sem  chan struct{}
	euid uint32
}

// servedHere decides what this surface will run.
//
// Everything except the profiling commands, which stay on the ssh debug server. Profile
// output is written on the host running nebula, under sshd.sandbox_dir, so a path typed
// here would not mean what the person typing it expects; and the profiling commands are
// one workflow, so splitting them would leave someone able to start a CPU profile in one
// place and stop it only in another.
func servedHere(c *commands.Command) bool {
	return !c.ForProfiling
}

// notServedHere explains a refusal in terms an operator can act on, naming the surface
// that will run the command instead.
const notServedHere = "profiling is driven from the ssh debug server, where the sshd.sandbox_dir " +
	"setting governs where profile output is written on the host running nebula"

// NewServer returns a Server that will serve the commands in reg that this surface
// accepts.
//
// reg is kept rather than filtered here, so a command registered on it after the server
// is built is served too. Filtering happens per request, which is how the ssh server
// treats the same registry, cloning it per session.
func NewServer(l *slog.Logger, reg *commands.Registry) *Server {
	return &Server{
		l:         l,
		src:       reg,
		maxConns:  defaultMaxConns,
		slowAfter: defaultSlowAfter,
		// The same identity the client's owner check is made for, so the peer check
		// cannot disagree with it, and so a test can stand in for it the same way.
		euid: currentUID(),
	}
}

// Rebind brings the server up at path, moves a running server there, and serves it until
// Stop or ctx cancellation. It is the one way the server comes up, so Wire's first
// attempt and its reload callback are the same call, and a server already serving path
// is left as it is: Wire registers the callback before the first attempt, so a HUP that
// lands between the two has the callback do the first bind, and the first attempt then
// finds the socket it was about to create already up.
//
// The new socket is bound before the old one is given up: a bad path in a reloaded
// config leaves the operator with the endpoint they already had rather than none.
//
// s.mu is held for the whole operation, bind included. Releasing it around listen would
// let a Stop land in between, and this would then install a fresh listener on a server
// that had just shut down, leaving a live socket on disk until the process exits. listen
// does not take s.mu, so holding it costs the other methods one bind's wait, at most the
// stale socket probe, once per reload.
//
// An error here is never fatal to the caller: nebula keeps forwarding packets without a
// control endpoint, and the caller is expected to log and carry on.
func (s *Server) Rebind(ctx context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running && s.path == path {
		return nil
	}

	ln, err := listen(path)
	if err != nil {
		return err
	}

	// A reload that arrives during shutdown must not bring the endpoint back. Stop is
	// not terminal (Rebind after Stop is allowed, and is how a server whose first bind
	// failed comes up), so running is no guide; the context is what shutdown cancels,
	// and it is checked here, while nothing else can change the server's state.
	if err := ctx.Err(); err != nil {
		release(ln, path)
		return fmt.Errorf("not starting the local control socket, nebula is shutting down: %w", err)
	}

	oldLn, oldPath := s.ln, s.path
	s.ln = ln
	s.path = path
	s.running = true
	sem := s.semaphore()

	s.watchLocked(ctx)

	// Stop accepting on the old listener. In flight commands keep their connections,
	// which stay usable until they finish. Its accept loop exits on the closed-listener
	// error, so it is gone as soon as this returns. oldPath differs from path whenever
	// oldLn is set: a running server on the same path returned above.
	if oldLn != nil {
		release(oldLn, oldPath)
	}

	logListening(s.l, path)

	go func() {
		s.accept(ln, sem)
	}()

	return nil
}

// watchLocked stops the server when ctx is cancelled. One watcher covers a run of the
// server, from the first bind that succeeds until Stop: a daemon whose initial listen
// failed and which later Rebinds onto a good path from a reloaded config still needs its
// socket removed on shutdown, and a Rebind on a running server must not stack a second
// watcher on the same ctx. Stop detaches the watcher, so a server started again
// afterwards is watched on the ctx that started it, and the ctx of an earlier run no
// longer reaches it whenever that one ends. Callers hold s.mu.
func (s *Server) watchLocked(ctx context.Context) {
	if s.unwatch != nil {
		return
	}
	s.unwatch = context.AfterFunc(ctx, s.Stop)
}

// registry returns the commands this surface serves, filtered from the source at the
// time of the call. It is a few allocations per request, which a control socket that
// sees a request every few seconds at most never notices.
func (s *Server) registry() *commands.Registry {
	return s.src.Filter(servedHere, notServedHere)
}

// Path returns the socket path currently being served, or "" when stopped.
func (s *Server) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// Stop closes the listener and removes the socket. In flight commands are allowed to
// finish; Stop does not wait for them.
//
// The whole of it runs under s.mu, listener and socket included, so a Rebind cannot land
// between the state change and the close and find a path that is still bound by the
// listener it is replacing.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	release(s.ln, s.path)
	s.running = false
	s.ln = nil
	s.path = ""

	// Set whenever running is. When this Stop is the watcher's own, stopping a watcher
	// that has already fired is a no-op.
	s.unwatch()
	s.unwatch = nil
}

// release gives up a listener and the socket node at its path. The node goes first,
// while the listener is still open: for as long as it is, the node is this server's,
// since a starting daemon's stale check refuses to remove a socket that answers. The
// other order opens a window between the close and the unlink in which a new daemon can
// find the node stale, clear it and bind its own at the same path, which the unlink
// then takes from under it, leaving that daemon serving a socket nothing can reach.
// listen turns off the listener's own unlink on close so this is the only unlink.
func release(ln net.Listener, path string) {
	removeSocket(path)
	_ = ln.Close()
}

// semaphore returns the connection limiter, creating it on first use. It is made once
// and never replaced: a handler releases into the channel it acquired from, so swapping
// in a fresh one across a Stop and Start would leave any handler still in flight
// blocked forever on a channel nothing had filled. Callers hold s.mu.
func (s *Server) semaphore() chan struct{} {
	if s.sem == nil {
		s.sem = make(chan struct{}, s.maxConns)
	}
	return s.sem
}

// Accept failures that are not the listener closing are retried after a pause that
// doubles from acceptRetryMin up to acceptRetryMax, the same shape as net/http.Serve.
const (
	acceptRetryMin = 5 * time.Millisecond
	acceptRetryMax = time.Second
)

// accept serves connections from ln until it is closed. sem is the limiter to acquire
// from and release into; it is passed rather than read from s so the handlers spawned
// here never touch s.sem without the lock.
//
// Only a closed listener ends the loop; Stop and Rebind are the two things that close
// it. Every other error is retried: the process being out of descriptors (EMFILE,
// ENFILE) or a client that hung up between the kernel's queue and us (ECONNABORTED)
// are passing conditions, and giving up on them would leave a socket on disk that
// nothing answers, with the reason buried in a log line from minutes or days earlier.
func (s *Server) accept(ln net.Listener, sem chan struct{}) {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}

			if delay == 0 {
				delay = acceptRetryMin
			} else {
				delay = min(delay*2, acceptRetryMax)
			}
			s.l.Warn("Local control socket could not accept a connection, retrying", "error", err, "retry_in", delay)
			time.Sleep(delay)
			continue
		}
		delay = 0

		select {
		case sem <- struct{}{}:
		default:
			// At capacity. Say so and hang up rather than holding the connection open.
			// Logged too: a slot is held for as long as a command runs, and the slow
			// command warning in serve says which ones are still running.
			s.l.Warn("Local control socket is at capacity, refusing a connection", "max", s.maxConns)
			s.reply(conn, &Response{Version: ProtocolVersion, Error: "local control socket is busy, try again"})
			_ = conn.Close()
			continue
		}

		go func() {
			defer func() { <-sem }()
			s.handle(conn)
		}()
	}
}

// handle serves one request. It recovers from panics in command callbacks: this
// surface is present on every install and reachable by any local process running as
// the daemon's user, so a malformed argument must cost a connection rather than the
// overlay.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	var args []string
	defer func() {
		if r := recover(); r != nil {
			s.l.Error("Recovered from panic serving a local control command",
				"panic", r,
				"args", args,
				"stack", string(debug.Stack()),
			)
			s.reply(conn, &Response{Version: ProtocolVersion, Error: "command failed"})
		}
	}()

	// Where the platform can identify the caller, check it. Where it cannot, the
	// endpoint is still protected by the socket's mode or the pipe's security
	// descriptor, which listen() set before serving.
	if peerCheckSupported {
		uid, err := peerUID(conn)
		if err != nil {
			s.l.Warn("Refusing local control connection with unreadable credentials", "error", err)
			return
		}

		// Access is restricted to the user who ran nebula. Root is allowed through
		// because it can reach the daemon's memory regardless of what this check says.
		if uid != s.euid && uid != 0 {
			s.l.Warn("Refusing local control connection from another user", "peerUid", uid)
			s.reply(conn, &Response{Version: ProtocolVersion, Error: "not permitted"})
			return
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

	req, err := readRequest(conn)
	if err != nil {
		s.reply(conn, &Response{Version: ProtocolVersion, Error: err.Error()})
		return
	}
	args = req.Args

	// No deadline while a command runs; the write deadline below is what bounds a client
	// that stops reading.
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))

	s.reply(conn, s.serve(req))
}

// serve runs one request and describes the outcome.
//
// Nothing bounds a command's run; a context would have to reach every Run. What is
// bounded is the silence: a command still running at slowAfter is named in the log, with
// the slot it is holding, so a socket that has gone "busy" can be traced to the commands
// that wedged it. The timer is stopped however the command ends, a panic included, so
// the line is only ever written about a command that is still running.
func (s *Server) serve(req *Request) *Response {
	slow := time.AfterFunc(s.slowAfter, func() {
		s.l.Warn("Local control command is still running and holding a connection slot",
			"command", req.Command,
			"args", req.Args,
			"after", s.slowAfter,
			"max", s.maxConns,
		)
	})
	defer slow.Stop()

	res := &Response{Version: ProtocolVersion}

	if req.Describe {
		schema, err := json.Marshal(s.registry().Schema())
		if err != nil {
			res.Error = err.Error()
			return res
		}

		res.Result = schema
		return res
	}

	if req.Command == "" {
		res.Error = "no command given"
		return res
	}

	params, err := stringParams(req.Params)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	cmd, err := s.registry().Resolve(commands.Name(req.Command))
	if err != nil {
		s.l.Debug("Local control command refused", "command", req.Command, "error", err)
		res.Error = err.Error()
		return res
	}

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}

	// A command that failed may have explained itself on its error stream; if it did
	// not, the returned error is the explanation.
	if err := commands.Invoke(commands.Request{Command: cmd, Params: params, Args: req.Args}, commands.NewSplitStringWriter(out, errOut)); err != nil {
		s.l.Debug("Local control command failed", "command", req.Command, "error", err)

		// Whatever the command wrote is the better explanation; the returned error is the
		// fallback for one that failed without saying so.
		if errOut.Len() == 0 {
			res.Error = err.Error()
		}
	}

	if errOut.Len() > 0 {
		res.Error = errOut.String()
	}

	// The command wrote bytes; carry them as a JSON value when they are one.
	res.Result = jsonOrString(out.Bytes())
	return res
}

// reply writes one response frame.
func (s *Server) reply(conn net.Conn, res *Response) {
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := writeFrame(conn, res); err != nil {
		s.l.Debug("Could not send a local control response", "error", err)
	}
}

// stringParams converts JSON's types into the strings flag.Value.Set expects, so a
// caller writes true and 3 rather than "true" and "3".
func stringParams(in map[string]any) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}

	out := make(map[string]string, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case bool:
			out[k] = strconv.FormatBool(t)
		case string:
			out[k] = t
		case float64:
			// encoding/json gives every number as a float64; render whole ones without
			// a decimal point so an int flag accepts them.
			if t != math.Trunc(t) {
				out[k] = strconv.FormatFloat(t, 'f', -1, 64)
				continue
			}

			// A whole float64 can be far outside int64, and Go's conversion of one that is
			// gives an unspecified value rather than an error, so the bounds are checked
			// first. MinInt64 is exactly representable and is in range. MaxInt64 is not:
			// as a float64 it rounds up to 2^63, which is the first value out of range,
			// hence the >= on that side.
			if t < math.MinInt64 || t >= math.MaxInt64 {
				return nil, fmt.Errorf("parameter %q is %s, outside the range of a 64-bit integer",
					k, strconv.FormatFloat(t, 'g', -1, 64))
			}
			out[k] = strconv.FormatInt(int64(t), 10)
		case nil:
			return nil, fmt.Errorf("parameter %q has no value", k)
		default:
			return nil, fmt.Errorf("parameter %q is not a string, number or boolean", k)
		}
	}

	return out, nil
}

func readRequest(conn net.Conn) (*Request, error) {
	req := &Request{}
	if err := readFrame(conn, MaxRequestBytes, "request", req); err != nil {
		return nil, err
	}

	if req.Version != ProtocolVersion {
		return nil, fmt.Errorf(
			"this nebula speaks local control protocol v%d, the client sent v%d; the two binaries are different versions",
			ProtocolVersion, req.Version,
		)
	}

	return req, nil
}
