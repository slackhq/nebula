package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/slackhq/nebula/config"
	"golang.org/x/net/netutil"
)

// The info API's config keys. It is off until InfoEnabledKey is true and InfoSocketKey
// names a socket; nothing is derived, because the programs that will dial it have to be
// told where it is anyway.
const (
	InfoEnabledKey = "local_api.info.enabled"
	InfoSocketKey  = "local_api.info.socket"
	InfoModeKey    = "local_api.info.socket_mode"
	InfoGroupKey   = "local_api.info.group"
)

const (
	// infoMaxConns bounds the connections held open at once. Beyond it the kernel
	// queues, which is what an HTTP client expects of a busy server; the control socket
	// refuses instead because its clients are people at a prompt.
	infoMaxConns = 64

	infoWriteTimeout   = 30 * time.Second
	infoIdleTimeout    = 60 * time.Second
	infoMaxHeaderBytes = 64 * 1024
)

// The read deadlines are variables so a test can shorten them. infoReadTimeout bounds
// the whole request, not only its headers: a request is a GET with a query string and
// the handlers never read a body, but net/http drains an unread body after the handler
// returns, and without a deadline on that read a client sending a body a byte at a time
// would hold its connection slot for as long as it liked, and sixty-four of them would
// hold every slot. A body is refused as well, see refuseBody, but net/http drains it
// before it closes, so this deadline is what ends a client that announced a body and
// never sent it.
var (
	infoReadHeaderTimeout = 10 * time.Second
	infoReadTimeout       = 15 * time.Second
)

// InfoServer serves the info API over HTTP, on a socket an operator may open to other
// users on the host.
//
// It is the second local API, and the opposite of the control socket in who it is for.
// The control socket is for the user who runs nebula, serves nearly everything and needs
// no configuration. This one is for every other program on the machine, a web server
// that wants to know who is on the other end of a connection arriving over the overlay,
// say, and it is off until an operator names a socket and a mode for it. What it serves
// is the handler nebula builds for it, Control.InfoHandler: the identity a certificate
// asserts and nothing operational, so opening it to a group of services, or to everyone
// on the host, gives away nothing the overlay did not already tell them. This server is
// the socket, its access control, the reload, and the rules every request is held to
// before the handler sees it: GET alone, no body, no path that would need cleaning, and
// a panic answered rather than dropped; the handler decides the rest.
type InfoServer struct {
	endpoint

	// h is what is served: the daemon's routes, as handed to NewInfoServer.
	h http.Handler
}

// NewInfoServer returns an InfoServer that serves h once Rebind brings it up.
func NewInfoServer(l *slog.Logger, h http.Handler) *InfoServer {
	return &InfoServer{
		endpoint: endpoint{l: l, name: "local info API"},
		h:        h,
	}
}

// Rebind brings the server up at path with mode, moves it there, or, when it is already
// there, applies a changed mode; endpoint.rebindLocked says what that promises. It is
// the one way the server comes up, so Wire's reload callback and its first attempt are
// the same call.
func (s *InfoServer) Rebind(ctx context.Context, path string, acc Access) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.rebindLocked(ctx, path, acc, func(ln net.Listener) io.Closer {
		srv := &http.Server{
			Handler:           s.handler(),
			ReadHeaderTimeout: infoReadHeaderTimeout,
			ReadTimeout:       infoReadTimeout,
			WriteTimeout:      infoWriteTimeout,
			IdleTimeout:       infoIdleTimeout,
			MaxHeaderBytes:    infoMaxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(s.l.Handler(), slog.LevelDebug),
		}

		s.l.Info("Local info API listening", "path", path, "access", acc.String())
		if w := unprotectedNameWarning(path); w != "" {
			s.l.Warn("Local info API is served on a pipe name that is not protected", "path", path, "risk", w)
		}
		go s.serve(srv, ln)

		// Closing the server closes the listener Serve was handed, and a Serve that has
		// not started yet closes it on its way out, so the node is never left bound by a
		// listener nothing is accepting from. Requests in flight are cut off rather than
		// waited for: a reload must not hang on a slow client, and the answer is a lookup
		// the client can simply repeat.
		return srv
	})
}

// serve runs the HTTP server on ln until it is closed. Only an error other than the
// close is worth a line: Stop and Rebind are the two things that close it.
func (s *InfoServer) serve(srv *http.Server, ln net.Listener) {
	err := srv.Serve(netutil.LimitListener(ln, infoMaxConns))
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		s.l.Error("Local info API stopped serving", "error", err)
	}
}

// handler wraps the daemon's handler in the rules every request is held to. The misses
// here are JSON, as the handler's are, so a client never has to parse net/http's text
// for a method or a path it did not expect.
func (s *InfoServer) handler() http.Handler {
	return s.recovering(readOnly(refuseBody(s.h)))
}

// readOnly answers any method but GET with 405 before the handler sees it: the info API
// reports and never acts, so there is nothing another method could mean.
func readOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// refuseBody answers a request that carries a body with 400, before any handler sees
// it, and has the connection closed after the reply rather than kept for another
// request. Nothing here reads a body; one is a mistake, and the client is told what to
// do instead. net/http still drains what the body it announced it would send, up to the
// read deadline, so the deadline is what bounds a client that never sends it.
func refuseBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			w.Header().Set("Connection", "close")
			WriteJSONError(w, http.StatusBadRequest, "the info API takes no request body; what it serves is named by the path")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// recovering turns a panic in the handler into a 500 and a log line rather than a dropped
// connection, which is all net/http would offer, and keeps the daemon up, which is what
// matters: this surface is reachable by whoever the operator opened it to. The handler
// produces its whole answer before writing any of it, so a panic always finds the
// response unwritten. A path that would need cleaning, /v1/../v1/x or //v1/x, is refused
// here outright rather than redirected: nothing legitimate sends one.
func (s *InfoServer) recovering(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.l.Error("Recovered from panic serving a local info API request",
					"panic", rec,
					"path", r.URL.Path,
					"query", r.URL.RawQuery,
					"stack", string(debug.Stack()),
				)
				WriteJSONError(w, http.StatusInternalServerError, "request failed")
			}
		}()

		if path.Clean(r.URL.Path) != r.URL.Path {
			notFoundRoute(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", http.MethodGet)
	WriteJSONError(w, http.StatusMethodNotAllowed, fmt.Sprintf("%s is not allowed; the info API is read only, use GET", r.Method))
}

func notFoundRoute(w http.ResponseWriter, r *http.Request) {
	WriteJSONError(w, http.StatusNotFound, fmt.Sprintf("no such path %s", r.URL.Path))
}

// WriteJSON writes body as the JSON answer with status. The handler nebula serves here
// uses it too, so every answer on this surface has one shape.
func WriteJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// WriteJSONError writes {"error": msg} with status, the one shape of a miss here.
func WriteJSONError(w http.ResponseWriter, status int, msg string) {
	body, _ := json.Marshal(map[string]string{"error": msg})
	WriteJSON(w, status, append(body, '\n'))
}

// infoConfig is the info API section of a config, read and checked.
type infoConfig struct {
	Enabled bool
	Path    string
	Access  Access
}

// infoConfigFrom reads the info API section. A disabled section needs nothing else to be
// right; an enabled one needs a socket path, a group that exists if it names one, and
// a mode that parses if it names one. A group with no mode means groupSocketMode, and a
// mode that gives a named group nothing is refused: it would be a group that cannot
// connect, which is not what naming one asks for.
func infoConfigFrom(c *config.C) (infoConfig, error) {
	cfg := infoConfig{Enabled: c.GetBool(InfoEnabledKey, false)}
	if !cfg.Enabled {
		return cfg, nil
	}

	p := c.GetString(InfoSocketKey, "")
	if p == "" {
		return cfg, fmt.Errorf("%s is true but %s is not set; the info API needs a socket path", InfoEnabledKey, InfoSocketKey)
	}
	if err := checkSocketPath(InfoSocketKey, p); err != nil {
		return cfg, err
	}
	cfg.Path = p

	group, err := groupFromConfig(c, InfoGroupKey)
	if err != nil {
		return cfg, err
	}
	// With neither a mode nor a group named, the daemon's user alone, so that enabling
	// the API does not open it to anyone until the operator says who.
	def := ownerOnlyMode
	if group.ID != "" {
		def = groupSocketMode
	}

	mode, err := parseSocketMode(c.Get(InfoModeKey), def)
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", InfoModeKey, err)
	}
	// On unix the mode is what admits the group, so one that shuts it out is a config
	// error; on windows the group is an entry in the pipe's security descriptor and the
	// mode means nothing to a pipe, so it is not held against the group there.
	if runtime.GOOS != "windows" && group.ID != "" && mode&0070 == 0 {
		return cfg, fmt.Errorf("%s %s gives group %s no access to the socket; use \"%04o\" or leave the mode unset", InfoModeKey, modeString(mode), group.Name, mode|0060)
	}
	cfg.Access = Access{Mode: mode, Group: group}

	return cfg, nil
}

// parseSocketMode reads an octal mode written as a string. A bare 0660 in yaml is an
// integer, and which integer depends on the parser (octal 432 under YAML 1.1, decimal
// 660 under 1.2), so a number is refused with the fix rather than quietly applied as
// whichever mode its digits happen to spell in octal.
func parseSocketMode(raw any, def os.FileMode) (os.FileMode, error) {
	switch v := raw.(type) {
	case nil:
		return def, nil
	case string:
		mode, err := strconv.ParseUint(v, 8, 32)
		if err != nil || mode&^0777 != 0 {
			return 0, fmt.Errorf("%q is not an octal file mode such as \"0660\"", v)
		}
		return os.FileMode(mode), nil
	default:
		return 0, fmt.Errorf("must be a quoted octal string such as \"0660\", not the number %v; yaml reads a bare mode as a decimal or octal integer depending on the parser", v)
	}
}
