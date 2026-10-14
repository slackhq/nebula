package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime/debug"
	"slices"
	"strconv"
	"time"

	"github.com/slackhq/nebula/commands"
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
)

const (
	// defaultInfoMode is the socket's mode when the config names none: the daemon's
	// user alone, so that enabling the API does not open it to anyone until the operator
	// says who.
	defaultInfoMode os.FileMode = 0600

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

// errInfoUnsupported is returned by Rebind on a platform without a socket mode to open.
var errInfoUnsupported = errors.New("the info API is not available on this platform")

// servedOnInfo decides what the info API will run: the commands that report identity
// and nothing else, which the commands declare about themselves. Filter adds help to
// the result, so a client can ask what is served; help on a filtered registry describes
// only that registry.
func servedOnInfo(c *commands.Command) bool {
	return c.Identity
}

// notServedOnInfo explains a refusal, naming the surfaces that will run the command.
const notServedOnInfo = "the info API serves identity lookups only; the ssh debug server and nebula ctl serve the rest"

// InfoServer serves the identity commands over HTTP, on a socket an operator may open to
// other users on the host.
//
// It is the second local API, and the opposite of the control socket in who it is for.
// The control socket is for the user who runs nebula, serves nearly everything and needs
// no configuration. This one is for every other program on the machine, a web server
// that wants to know who is on the other end of a connection arriving over the overlay,
// say, and it is off until an operator names a socket and a mode for it. What it serves
// is decided by the commands themselves, Command.Identity: the identity a certificate
// asserts and nothing operational, so opening it to a group of services, or to everyone
// on the host, gives away nothing the overlay did not already tell them.
//
// HTTP, so that no client library is needed. GET /v1/<command>?<flag>=<value> runs a
// command with its options as the query string and answers with the command's JSON, the
// same value the control socket and -json produce. GET /v1 describes what is served. A
// refusal is a 4xx with {"error": reason}: 404 when the command said the thing asked
// about does not exist (commands.NotFound), 400 for a parameter or an argument the
// command would not take, 403 for a command this surface withholds.
type InfoServer struct {
	endpoint

	// reg is the identity commands this surface serves, filtered from the daemon's
	// registry when the server was built.
	reg *commands.Registry
}

// NewInfoServer returns an InfoServer that serves the identity commands in reg. reg is
// complete when it arrives: nebula registers every command before it wires its local
// APIs, and nothing registers one later, so the filter is taken once here rather than
// kept up to date against the source.
func NewInfoServer(l *slog.Logger, reg *commands.Registry) *InfoServer {
	return &InfoServer{
		endpoint: endpoint{l: l, name: "local info API"},
		reg:      reg.Filter(servedOnInfo, notServedOnInfo),
	}
}

// Rebind brings the server up at path with mode, moves it there, or, when it is already
// there, applies a changed mode; endpoint.rebindLocked says what that promises. It is
// the one way the server comes up, so Wire's reload callback and its first attempt are
// the same call.
func (s *InfoServer) Rebind(ctx context.Context, path string, acc Access) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !infoSupported {
		return errInfoUnsupported
	}

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

// handler builds the routes. Every answer is JSON, the misses included, so a client
// never has to parse net/http's text for a path or method it did not expect. That
// includes a path ServeMux would clean and redirect, /v1/../v1/x or //v1/x, which is
// refused outright: nothing legitimate sends one, and a redirect is one more thing a
// client would have to follow.
func (s *InfoServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1", s.handleDescribe)
	mux.HandleFunc("GET /v1/{command}", s.handleCommand)
	mux.HandleFunc("/v1", methodNotAllowed)
	mux.HandleFunc("/v1/{command}", methodNotAllowed)
	mux.HandleFunc("/", notFoundRoute)
	return s.recovering(refuseBody(mux))
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
			writeJSONError(w, http.StatusBadRequest, "the info API takes no request body; put the command's parameters in the query string")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// recovering turns a panic in a command into a 500 and a log line rather than a dropped
// connection, which is all net/http would offer, and keeps the daemon up, which is what
// matters: this surface is reachable by whoever the operator opened it to. The handlers
// produce their whole answer before writing any of it, so a panic in Run always finds
// the response unwritten.
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
				writeJSONError(w, http.StatusInternalServerError, "command failed")
			}
		}()

		if path.Clean(r.URL.Path) != r.URL.Path {
			notFoundRoute(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleDescribe answers GET /v1 with the schema of every command served here, the same
// document the control socket's describe returns for its own surface.
func (s *InfoServer) handleDescribe(w http.ResponseWriter, _ *http.Request) {
	body, err := json.Marshal(s.reg.Schema())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// handleCommand answers GET /v1/<command>: the query string carries the command's
// parameters, and the response body is the command's JSON. A request body is never
// read. It is the control socket's serve with HTTP's vocabulary for the outcomes.
func (s *InfoServer) handleCommand(w http.ResponseWriter, r *http.Request) {
	name := commands.Name(r.PathValue("command"))

	reg := s.reg
	cmd, err := reg.Resolve(name)
	if err != nil {
		// A command this surface withholds is a different answer from one that does not
		// exist, and Resolve says which; only the status is picked here.
		status := http.StatusNotFound
		var withheld *commands.WithheldError
		if errors.As(err, &withheld) {
			status = http.StatusForbidden
		}
		writeJSONError(w, status, err.Error())
		return
	}

	// Parsed strictly: the lenient parser on the request drops a pair it cannot decode
	// and keeps the rest, and a request that lost its address would be answered as one
	// that never had it, which for print-cert is this node's own certificate.
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed query string: "+err.Error())
		return
	}
	params, format, err := queryParams(q, reg.SchemaFor(cmd))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	res, err := commands.Invoke(commands.Request{Command: cmd, Params: params})
	if err != nil {
		var pe *commands.ParamError
		if errors.As(err, &pe) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Run failed. The sentence is for the operator's log; the caller, who may be
		// anyone the operator admitted, is told that it failed and no more.
		s.l.Warn("Local info API command failed", "command", name, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "command failed")
		return
	}

	// A command that acts does so before this surface's one reply, whose body is the
	// outcome; see Command.Then.
	if cmd.Then != nil && res.OK {
		res = cmd.Then()
	}

	// A refusal is answered before an empty Result is: the zero Result is a refusal with
	// nothing to say, which exits 1 over ssh and must not read as success here. One with
	// no reason is the command's fault, as a Run error is, and is answered the same way.
	if !res.OK {
		if res.Reason == "" {
			s.l.Warn("Local info API command refused without a reason", "command", name)
			writeJSONError(w, http.StatusInternalServerError, "command failed")
			return
		}
		status := http.StatusBadRequest
		if res.NotFound {
			status = http.StatusNotFound
		}
		writeJSONError(w, status, res.Reason)
		return
	}

	if res.Empty() {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// The same rendering function every surface uses, so the value here is byte for
	// byte what -json prints at an ssh prompt.
	buf := &bytes.Buffer{}
	if err := commands.Render(cmd, res, format, buf); err != nil {
		s.l.Warn("Local info API could not render a result", "command", name, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "command failed")
		return
	}

	writeJSON(w, http.StatusOK, buf.Bytes())
}

// queryParams reads a query string as a command's parameters. Each key is a flag of the
// command, by name, in the form the control socket takes them; one given twice is
// refused rather than silently picking either. The presentation flags are read as a
// command line reads them, and set apart: the answer is JSON regardless, and pretty
// indents it.
func queryParams(q url.Values, schema commands.CommandSchema) (map[string]string, commands.Format, error) {
	var params, presentation map[string]string
	for _, k := range slices.Sorted(maps.Keys(q)) {
		vs := q[k]
		if len(vs) > 1 {
			return nil, commands.FormatUnset, fmt.Errorf("parameter %q was given more than once", k)
		}

		into := &params
		if k == commands.FlagJSON || k == commands.FlagPretty {
			into = &presentation
		}
		if *into == nil {
			*into = map[string]string{}
		}
		v := vs[0]
		// ?raw is ?raw=true, as -raw is -raw=true on a command line.
		if v == "" && isBoolParam(schema, k) {
			v = "true"
		}
		(*into)[k] = v
	}

	format, err := commands.PresentationFormat(presentation)
	if err != nil {
		return nil, commands.FormatUnset, err
	}
	if format == commands.FormatUnset {
		format = commands.FormatJSON
	}

	return params, format, nil
}

// isBoolParam reports whether name is one of the command's boolean flags.
func isBoolParam(schema commands.CommandSchema, name string) bool {
	for _, f := range schema.Flags {
		if f.Name == name {
			return f.Bool
		}
	}
	return false
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", http.MethodGet)
	writeJSONError(w, http.StatusMethodNotAllowed, fmt.Sprintf("%s is not allowed; the info API is read only, use GET", r.Method))
}

func notFoundRoute(w http.ResponseWriter, r *http.Request) {
	writeJSONError(w, http.StatusNotFound, fmt.Sprintf("no such path %s; GET /v1 lists the commands and GET /v1/<command> runs one", r.URL.Path))
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	body, _ := json.Marshal(map[string]string{"error": msg})
	writeJSON(w, status, append(body, '\n'))
}

// infoConfig is the info API section of a config, read and checked.
type infoConfig struct {
	Enabled bool
	Path    string
	Access  Access
}

// infoConfigFrom reads the info API section. A disabled section needs nothing else to be
// right; an enabled one needs a socket path and, if it names a mode, one that parses.
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

	mode, err := parseSocketMode(c.Get(InfoModeKey))
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", InfoModeKey, err)
	}
	cfg.Access = Access{Mode: mode}

	return cfg, nil
}

// parseSocketMode reads an octal mode written as a string. A bare 0660 in yaml is an
// integer, and which integer depends on the parser (octal 432 under YAML 1.1, decimal
// 660 under 1.2), so a number is refused with the fix rather than quietly applied as
// whichever mode its digits happen to spell in octal.
func parseSocketMode(raw any) (os.FileMode, error) {
	switch v := raw.(type) {
	case nil:
		return defaultInfoMode, nil
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
