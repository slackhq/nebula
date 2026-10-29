package nebula

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/slackhq/nebula/localapi"
)

// InfoHandler is what the info API serves: this node's identity, the identity of the
// host behind a vpn address, and beneath each its certificate. localapi.InfoServer puts
// it on the socket the operator opened and holds every request to its rules first; the
// routes here are the whole of what that socket gives away, so opening it to a group of
// services, or to everyone on the host, hands out nothing the overlay did not already
// tell them.
//
//	GET /v1/identity                          this node
//	GET /v1/identity/pem                      this node's certificate, as {"pem": ...}
//	GET /v1/identity/<vpn addr>[:port]        the host owning the address
//	GET /v1/identity/<vpn addr>[:port]/pem    its certificate
//
// The identity and the certificate are what the identity command reports, through the
// one lookup, so the two surfaces cannot disagree about whose address it is; see
// hostIdentity for what an answer proves. ?pretty indents the JSON. A miss is JSON too:
// 404 for a path not served and for an address with no tunnel behind it, 400 for one
// that does not parse or a query parameter other than pretty. The address may carry a
// port, which is stripped, so a connection's remote address passes through as it is;
// /v1/identity/ with nothing after it is a path not served, never this node, so a
// program that failed to fill an address in is told so rather than handed this node's
// identity to authorize against.
func (c *Control) InfoHandler() http.Handler {
	return infoHandler(c.f)
}

func infoHandler(f *Interface) http.Handler {
	api := &infoAPI{f: f}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", api.identity(false, false))
	mux.HandleFunc("GET /v1/identity/pem", api.identity(false, true))
	mux.HandleFunc("GET /v1/identity/{addr}", api.identity(true, false))
	mux.HandleFunc("GET /v1/identity/{addr}/pem", api.identity(true, true))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		localapi.WriteJSONError(w, http.StatusNotFound, fmt.Sprintf("no such path %s; the info API serves /v1/identity, /v1/identity/<vpn addr> and /pem under either", r.URL.Path))
	})
	return mux
}

type infoAPI struct {
	f *Interface
}

// identity answers one of the four routes: given says the address is in the path, pem
// that the certificate is wanted rather than the identity read from it.
func (a *infoAPI) identity(given, pem bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pretty, ok := prettyParam(w, r)
		if !ok {
			return
		}

		crt, fingerprint, err := lookupIdentity(a.f, r.PathValue("addr"), given)
		if err != nil {
			status := http.StatusBadRequest
			var le *lookupError
			if errors.As(err, &le) {
				switch le.kind {
				case lookupNoTunnel:
					status = http.StatusNotFound
				case lookupNoCertificate:
					status = http.StatusInternalServerError
				}
			}
			localapi.WriteJSONError(w, status, err.Error())
			return
		}

		var v any
		if pem {
			b, err := crt.MarshalPEM()
			if err != nil {
				localapi.WriteJSONError(w, http.StatusInternalServerError, "the certificate could not be encoded")
				return
			}
			v = certPEM{PEM: string(b)}
		} else {
			id, err := newHostIdentity(crt, fingerprint)
			if err != nil {
				localapi.WriteJSONError(w, http.StatusInternalServerError, "the identity could not be read")
				return
			}
			v = id
		}

		body, err := marshalJSON(v, pretty)
		if err != nil {
			localapi.WriteJSONError(w, http.StatusInternalServerError, "the answer could not be encoded")
			return
		}
		localapi.WriteJSON(w, http.StatusOK, body)
	}
}

// prettyParam reads the one query parameter the info API takes. Anything else is
// refused, as is a query string that does not decode: the lenient parser would drop
// what it could not read and keep the rest, and a request that lost something would be
// answered as one that never had it. It writes the refusal itself and says so.
func prettyParam(w http.ResponseWriter, r *http.Request) (pretty bool, ok bool) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		localapi.WriteJSONError(w, http.StatusBadRequest, "malformed query string: "+err.Error())
		return false, false
	}
	for k, vs := range q {
		if k != "pretty" {
			localapi.WriteJSONError(w, http.StatusBadRequest, fmt.Sprintf("unknown parameter %q; the info API takes pretty alone", k))
			return false, false
		}
		if len(vs) > 1 {
			localapi.WriteJSONError(w, http.StatusBadRequest, "parameter \"pretty\" was given more than once")
			return false, false
		}
		// ?pretty is ?pretty=true, as -pretty is on a command line.
		if vs[0] == "" {
			pretty = true
			continue
		}
		pretty, err = strconv.ParseBool(vs[0])
		if err != nil {
			localapi.WriteJSONError(w, http.StatusBadRequest, fmt.Sprintf("pretty: expected a boolean, got %q", vs[0]))
			return false, false
		}
	}
	return pretty, true
}

// marshalJSON encodes v the way -json and -pretty print it over ssh, a newline after,
// so a program reading both surfaces sees one shape.
func marshalJSON(v any, pretty bool) ([]byte, error) {
	var b []byte
	var err error
	if pretty {
		b, err = json.MarshalIndent(v, "", "    ")
	} else {
		b, err = json.Marshal(v)
	}
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
