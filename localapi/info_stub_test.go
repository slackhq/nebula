package localapi

import (
	"fmt"
	"net/http"
)

// stubInfoHandler stands in for the daemon's handler: one resource, /v1/whoami, whose
// name, from the query string or the path, selects an outcome. The server's own
// behaviour, the socket, its access, the rules it holds requests to and the reload, is
// tested against it apart from what nebula serves, which the root package tests.
func stubInfoHandler() http.Handler {
	answer := func(w http.ResponseWriter, name string) {
		switch name {
		case "":
			WriteJSON(w, http.StatusOK, []byte("{\"name\":\"me\",\"groups\":[]}\n"))
		case "boom":
			panic("this handler is broken")
		default:
			WriteJSON(w, http.StatusOK, []byte(fmt.Sprintf("{\"name\":%q}\n", name)))
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/whoami", func(w http.ResponseWriter, r *http.Request) {
		answer(w, r.URL.Query().Get("name"))
	})
	mux.HandleFunc("GET /v1/whoami/{name}", func(w http.ResponseWriter, r *http.Request) {
		answer(w, r.PathValue("name"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		WriteJSONError(w, http.StatusNotFound, "no such path "+r.URL.Path)
	})
	return mux
}
