package test

import (
	"context"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ShortTempDir returns a short private directory of the test's own, removed when the
// test ends. t.TempDir embeds the test name, which on darwin routinely pushes a unix
// socket path laid out under it past the 104 byte sun_path limit.
func ShortTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "la")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// Update is the -update flag: Golden rewrites its file instead of comparing against it.
var Update = flag.Bool("update", false, "rewrite golden files instead of comparing against them")

// Golden compares got with the file at path, or rewrites the file when -update is set.
func Golden(t *testing.T, path, got string) {
	t.Helper()

	if *Update {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, []byte(got), 0644))
		return
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden file, run with -update")
	assert.Equal(t, string(want), got)
}

// HTTPDo sends one request to the HTTP server on the unix socket at socket and returns
// the status, body and headers of its answer. The host in the URL is a placeholder:
// every connection goes to the socket.
func HTTPDo(t *testing.T, socket, method, target string) (int, string, http.Header) {
	t.Helper()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(method, "http://nebula"+target, nil)
	require.NoError(t, err)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(body), res.Header
}

// HTTPGet is HTTPDo for a GET whose headers the test does not read.
func HTTPGet(t *testing.T, socket, target string) (int, string) {
	t.Helper()
	status, body, _ := HTTPDo(t, socket, http.MethodGet, target)
	return status, body
}
