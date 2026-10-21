//go:build !windows

package localapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveInfo(t *testing.T, h http.Handler, mode os.FileMode) (*InfoServer, string) {
	t.Helper()

	path := testSocket(t)
	s := NewInfoServer(test.NewLogger(), h)
	require.NoError(t, s.Rebind(context.Background(), path, Access{Mode: mode}))
	t.Cleanup(s.Stop)
	return s, path
}

// httpDo sends one request over the socket at path and returns the status, body and
// headers. The host in the URL is a placeholder: the dialer ignores it.
func TestInfoServesTheHandler(t *testing.T) {
	_, path := serveInfo(t, stubInfoHandler(), 0600)

	status, body, hdr := test.HTTPDo(t, path, http.MethodGet, "/v1/whoami?name=alice")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"alice"}`, body)
	assert.Equal(t, "application/json", hdr.Get("Content-Type"))

	status, body = test.HTTPGet(t, path, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"me","groups":[]}`, body)

	// The path arrives as the client wrote it: an address in brackets with a port, or
	// with a zone, needs no escaping, and a percent-escaped segment is decoded.
	status, body = test.HTTPGet(t, path, "/v1/whoami/[::ffff:10.0.0.2]:8")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"[::ffff:10.0.0.2]:8"}`, body)

	status, body = test.HTTPGet(t, path, "/v1/whoami/fe80::1%25eth0")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"fe80::1%eth0"}`, body)
}

// TestInfoRefusesWhatTheHandlerNeverSees: the rules every request is held to before
// the handler: GET alone, and no path that would need cleaning, which ServeMux would
// otherwise redirect. The misses are JSON, as the handler's own are.
func TestInfoRefusesWhatTheHandlerNeverSees(t *testing.T) {
	_, path := serveInfo(t, stubInfoHandler(), 0600)

	for _, target := range []string{"//v1/whoami", "/v1/x/../whoami", "/v1/../v1/whoami"} {
		status, body := test.HTTPGet(t, path, target)
		assert.Equal(t, http.StatusNotFound, status, target)
		assert.JSONEq(t, `{"error":"no such path `+target+`"}`, body, target)
	}

	// A path the handler does not serve is the handler's miss, in the same shape.
	status, body := test.HTTPGet(t, path, "/v2/whoami")
	assert.Equal(t, http.StatusNotFound, status)
	assert.JSONEq(t, `{"error":"no such path /v2/whoami"}`, body)

	status, body, hdr := test.HTTPDo(t, path, http.MethodPost, "/v1/whoami?name=alice")
	assert.Equal(t, http.StatusMethodNotAllowed, status)
	assert.Equal(t, http.MethodGet, hdr.Get("Allow"))
	assert.Contains(t, body, "read only")

	status, _, _ = test.HTTPDo(t, path, http.MethodDelete, "/v1")
	assert.Equal(t, http.StatusMethodNotAllowed, status)
}

// TestInfoPanicDoesNotKillTheDaemon: a broken handler costs a request, not the overlay.
// This surface may be open to anyone on the host, so that holds against them too.
func TestInfoPanicDoesNotKillTheDaemon(t *testing.T) {
	_, path := serveInfo(t, stubInfoHandler(), 0600)

	status, body := test.HTTPGet(t, path, "/v1/whoami?name=boom")
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.JSONEq(t, `{"error":"request failed"}`, body)

	status, body = test.HTTPGet(t, path, "/v1/whoami?name=alice")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"alice"}`, body)
}

// TestInfoModeChangeRefusesASwappedSocket: whoever can write the directory can replace
// the node with a link to a file of their choosing; the daemon must not set the
// operator's mode on that file. The node is seen to be gone, the link is refused by the
// stale check, the file is untouched, and the endpoint reports itself down, since
// nothing of ours is reachable at the path.
func TestInfoModeChangeRefusesASwappedSocket(t *testing.T) {
	s, path := serveInfo(t, stubInfoHandler(), 0600)

	target := filepath.Join(filepath.Dir(path), "target")
	require.NoError(t, os.WriteFile(target, nil, 0600))
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Symlink(target, path))

	err := s.Rebind(context.Background(), path, Access{Mode: 0666})
	require.ErrorContains(t, err, "is not a socket")
	fi, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm(), "the file behind the link keeps its mode")
	assert.Empty(t, s.Path(), "nothing of ours answers at the path, so nothing is served")
}

func TestInfoConfig(t *testing.T) {
	load := func(t *testing.T, yaml string) (infoConfig, error) {
		t.Helper()
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(yaml))
		return infoConfigFrom(c)
	}

	cfg, err := load(t, "local_api: {}\n")
	require.NoError(t, err)
	assert.False(t, cfg.Enabled)

	cfg, err = load(t, "local_api:\n  info:\n    socket: /run/nebula/info.sock\n")
	require.NoError(t, err)
	assert.False(t, cfg.Enabled, "a socket alone does not enable it")

	_, err = load(t, "local_api:\n  info:\n    enabled: true\n")
	require.Error(t, err)
	require.ErrorContains(t, err, "needs a socket path")

	cfg, err = load(t, "local_api:\n  info:\n    enabled: true\n    socket: /run/nebula/info.sock\n")
	require.NoError(t, err)
	assert.Equal(t, infoConfig{Enabled: true, Path: "/run/nebula/info.sock", Access: Access{Mode: 0600}}, cfg)

	cfg, err = load(t, "local_api:\n  info:\n    enabled: true\n    socket: /run/nebula/info.sock\n    socket_mode: \"0660\"\n")
	require.NoError(t, err)
	assert.Equal(t, infoConfig{Enabled: true, Path: "/run/nebula/info.sock", Access: Access{Mode: 0660}}, cfg)

	_, err = load(t, "local_api:\n  info:\n    enabled: true\n    socket: run/info.sock\n")
	require.Error(t, err, "a relative socket path is refused rather than resolved against anything")
	require.ErrorContains(t, err, "must be an absolute path")
	require.ErrorContains(t, err, InfoSocketKey)

	_, err = load(t, "local_api:\n  info:\n    enabled: true\n    socket: /run/nebula/info.sock\n    socket_mode: 0660\n")
	require.Error(t, err, "a bare number is whichever integer the yaml parser made of it")
	require.ErrorContains(t, err, "quoted octal string")

	for _, bad := range []string{`"abc"`, `"1777"`, `"08"`} {
		_, err = load(t, "local_api:\n  info:\n    enabled: true\n    socket: /run/nebula/info.sock\n    socket_mode: "+bad+"\n")
		require.Error(t, err, bad)
		require.ErrorContains(t, err, "not an octal file mode", bad)
	}

	_, err = load(t, fmt.Sprintf("local_api:\n  info:\n    enabled: true\n    socket: /%s\n", strings.Repeat("x", sunPathMax)))
	require.Error(t, err)
	assert.ErrorContains(t, err, "too long")
}

// TestWireInfoFollowsConfig: off by default, up when enabled, down when disabled, and
// never on the control socket's path.
func TestWireInfoFollowsConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ctlPath := testSocket(t)
	infoPath := testSocket(t)
	section := func(enabled bool, socket string) string {
		return fmt.Sprintf("local_api:\n  control:\n    socket: %s\n  info:\n    enabled: %t\n    socket: %s\n", ctlPath, enabled, socket)
	}

	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(section(false, infoPath)))

	var logs lockedBuffer
	eps := Wire(ctx, test.NewLoggerWithOutput(&logs), c, commands.New(), stubInfoHandler())
	t.Cleanup(eps.Stop)
	ctl, info := eps.Control, eps.Info
	assert.Equal(t, ctlPath, ctl.Path())
	assert.Empty(t, info.Path(), "off until enabled")

	require.NoError(t, c.ReloadConfigString(section(true, infoPath)).Err)
	assert.Equal(t, infoPath, info.Path())
	status, body := test.HTTPGet(t, infoPath, "/v1/whoami?name=alice")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"alice"}`, body)

	// A reload that changes nothing leaves it where it is.
	require.NoError(t, c.ReloadConfigString(section(true, infoPath)).Err)
	assert.Equal(t, infoPath, info.Path())

	// A reload that moves the socket moves it, and removes the old one.
	moved := testSocket(t)
	require.NoError(t, c.ReloadConfigString(section(true, moved)).Err)
	assert.Equal(t, moved, info.Path())
	_, err := os.Stat(infoPath)
	assert.True(t, os.IsNotExist(err))
	status, body = test.HTTPGet(t, moved, "/v1/whoami?name=bob")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"bob"}`, body)
	require.NoError(t, c.ReloadConfigString(section(true, infoPath)).Err)
	require.Equal(t, infoPath, info.Path())

	// The control socket's path is refused, and the running endpoint is kept, which is
	// what the log says.
	require.NoError(t, c.ReloadConfigString(section(true, ctlPath)).Err)
	assert.Equal(t, infoPath, info.Path())
	assert.Equal(t, ctlPath, ctl.Path())
	assert.Contains(t, logs.String(), "keeping the current endpoint")
	assert.NotContains(t, logs.String(), "Local info API is not available")

	require.NoError(t, c.ReloadConfigString(section(false, infoPath)).Err)
	assert.Empty(t, info.Path())
	_, err = os.Stat(infoPath)
	assert.True(t, os.IsNotExist(err))

	// One Stop takes both down.
	require.NoError(t, c.ReloadConfigString(section(true, infoPath)).Err)
	eps.Stop()
	assert.Empty(t, info.Path())
	assert.Empty(t, ctl.Path())
}

// TestWireInfoKeepsRunningOnABadReload: a typo in the section must not cut off the
// programs relying on the endpoint; the operator is told and the endpoint stays.
func TestWireInfoKeepsRunningOnABadReload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infoPath := testSocket(t)
	good := fmt.Sprintf("local_api:\n  info:\n    enabled: true\n    socket: %s\n", infoPath)

	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(good))

	srv := wireInfo(ctx, test.NewLogger(), c, stubInfoHandler())
	t.Cleanup(srv.Stop)
	require.Equal(t, infoPath, srv.Path())

	require.NoError(t, c.ReloadConfigString(good+"    socket_mode: 0660\n").Err)
	assert.Equal(t, infoPath, srv.Path())
	status, _ := test.HTTPGet(t, infoPath, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status)
}

// rawInfoRequest opens the socket and writes req as it is, so a test can send what an
// HTTP client would not: a body that never arrives. It returns the connection.
func rawInfoRequest(t *testing.T, path, req string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = conn.Write([]byte(req))
	require.NoError(t, err)
	return conn
}

// TestInfoRefusesARequestBody: a request that announces a body is answered 400 at once,
// before the body arrives, and the connection is closed once the read deadline has ended
// the wait for it, so a client that never sends the body holds its slot for the deadline
// and no longer.
func TestInfoRefusesARequestBody(t *testing.T) {
	oldHeader, oldRead := infoReadHeaderTimeout, infoReadTimeout
	infoReadHeaderTimeout, infoReadTimeout = 200*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { infoReadHeaderTimeout, infoReadTimeout = oldHeader, oldRead })
	_, path := serveInfo(t, stubInfoHandler(), 0600)

	start := time.Now()
	conn := rawInfoRequest(t, path, "GET /v1/whoami HTTP/1.1\r\nHost: nebula\r\nContent-Length: 10\r\n\r\n")
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Contains(t, string(body), "takes no request body")
	assert.True(t, res.Close, "the connection is not kept for another request")
	assert.Less(t, time.Since(start), 200*time.Millisecond, "answered before the body, which never comes")

	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "the server closed the connection")
	assert.Less(t, time.Since(start), time.Second, "and did so at the read deadline, not later")
}

// TestInfoDropsASlowClient: a client that sends its headers and then nothing loses its
// connection at the read timeout rather than holding a slot for as long as it likes.
func TestInfoDropsASlowClient(t *testing.T) {
	oldHeader, oldRead := infoReadHeaderTimeout, infoReadTimeout
	infoReadHeaderTimeout, infoReadTimeout = 200*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { infoReadHeaderTimeout, infoReadTimeout = oldHeader, oldRead })
	_, path := serveInfo(t, stubInfoHandler(), 0600)

	// Half a request line, then silence: the header deadline ends it.
	conn := rawInfoRequest(t, path, "GET /v1/whoami HTTP/1.1\r\nHost: neb")
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	start := time.Now()
	_, err := conn.Read(make([]byte, 1))
	require.Error(t, err, "the server closed the connection")
	assert.Less(t, time.Since(start), time.Second)

	// And the server still answers the next client.
	status, _ := test.HTTPGet(t, path, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status)
}
