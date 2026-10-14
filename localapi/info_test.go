//go:build !windows

package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	"golang.org/x/sys/unix"
)

type whoamiFlags struct {
	Name string
}

// infoRegistry holds one identity command, whoami, whose -name selects an outcome, and
// one command the info API must withhold.
func infoRegistry() *commands.Registry {
	reg := commands.New()
	reg.Register(&commands.Command{
		Name:             "whoami",
		ShortDescription: "reports who a name belongs to",
		Identity:         true,
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := &whoamiFlags{}
			fl.StringVar(&s.Name, "name", "", "the name to look up")
			return fl, s
		},
		Run: func(fs any, a []string) (commands.Result, error) {
			switch name := fs.(*whoamiFlags).Name; name {
			case "":
				return commands.Value(map[string]any{"name": "me", "groups": []string{}}), nil
			case "nobody":
				return commands.NotFound("No active tunnel for vpn addr: %s", name), nil
			case "bad":
				return commands.Failed("The provided vpn addr could not be parsed: %s", name), nil
			case "boom":
				panic("this command is broken")
			case "err":
				return commands.Result{}, errors.New("an internal detail")
			default:
				return commands.Value(map[string]any{"name": name}), nil
			}
		},
	})
	reg.Register(echoCommand())
	return reg
}

func serveInfo(t *testing.T, reg *commands.Registry, mode os.FileMode) (*InfoServer, string) {
	t.Helper()

	path := testSocket(t)
	s := NewInfoServer(test.NewLogger(), reg)
	require.NoError(t, s.Rebind(context.Background(), path, mode))
	t.Cleanup(s.Stop)
	return s, path
}

// httpDo sends one request over the socket at path and returns the status, body and
// headers. The host in the URL is a placeholder: the dialer ignores it.
func TestInfoServesIdentityCommands(t *testing.T) {
	_, path := serveInfo(t, infoRegistry(), 0600)

	status, body, hdr := test.HTTPDo(t, path, http.MethodGet, "/v1/whoami?name=alice")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"alice"}`, body)
	assert.Equal(t, "application/json", hdr.Get("Content-Type"))

	status, body = test.HTTPGet(t, path, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"me","groups":[]}`, body, "a parameter left out is the command's default")
}

// TestInfoWithholdsTheRest checks the filter at the wire: a command that exists but is
// not an identity command is refused with the reason, and a name nothing is registered
// under is unknown, so a caller can tell a typo from a closed door.
func TestInfoWithholdsTheRest(t *testing.T) {
	_, path := serveInfo(t, infoRegistry(), 0600)

	status, body := test.HTTPGet(t, path, "/v1/echo?x=1")
	assert.Equal(t, http.StatusForbidden, status)
	assert.Contains(t, body, "echo is not available on this surface")
	assert.Contains(t, body, "identity lookups only")

	status, body = test.HTTPGet(t, path, "/v1/nope")
	assert.Equal(t, http.StatusNotFound, status)
	assert.Contains(t, body, `unknown command \"nope\"`)

	for _, target := range []string{"/", "/v2/whoami", "/v1/", "/v1/whoami/extra", "//v1/whoami", "/v1/x/../whoami", "/v1/../v1/whoami"} {
		status, body = test.HTTPGet(t, path, target)
		assert.Equal(t, http.StatusNotFound, status, target)
		assert.Contains(t, body, `"error"`, "%s: misses are JSON too", target)
	}
}

func TestInfoStatusCodes(t *testing.T) {
	_, path := serveInfo(t, infoRegistry(), 0600)

	for _, tc := range []struct {
		target string
		status int
		body   string
	}{
		{"/v1/whoami?name=nobody", http.StatusNotFound, `{"error":"No active tunnel for vpn addr: nobody"}`},
		{"/v1/whoami?name=bad", http.StatusBadRequest, `{"error":"The provided vpn addr could not be parsed: bad"}`},
		{"/v1/whoami?nope=1", http.StatusBadRequest, `{"error":"whoami has no parameter \"nope\""}`},
		{"/v1/whoami?name=a&name=b", http.StatusBadRequest, `{"error":"parameter \"name\" was given more than once"}`},
		{"/v1/whoami?pretty=maybe", http.StatusBadRequest, `{"error":"pretty: expected a boolean, got \"maybe\""}`},
		// Run failed: the caller hears that it did and no more; the detail is for the log.
		{"/v1/whoami?name=err", http.StatusInternalServerError, `{"error":"command failed"}`},
	} {
		status, body := test.HTTPGet(t, path, tc.target)
		assert.Equal(t, tc.status, status, tc.target)
		assert.JSONEq(t, tc.body, body, tc.target)
	}

	status, body, hdr := test.HTTPDo(t, path, http.MethodPost, "/v1/whoami?name=alice")
	assert.Equal(t, http.StatusMethodNotAllowed, status)
	assert.Equal(t, http.MethodGet, hdr.Get("Allow"))
	assert.Contains(t, body, "read only")

	status, _, _ = test.HTTPDo(t, path, http.MethodDelete, "/v1")
	assert.Equal(t, http.StatusMethodNotAllowed, status)
}

// TestInfoPanicDoesNotKillTheDaemon: a broken command costs a request, not the overlay.
// This surface may be open to anyone on the host, so that holds against them too.
func TestInfoPanicDoesNotKillTheDaemon(t *testing.T) {
	_, path := serveInfo(t, infoRegistry(), 0600)

	status, body := test.HTTPGet(t, path, "/v1/whoami?name=boom")
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.JSONEq(t, `{"error":"command failed"}`, body)

	status, body = test.HTTPGet(t, path, "/v1/whoami?name=alice")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"alice"}`, body)
}

func TestInfoDescribe(t *testing.T) {
	_, path := serveInfo(t, infoRegistry(), 0600)

	status, body := test.HTTPGet(t, path, "/v1")
	require.Equal(t, http.StatusOK, status)

	var schema []commands.CommandSchema
	require.NoError(t, json.Unmarshal([]byte(body), &schema))

	var names []commands.Name
	flags := map[commands.Name][]string{}
	for _, c := range schema {
		names = append(names, c.Name)
		for _, f := range c.Flags {
			flags[c.Name] = append(flags[c.Name], f.Name)
		}
	}
	assert.ElementsMatch(t, []commands.Name{"help", "whoami"}, names, "only what is served is described")
	assert.Equal(t, []string{"name", commands.FlagJSON, commands.FlagPretty}, flags["whoami"])
}

// TestInfoPresentationFlags: the query string takes -json and -pretty as a command line
// would. The answer is JSON either way; pretty indents it.
func TestInfoPresentationFlags(t *testing.T) {
	_, path := serveInfo(t, infoRegistry(), 0600)

	_, compact := test.HTTPGet(t, path, "/v1/whoami?name=alice&json=true")
	assert.Equal(t, "{\"name\":\"alice\"}\n", compact)

	_, pretty := test.HTTPGet(t, path, "/v1/whoami?name=alice&pretty")
	assert.Equal(t, "{\n    \"name\": \"alice\"\n}\n", pretty)

	_, off := test.HTTPGet(t, path, "/v1/whoami?name=alice&pretty=false")
	assert.Equal(t, compact, off)
}

// TestInfoSocketMode: the mode is the operator's, pinned regardless of the umask, and a
// changed mode on a reload is applied in place rather than by rebinding.
func TestInfoSocketMode(t *testing.T) {
	old := unix.Umask(0077)
	defer unix.Umask(old)

	s, path := serveInfo(t, infoRegistry(), 0660)

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0660), fi.Mode().Perm())

	require.NoError(t, s.Rebind(context.Background(), path, 0640))
	fi, err = os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0640), fi.Mode().Perm())
	assert.Equal(t, path, s.Path())

	status, _ := test.HTTPGet(t, path, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status, "the same listener is still serving")
}

func TestInfoRebindMovesAndStopRemoves(t *testing.T) {
	s, first := serveInfo(t, infoRegistry(), 0600)

	second := testSocket(t)
	require.NoError(t, s.Rebind(context.Background(), second, 0600))
	assert.Equal(t, second, s.Path())
	_, err := os.Stat(first)
	assert.True(t, os.IsNotExist(err), "the old socket is removed")

	status, body := test.HTTPGet(t, second, "/v1/whoami?name=alice")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"alice"}`, body)

	s.Stop()
	assert.Empty(t, s.Path())
	_, err = os.Stat(second)
	assert.True(t, os.IsNotExist(err), "Stop removes the socket")
}

func TestInfoRebindFailureKeepsTheOldSocket(t *testing.T) {
	s, first := serveInfo(t, infoRegistry(), 0600)

	err := s.Rebind(context.Background(), filepath.Join(privateBase(t), "missing", "n", "s.sock"), 0600)
	require.Error(t, err)
	assert.Equal(t, first, s.Path())

	status, _ := test.HTTPGet(t, first, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status)
}

func TestInfoContextCancellationStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	path := testSocket(t)
	s := NewInfoServer(test.NewLogger(), infoRegistry())
	require.NoError(t, s.Rebind(ctx, path, 0600))
	t.Cleanup(s.Stop)

	cancel()
	require.Eventually(t, func() bool { return s.Path() == "" }, time.Second, 10*time.Millisecond)
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))

	// And a reload that lands during shutdown must not bring it back.
	err = s.Rebind(ctx, path, 0600)
	require.Error(t, err)
	assert.ErrorContains(t, err, "shutting down")
}

func TestInfoConfig(t *testing.T) {
	load := func(t *testing.T, yaml string) (infoConfig, error) {
		t.Helper()
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(yaml))
		return infoConfigFrom(c, "/etc/nebula/config.yml")
	}

	cfg, err := load(t, "local_api: {}\n")
	require.NoError(t, err)
	assert.False(t, cfg.Enabled)

	cfg, err = load(t, "local_api:\n  info:\n    socket: /run/nebula/info.sock\n")
	require.NoError(t, err)
	assert.False(t, cfg.Enabled, "a socket alone does not enable it")

	_, err = load(t, "local_api:\n  info:\n    enabled: true\n")
	require.Error(t, err)
	assert.ErrorContains(t, err, "needs a socket path")

	cfg, err = load(t, "local_api:\n  info:\n    enabled: true\n    socket: /run/nebula/info.sock\n")
	require.NoError(t, err)
	assert.Equal(t, infoConfig{Enabled: true, Path: "/run/nebula/info.sock", Mode: 0600}, cfg)

	cfg, err = load(t, "local_api:\n  info:\n    enabled: true\n    socket: run/info.sock\n    socket_mode: \"0660\"\n")
	require.NoError(t, err)
	assert.Equal(t, infoConfig{Enabled: true, Path: "/etc/nebula/run/info.sock", Mode: 0660}, cfg, "a relative socket is taken from the config's directory")

	_, err = load(t, "local_api:\n  info:\n    enabled: true\n    socket: /run/nebula/info.sock\n    socket_mode: 0660\n")
	require.Error(t, err, "a bare number is whichever integer the yaml parser made of it")
	assert.ErrorContains(t, err, "quoted octal string")

	for _, bad := range []string{`"abc"`, `"1777"`, `"08"`} {
		_, err = load(t, "local_api:\n  info:\n    enabled: true\n    socket: /run/nebula/info.sock\n    socket_mode: "+bad+"\n")
		require.Error(t, err, bad)
		assert.ErrorContains(t, err, "not an octal file mode", bad)
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
	sectionWithMode := func(enabled bool, socket, mode string) string {
		return fmt.Sprintf("local_api:\n  control:\n    socket: %s\n  info:\n    enabled: %t\n    socket: %s\n    socket_mode: \"%s\"\n", ctlPath, enabled, socket, mode)
	}
	section := func(enabled bool, socket string) string {
		return sectionWithMode(enabled, socket, "0600")
	}

	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(section(false, infoPath)))

	eps := Wire(ctx, test.NewLogger(), c, infoRegistry(), "/etc/nebula/config.yml")
	t.Cleanup(eps.Stop)
	assert.Equal(t, ctlPath, eps.Control.Path())
	assert.Empty(t, eps.Info.Path(), "off until enabled")

	require.NoError(t, c.ReloadConfigString(section(true, infoPath)))
	assert.Equal(t, infoPath, eps.Info.Path())
	status, body := test.HTTPGet(t, infoPath, "/v1/whoami?name=alice")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"alice"}`, body)

	// A reload that changes nothing leaves it where it is.
	require.NoError(t, c.ReloadConfigString(section(true, infoPath)))
	assert.Equal(t, infoPath, eps.Info.Path())

	// A reload that changes only the mode applies it in place.
	require.NoError(t, c.ReloadConfigString(sectionWithMode(true, infoPath, "0660")))
	assert.Equal(t, infoPath, eps.Info.Path())
	fi, err := os.Stat(infoPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0660), fi.Mode().Perm())

	// A reload that moves the socket moves it, and removes the old one.
	moved := testSocket(t)
	require.NoError(t, c.ReloadConfigString(section(true, moved)))
	assert.Equal(t, moved, eps.Info.Path())
	_, err = os.Stat(infoPath)
	assert.True(t, os.IsNotExist(err))
	status, body = test.HTTPGet(t, moved, "/v1/whoami?name=bob")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"bob"}`, body)
	require.NoError(t, c.ReloadConfigString(section(true, infoPath)))
	require.Equal(t, infoPath, eps.Info.Path())

	// The control socket's path is refused, and the running endpoint is kept.
	require.NoError(t, c.ReloadConfigString(section(true, ctlPath)))
	assert.Equal(t, infoPath, eps.Info.Path())
	assert.Equal(t, ctlPath, eps.Control.Path())

	require.NoError(t, c.ReloadConfigString(section(false, infoPath)))
	assert.Empty(t, eps.Info.Path())
	_, err = os.Stat(infoPath)
	assert.True(t, os.IsNotExist(err))

	// One Stop takes both down.
	require.NoError(t, c.ReloadConfigString(section(true, infoPath)))
	eps.Stop()
	assert.Empty(t, eps.Info.Path())
	assert.Empty(t, eps.Control.Path())
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

	srv := wireInfo(ctx, test.NewLogger(), c, infoRegistry(), "/etc/nebula/config.yml", NewServer(test.NewLogger(), infoRegistry()))
	t.Cleanup(srv.Stop)
	require.Equal(t, infoPath, srv.Path())

	require.NoError(t, c.ReloadConfigString(good+"    socket_mode: 0660\n"))
	assert.Equal(t, infoPath, srv.Path())
	status, _ := test.HTTPGet(t, infoPath, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status)
}

// TestInfoAfterReplyRunsOnceTheResponseIsOut: the hook blocks until the test releases
// it, so the only way the response can arrive is if it left the server before the hook
// began. The reply carries a Content-Length, so a flushed reply is complete to its reader.
func TestInfoAfterReplyRunsOnceTheResponseIsOut(t *testing.T) {
	release := make(chan struct{})
	acted := make(chan struct{})

	reg := commands.New()
	reg.Register(&commands.Command{
		Name:             "act",
		ShortDescription: "replies, then acts",
		Identity:         true,
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Did("about to act"), nil
		},
		AfterReply: func() {
			<-release
			close(acted)
		},
	})
	_, path := serveInfo(t, reg, 0o600)

	status, body := test.HTTPGet(t, path, "/v1/act")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"ok":true,"reason":"about to act"}`, body)

	select {
	case <-acted:
		t.Fatal("AfterReply ran before the response was delivered")
	default:
	}

	close(release)
	select {
	case <-acted:
	case <-time.After(2 * time.Second):
		t.Fatal("AfterReply never ran")
	}
}
