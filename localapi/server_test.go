//go:build !windows

package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// testSocket returns a short socket path whose directory does not exist yet and whose
// parent is private: one level below the test's own directory, so that listen has a
// directory of its own to create.
func testSocket(t *testing.T) string {
	t.Helper()
	return filepath.Join(test.ShortTempDir(t), "n", "s.sock")
}

func serve(t *testing.T, reg *commands.Registry) (*Server, string) {
	t.Helper()

	path := testSocket(t)
	s := NewServer(test.NewLogger(), reg)
	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	t.Cleanup(s.Stop)

	return s, path
}

// serveAt starts a server on an exact path, for tests that care where the socket is.
func serveAt(t *testing.T, path string) (*Server, func()) {
	t.Helper()

	s := NewServer(test.NewLogger(), basicRegistry())
	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	return s, s.Stop
}

// echoCommand reports its operands, for tests on either surface.
func echoCommand() *commands.Command {
	return &commands.Command{
		Name:             "echo",
		ShortDescription: "echoes its arguments",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Value(fmt.Sprintf("%v", a)), nil
		},
	}
}

func basicRegistry() *commands.Registry {
	reg := commands.New()
	reg.Register(echoCommand())
	reg.Register(&commands.Command{
		Name:             "boom",
		ShortDescription: "panics",
		Run: func(fs any, a []string) (commands.Result, error) {
			panic("this command is broken")
		},
	})
	return reg
}

// run invokes one command and returns its output and its error text. An empty error is
// success: the protocol has no separate status field.
func run(t *testing.T, path, command string, args ...string) (string, string) {
	t.Helper()

	res, err := (&Client{Path: path}).Invoke(command, nil, args, "")
	require.NoError(t, err)
	return textOf(res), res.Error
}

// textOf is what a test reads as a command's output: the text when text was asked for,
// else the JSON result, unquoted when it is a JSON string so a test can compare words.
func textOf(res *Response) string {
	if len(res.Text) > 0 {
		return string(res.Text)
	}
	if len(res.Result) > 0 && res.Result[0] == '"' {
		var s string
		if err := json.Unmarshal(res.Result, &s); err == nil {
			return s
		}
	}
	return string(res.Result)
}

func TestServeAllowedCommand(t *testing.T) {
	_, path := serve(t, basicRegistry())

	out, errOut := run(t, path, "echo", "a", "b")
	assert.Equal(t, "[a b]", out)
	assert.Empty(t, errOut, "a command that worked reports no error")
}

// TestPanicInCommandDoesNotKillTheDaemon: a broken command costs a connection, not the
// overlay.
func TestPanicInCommandDoesNotKillTheDaemon(t *testing.T) {
	_, path := serve(t, basicRegistry())

	out, errOut := run(t, path, "boom")
	assert.Empty(t, out)
	assert.Contains(t, errOut, "command failed")

	// The server is still serving, which is the point of the test.
	out, errOut = run(t, path, "echo", "still", "here")
	assert.Equal(t, "[still here]", out)
	assert.Empty(t, errOut)
}

// TestSocketPermissions: the modes are pinned, not left to the umask. A 077 umask would
// make the directory 0700 and hide a root daemon's socket from an unprivileged nebula
// ctl.
func TestSocketPermissions(t *testing.T) {
	for _, umask := range []int{0, 0077} {
		t.Run(fmt.Sprintf("umask %04o", umask), func(t *testing.T) {
			old := unix.Umask(umask)
			defer unix.Umask(old)

			_, path := serve(t, basicRegistry())

			fi, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), fi.Mode().Perm(), "socket must not be reachable by other users")

			di, err := os.Stat(filepath.Dir(path))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0755), di.Mode().Perm(), "a directory we create ourselves is searchable, so ServedByRoot can see into it")
		})
	}
}

func TestLiveSocketIsNotStolen(t *testing.T) {
	first, path := serve(t, basicRegistry())
	require.NotNil(t, first)

	second := NewServer(test.NewLogger(), basicRegistry())
	err := second.Rebind(context.Background(), path, ownerOnly())
	assert.ErrorContains(t, err, "already in use", "a live endpoint must not be unlinked by a second instance")
}

// TestLiveSocketIsNotStolenBeforeItsChmod: between an instance's bind and its chmod the
// socket is at whatever mode the umask left. A second instance starting in that window
// must still see it as live, not stale: only a refused connect proves nothing is behind
// the file.
func TestLiveSocketIsNotStolenBeforeItsChmod(t *testing.T) {
	first, path := serve(t, basicRegistry())
	require.NotNil(t, first)
	require.NoError(t, os.Chmod(path, 0666))

	second := NewServer(test.NewLogger(), basicRegistry())
	err := second.Rebind(context.Background(), path, ownerOnly())
	require.ErrorContains(t, err, "already in use", "a live socket at any mode is not thereby dead")

	_, err = os.Stat(path)
	require.NoError(t, err, "the first instance's socket is still there")
	require.NoError(t, os.Chmod(path, 0600))
	out, _ := run(t, path, "echo", "ok")
	assert.Equal(t, "[ok]", out, "and still served")
}

func TestRebindMovesTheSocket(t *testing.T) {
	s, path := serve(t, basicRegistry())
	next := filepath.Join(filepath.Dir(path), "n.sock")

	require.NoError(t, s.Rebind(context.Background(), next, ownerOnly()))
	assert.Equal(t, next, s.Path())

	out, _ := run(t, next, "echo", "moved")
	assert.Equal(t, "[moved]", out)

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "the old socket should be unlinked")
}

func TestRebindFailureKeepsTheOldSocket(t *testing.T) {
	s, path := serve(t, basicRegistry())

	err := s.Rebind(context.Background(), "/nonexistent-dir-for-tests/x.sock", ownerOnly())
	require.Error(t, err)
	assert.Equal(t, path, s.Path(), "a bad path must leave the working endpoint alone")

	out, _ := run(t, path, "echo", "ok")
	assert.Equal(t, "[ok]", out)
}

// TestSemaphoreSurvivesRestart pins the rule that the connection limiter is made once. A
// handler releases into the channel it acquired from, so if Rebind replaced it after a
// Stop, a command still running across the restart would block forever on the new,
// empty channel and leak its goroutine and connection.
func TestSemaphoreSurvivesRestart(t *testing.T) {
	s := NewServer(test.NewLogger(), basicRegistry())
	path := testSocket(t)

	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	first := s.sem
	require.NotNil(t, first)
	s.Stop()

	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	defer s.Stop()
	assert.Equal(t, first, s.sem, "Rebind after Stop must keep the same semaphore")

	require.NoError(t, s.Rebind(context.Background(), testSocket(t), ownerOnly()))
	assert.Equal(t, first, s.sem, "Rebind must keep the same semaphore")
}

// TestRestartIsWatchedOnItsOwnContext: the ctx watcher is installed by the first bind of
// a run and cleared by Stop, so a server stopped by one context's cancellation and
// started again under another is stopped when that second context is cancelled, not
// left serving until the process exits.
func TestRestartIsWatchedOnItsOwnContext(t *testing.T) {
	s := NewServer(test.NewLogger(), basicRegistry())
	path := testSocket(t)

	ctxA, cancelA := context.WithCancel(context.Background())
	require.NoError(t, s.Rebind(ctxA, path, ownerOnly()))
	cancelA()
	require.Eventually(t, func() bool { return s.Path() == "" }, time.Second, 10*time.Millisecond, "the first context must stop the server")

	ctxB, cancelB := context.WithCancel(context.Background())
	require.NoError(t, s.Rebind(ctxB, path, ownerOnly()))
	defer s.Stop()
	assert.Equal(t, path, s.Path())

	cancelB()
	require.Eventually(t, func() bool { return s.Path() == "" }, time.Second, 10*time.Millisecond, "the second context must stop the server too")
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "the socket must be removed when the second context stops the server")
}

// TestStopDetachesTheWatcher: a server stopped by Stop and started again under another
// context belongs to that context alone. The one that started the earlier run, ending
// later, must not take the new run down with it.
func TestStopDetachesTheWatcher(t *testing.T) {
	s := NewServer(test.NewLogger(), basicRegistry())
	path := testSocket(t)

	ctxA, cancelA := context.WithCancel(context.Background())
	t.Cleanup(cancelA)
	require.NoError(t, s.Rebind(ctxA, path, ownerOnly()))
	s.Stop()

	ctxB, cancelB := context.WithCancel(context.Background())
	t.Cleanup(cancelB)
	require.NoError(t, s.Rebind(ctxB, path, ownerOnly()))
	t.Cleanup(s.Stop)

	cancelA()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, path, s.Path(), "the first run's context has nothing to do with the second run")
	_, err := (&Client{Path: path}).Describe()
	require.NoError(t, err)

	cancelB()
	require.Eventually(t, func() bool { return s.Path() == "" }, time.Second, 10*time.Millisecond, "the second run's context stops it")
}

// TestGivingUpTheSocketDetachesTheWatcher: when the node is gone from under the endpoint
// and the bind that follows fails, the run is over and its watcher went with it, so a
// later Rebind is watched on the ctx it was given, as after a Stop.
func TestGivingUpTheSocketDetachesTheWatcher(t *testing.T) {
	s := NewServer(test.NewLogger(), basicRegistry())
	path := testSocket(t)

	ctxA, cancelA := context.WithCancel(context.Background())
	t.Cleanup(cancelA)
	require.NoError(t, s.Rebind(ctxA, path, ownerOnly()))

	// The node goes and a directory takes its place, so the bind that follows fails.
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Mkdir(path, 0700))
	err := s.Rebind(ctxA, path, ownerOnly())
	require.ErrorContains(t, err, "is not a socket")
	assert.Empty(t, s.Path(), "the socket was given up before the bind failed")
	require.NoError(t, os.Remove(path))

	ctxB, cancelB := context.WithCancel(context.Background())
	t.Cleanup(cancelB)
	require.NoError(t, s.Rebind(ctxB, path, ownerOnly()))
	t.Cleanup(s.Stop)

	cancelA()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, path, s.Path(), "the first run's context has nothing to do with the second run")

	cancelB()
	require.Eventually(t, func() bool { return s.Path() == "" }, time.Second, 10*time.Millisecond, "the second run's context stops it")
}

func TestVersionMismatchIsExplained(t *testing.T) {
	_, path := serve(t, basicRegistry())

	conn, err := net.Dial("unix", path)
	require.NoError(t, err)
	defer conn.Close()

	body, _ := json.Marshal(Request{Version: ProtocolVersion + 1, Command: "echo"})
	_, err = conn.Write(append(body, '\n'))
	require.NoError(t, err)

	res, err := readResponse(conn)
	require.NoError(t, err)
	assert.Contains(t, res.Error, "different versions")
}

func TestOversizedRequestIsRejected(t *testing.T) {
	_, path := serve(t, basicRegistry())

	conn, err := net.Dial("unix", path)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write(append(bytes.Repeat([]byte("a"), MaxRequestBytes+10), '\n'))
	if err == nil {
		res, rerr := readResponse(conn)
		require.NoError(t, rerr)
		assert.NotEmpty(t, res.Error)
	}
}

// TestConcurrentClientsAreBounded checks that going over the connection cap is answered
// rather than queued, so a burst of clients cannot pile up against the packet path.
// TestSlowCommandIsNamedInTheLog: a command that does not return holds its slot for
// good, and enough of them leave the socket answering only "busy". Both are logged, the
// command by name once it has run past slowAfter and each refused connection as it
// happens, so a busy socket can be traced to what wedged it.
func TestSlowCommandIsNamedInTheLog(t *testing.T) {
	reg := commands.New()
	release := make(chan struct{})
	reg.Register(&commands.Command{
		Name:             "block",
		ShortDescription: "blocks until released",
		Run: func(fs any, a []string) (commands.Result, error) {
			<-release
			return commands.Value("done"), nil
		},
	})

	var logs lockedBuffer
	s := NewServer(test.NewLoggerWithOutput(&logs), reg)
	s.maxConns = 1
	s.slowAfter = 20 * time.Millisecond
	path := testSocket(t)
	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	defer s.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = (&Client{Path: path}).Invoke("block", nil, []string{"x"}, "")
	}()

	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "still running")
	}, 2*time.Second, 10*time.Millisecond)
	assert.Contains(t, logs.String(), "command=block")
	assert.Contains(t, logs.String(), "args=[x]")

	res, err := (&Client{Path: path}).Invoke("block", nil, nil, "")
	require.NoError(t, err)
	assert.Contains(t, res.Error, "busy")
	assert.Contains(t, logs.String(), "at capacity")

	close(release)
	wg.Wait()
}

// TestPanickedCommandIsNotReportedAsStillRunning: the slow command line is about a slot
// that is still held. A command that panicked has given its slot back, and the client
// its answer, so no line must claim otherwise after the fact.
func TestPanickedCommandIsNotReportedAsStillRunning(t *testing.T) {
	reg := commands.New()
	reg.Register(&commands.Command{
		Name:             "boom",
		ShortDescription: "panics",
		Run: func(fs any, a []string) (commands.Result, error) {
			panic("this command is broken")
		},
	})

	var logs lockedBuffer
	s := NewServer(test.NewLoggerWithOutput(&logs), reg)
	s.slowAfter = 20 * time.Millisecond
	path := testSocket(t)
	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	defer s.Stop()

	res, err := (&Client{Path: path}).Invoke("boom", nil, nil, "")
	require.NoError(t, err)
	assert.Equal(t, "command failed", res.Error)

	time.Sleep(100 * time.Millisecond)
	assert.Contains(t, logs.String(), "Recovered from panic")
	assert.NotContains(t, logs.String(), "still running")
}

// lockedBuffer is a strings.Builder the server's goroutines and the test can share.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// flakyListener fails its first few Accepts the way a process that is out of file
// descriptors does, then behaves.
type flakyListener struct {
	net.Listener
	failures int
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if f.failures > 0 {
		f.failures--
		return nil, &net.OpError{Op: "accept", Net: "unix", Err: errors.New("too many open files")}
	}
	return f.Listener.Accept()
}

// TestAcceptSurvivesTransientErrors: an Accept that fails for a reason other than the
// listener being closed is retried, so a moment at the descriptor limit does not take
// the control socket down for the rest of the process. Closing the listener is still
// what ends the loop.
func TestAcceptSurvivesTransientErrors(t *testing.T) {
	path := testSocket(t)
	require.NoError(t, os.Mkdir(filepath.Dir(path), 0700))
	ln, err := listen(path, ownerOnly())
	require.NoError(t, err)

	s := NewServer(test.NewLogger(), basicRegistry())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.accept(&flakyListener{Listener: ln, failures: 3}, make(chan struct{}, 1))
	}()

	out, errText := run(t, path, "echo", "still", "here")
	assert.Empty(t, errText)
	assert.Equal(t, "[still here]", out)

	require.NoError(t, ln.Close())
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop did not exit when the listener was closed")
	}
}

func TestStopRemovesTheSocket(t *testing.T) {
	s, path := serve(t, basicRegistry())
	s.Stop()

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestContextCancellationStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	path := testSocket(t)

	s := NewServer(test.NewLogger(), basicRegistry())
	require.NoError(t, s.Rebind(ctx, path, ownerOnly()))

	cancel()
	assert.Eventually(t, func() bool {
		_, err := os.Stat(path)
		return os.IsNotExist(err)
	}, 2*time.Second, 20*time.Millisecond)
}

// TestNamedParametersDriveFlags is the point of the protocol: a caller passes options by
// name, with JSON's own types, and never assembles a command line.
// TestStringParamsNumbers: JSON numbers arrive as float64. Whole ones render as integers
// so int flags accept them, and a whole one outside int64 is refused rather than
// converted, since Go's float-to-int conversion of an out-of-range value is unspecified
// and would set a number the caller never sent.
func TestStringParamsNumbers(t *testing.T) {
	cases := map[string]struct {
		in      float64
		want    string
		wantErr bool
	}{
		"whole":            {in: 3, want: "3"},
		"negative whole":   {in: -1, want: "-1"},
		"fraction":         {in: 1.5, want: "1.5"},
		"min int64":        {in: math.MinInt64, want: "-9223372036854775808"},
		"largest in range": {in: 9223372036854774784, want: "9223372036854774784"},
		"2^63":             {in: 9223372036854775808, wantErr: true},
		"1e19":             {in: 1e19, wantErr: true},
		"below min int64":  {in: -9.3e18, wantErr: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := stringParams(map[string]any{"n": tc.in})
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, `parameter "n" is `)
				assert.ErrorContains(t, err, "outside the range of a 64-bit integer")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, out["n"])
		})
	}
}

func TestNamedParametersDriveFlags(t *testing.T) {
	reg := commands.New()
	reg.Register(&commands.Command{
		Name:             "report",
		ShortDescription: "reports its flags",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := struct {
				Verbose bool
				Label   string
			}{}
			fl.BoolVar(&s.Verbose, "verbose", false, "say more")
			fl.StringVar(&s.Label, "label", "none", "a label")
			return fl, &s
		},
		Run: func(fs any, a []string) (commands.Result, error) {
			s := fs.(*struct {
				Verbose bool
				Label   string
			})
			return commands.Value(fmt.Sprintf("verbose=%v label=%s args=%v", s.Verbose, s.Label, a)), nil
		},
	})

	_, path := serve(t, reg)

	res, err := (&Client{Path: path}).Invoke("report",
		map[string]string{"verbose": "true", "label": "here"},
		[]string{"an-operand"},
		"",
	)
	require.NoError(t, err)

	assert.Empty(t, res.Error)
	assert.Equal(t, "verbose=true label=here args=[an-operand]", textOf(res))
}

// TestUnknownParameterIsReported: a misspelled parameter is an error rather than a
// silently applied default, which is the difference between an API and a guess.
func TestUnknownParameterIsReported(t *testing.T) {
	reg := commands.New()
	reg.Register(&commands.Command{
		Name:             "report",
		ShortDescription: "takes a flag",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			fl.Bool("verbose", false, "say more")
			return fl, nil
		},
		Run: func(fs any, a []string) (commands.Result, error) { return commands.Nothing(), nil },
	})

	_, path := serve(t, reg)

	res, err := (&Client{Path: path}).Invoke("report", map[string]string{"verbos": "true"}, nil, "")
	require.NoError(t, err)

	assert.Contains(t, res.Error, `report has no parameter "verbos"`)
}

func TestParametersOnACommandThatTakesNoneAreReported(t *testing.T) {
	_, path := serve(t, basicRegistry())

	res, err := (&Client{Path: path}).Invoke("echo", map[string]string{"nope": "true"}, nil, "")
	require.NoError(t, err)

	assert.Contains(t, res.Error, "echo takes no parameters")
}

// TestJSONOutputIsAJSONValue: a command that emits JSON lands in the response as JSON,
// not as a string a caller has to parse a second time.
func TestJSONOutputIsAJSONValue(t *testing.T) {
	reg := commands.New()
	reg.Register(&commands.Command{
		Name:             "emit",
		ShortDescription: "emits json",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Value(map[string]any{"hosts": []int{1, 2, 3}}), nil
		},
	})

	_, path := serve(t, reg)

	res, err := (&Client{Path: path}).Invoke("emit", nil, nil, "")
	require.NoError(t, err)

	var decoded struct {
		Hosts []int `json:"hosts"`
	}
	require.NoError(t, json.Unmarshal(res.Result, &decoded))
	assert.Equal(t, []int{1, 2, 3}, decoded.Hosts)
}

// TestStringValueIsAJSONString: a command whose value is a string answers a JSON request
// with a JSON string, quotes and all.
func TestStringValueIsAJSONString(t *testing.T) {
	_, path := serve(t, basicRegistry())

	res, err := (&Client{Path: path}).Invoke("echo", nil, []string{"hi"}, "")
	require.NoError(t, err)

	var s string
	require.NoError(t, json.Unmarshal(res.Result, &s))
	assert.Equal(t, "[hi]", s)
}

func TestDescribeListsTheCommands(t *testing.T) {
	_, path := serve(t, basicRegistry())

	schema, err := (&Client{Path: path}).Describe()
	require.NoError(t, err)

	names := make([]string, 0, len(schema))
	for _, c := range schema {
		names = append(names, string(c.Name))
	}

	assert.ElementsMatch(t, []string{"help", "echo", "boom"}, names)
}

// TestPresentationParametersAreRefused: the schema lists json and pretty on every
// command, because the command lines take them, but a request has one way to choose its
// rendering, the format field. A client that sends them as parameters is pointed there
// rather than given a second, weaker way to say the same thing.
func TestPresentationParametersAreRefused(t *testing.T) {
	reg := commands.New()
	reg.Register(&commands.Command{
		Name:             "pair",
		ShortDescription: "returns a pair",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Value(map[string]int{"a": 1}), nil
		},
		Text: func(v any, w io.Writer) error {
			_, err := fmt.Fprintln(w, "a is one")
			return err
		},
	})
	_, path := serve(t, reg)
	c := &Client{Path: path}

	for _, name := range []string{"json", "pretty"} {
		res, err := c.Invoke("pair", map[string]string{name: "true"}, nil, "text")
		require.NoError(t, err)
		assert.Contains(t, res.Error, name+" is a command line flag, not a parameter")
		assert.Contains(t, res.Error, "format")
		assert.Empty(t, res.Result, "a refused request runs nothing")
	}

	// The format field is the one that counts.
	res, err := c.Invoke("pair", nil, nil, "text")
	require.NoError(t, err)
	require.Empty(t, res.Error)
	assert.Equal(t, "a is one\n", textOf(res))

	res, err = c.Invoke("pair", nil, nil, "")
	require.NoError(t, err)
	require.Empty(t, res.Error)
	assert.JSONEq(t, `{"a":1}`, string(res.Result), "the API default is JSON")
}

// TestTextRequestToATextlessCommand: a command with no human rendering still answers a
// text request when the answer is a refusal, since a refusal always has one. Only a
// successful result has nothing to say in text, and that is reported then, by the daemon.
func TestTextRequestToATextlessCommand(t *testing.T) {
	reg := commands.New()
	reg.Register(&commands.Command{
		Name:             "tunnel",
		ShortDescription: "data on success, a refusal without an operand",
		Run: func(fs any, a []string) (commands.Result, error) {
			if len(a) == 0 {
				return commands.Failed("No vpn address was provided"), nil
			}
			return commands.Value(map[string]int{"index": 7}), nil
		},
		JSONOnly: true,
	})
	_, path := serve(t, reg)
	c := &Client{Path: path}

	res, err := c.Invoke("tunnel", nil, nil, "text")
	require.NoError(t, err)
	assert.Equal(t, "No vpn address was provided\n", res.Error, "the refusal is rendered, not the missing text form")

	res, err = c.Invoke("tunnel", nil, []string{"10.0.0.1"}, "text")
	require.NoError(t, err)
	assert.Contains(t, res.Error, "tunnel has no human readable output yet; pass -json or -pretty")
	assert.Empty(t, res.Result)

	res, err = c.Invoke("tunnel", nil, []string{"10.0.0.1"}, "json")
	require.NoError(t, err)
	require.Empty(t, res.Error)
	assert.JSONEq(t, `{"index":7}`, string(res.Result))

	// A refusal asked for as JSON carries the outcome for a program and the reason in
	// Error, so a client exits non-zero on the envelope alone, never by sniffing the
	// payload for an ok field some unrelated result might also have.
	res, err = c.Invoke("tunnel", nil, nil, "json")
	require.NoError(t, err)
	assert.Equal(t, "No vpn address was provided", res.Error)
	assert.JSONEq(t, `{"ok":false,"reason":"No vpn address was provided"}`, string(res.Result))
}

// TestRebindAfterFailedBindStillStopsOnCancel covers a daemon whose initial listen
// failed and which later Rebinds onto a good path from a reloaded config. The context
// watcher has to be installed by that Rebind, or the socket outlives the daemon.
func TestRebindAfterFailedBindStillStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	base := test.ShortTempDir(t)

	// listen creates one level only, so a socket directory under a parent that is not
	// there yet fails to bind, the shape of a runtime directory that does not exist.
	s := NewServer(test.NewLogger(), basicRegistry())
	require.Error(t, s.Rebind(ctx, filepath.Join(base, "missing", "n", "s.sock"), ownerOnly()))

	good := filepath.Join(base, "n", "s.sock")
	require.NoError(t, s.Rebind(ctx, good, ownerOnly()))
	t.Cleanup(s.Stop)
	_, err := (&Client{Path: good}).Describe()
	require.NoError(t, err)

	cancel()
	assert.Eventually(t, func() bool {
		_, err := os.Stat(good)
		return os.IsNotExist(err)
	}, 2*time.Second, 20*time.Millisecond)
}

// TestCommandRegisteredAfterStartIsServed: the server filters the registry per request,
// so a command an embedder registers after wiring the socket is served, and described,
// just as it would be over ssh.
func TestCommandRegisteredAfterStartIsServed(t *testing.T) {
	reg := basicRegistry()
	_, path := serve(t, reg)

	reg.Register(&commands.Command{
		Name:             "late",
		ShortDescription: "registered after the server started",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Value("late"), nil
		},
	})

	c := &Client{Path: path}

	schema, err := c.Describe()
	require.NoError(t, err)
	names := make([]string, 0, len(schema))
	for _, cs := range schema {
		names = append(names, string(cs.Name))
	}
	assert.Contains(t, names, "late")

	res, err := c.Invoke("late", nil, nil, "")
	require.NoError(t, err)
	require.Empty(t, res.Error)
	assert.JSONEq(t, `"late"`, string(res.Result))
}

// TestThenIsAnsweredInTheOneReply: this surface answers in one piece, so a command that
// acts does so before the reply, and the reply carries Run's line and Then's outcome in
// text, and the outcome alone in JSON.
func TestThenIsAnsweredInTheOneReply(t *testing.T) {
	reg := commands.New()
	acted := false
	reg.Register(&commands.Command{
		Name:             "act",
		ShortDescription: "replies, then acts",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Did("about to act"), nil
		},
		Then: func() commands.Result {
			acted = true
			return commands.Did("acted")
		},
	})
	_, path := serve(t, reg)

	res, err := (&Client{Path: path}).Invoke("act", nil, nil, "text")
	require.NoError(t, err)
	assert.True(t, acted)
	assert.Empty(t, res.Error)
	assert.Equal(t, "about to act\nacted\n", string(res.Text))

	res, err = (&Client{Path: path}).Invoke("act", nil, nil, "")
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"reason":"acted"}`, string(res.Result))

	// A refusal from Then still carries Run's line ahead of it in text, as ssh prints it.
	acted = false
	reg.Register(&commands.Command{
		Name:             "fail",
		ShortDescription: "replies, then fails to act",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Did("about to act"), nil
		},
		Then: func() commands.Result {
			return commands.Failed("could not act")
		},
	})
	res, err = (&Client{Path: path}).Invoke("fail", nil, nil, "text")
	require.NoError(t, err)
	assert.Equal(t, "about to act\ncould not act\n", res.Error)
	assert.Empty(t, res.Text)

	// A Run that refused is the outcome, and Then does not run.
	acted = false
	reg.Register(&commands.Command{
		Name:             "refuse",
		ShortDescription: "refuses, so never acts",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Failed("not like that"), nil
		},
		Then: func() commands.Result {
			acted = true
			return commands.Did("acted anyway")
		},
	})
	res, err = (&Client{Path: path}).Invoke("refuse", nil, nil, "text")
	require.NoError(t, err)
	assert.Equal(t, "not like that\n", res.Error)
	assert.False(t, acted)
}

// TestRebindRefusesDuringShutdown: a reload that lands after the daemon's context is
// cancelled must not bring the endpoint back. Stop is not terminal, so Rebind has to
// take the answer from the context rather than from the running flag.
func TestRebindRefusesDuringShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Built by hand rather than through serve: the context watcher is installed once,
	// by the first bind, and this test needs it on a context it can cancel.
	s := NewServer(test.NewLogger(), basicRegistry())
	require.NoError(t, s.Rebind(ctx, testSocket(t), ownerOnly()))
	t.Cleanup(s.Stop)

	cancel()
	assert.Eventually(t, func() bool { return s.Path() == "" }, 2*time.Second, 20*time.Millisecond, "the watcher stops the server")

	next := testSocket(t)
	err := s.Rebind(ctx, next, ownerOnly())
	require.Error(t, err)
	require.ErrorContains(t, err, "shutting down")
	assert.Empty(t, s.Path(), "the server stays stopped")

	_, statErr := os.Stat(next)
	assert.True(t, os.IsNotExist(statErr), "and the refused socket is not left on disk")
}

// TestRebindAndStopSerialize hammers Rebind against Stop. Whichever runs last decides
// the final state, so after the dust settles a Stop must leave nothing listening and no
// socket file behind, on either path.
func TestRebindAndStopSerialize(t *testing.T) {
	a := testSocket(t)
	b := testSocket(t)

	for i := 0; i < 50; i++ {
		s := NewServer(test.NewLogger(), basicRegistry())
		require.NoError(t, s.Rebind(context.Background(), a, ownerOnly()))

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = s.Rebind(context.Background(), b, ownerOnly())
		}()
		go func() {
			defer wg.Done()
			s.Stop()
		}()
		wg.Wait()

		// The Rebind may have run after the Stop, which restarts the server by design.
		// A final Stop then has to take everything down.
		s.Stop()
		assert.Empty(t, s.Path())
		for _, p := range []string{a, b} {
			_, err := os.Stat(p)
			assert.True(t, os.IsNotExist(err), "iteration %d: %s left behind", i, p)
		}
	}
}

// TestUnknownRequestFieldIsRefused: a request with a field the protocol does not define
// is answered with the field named, the way an unknown parameter is, and not run.
func TestUnknownRequestFieldIsRefused(t *testing.T) {
	_, path := serve(t, basicRegistry())

	conn, err := dial(path, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, writeFrame(conn, map[string]any{"version": ProtocolVersion, "command": "echo", "arguments": []string{"x"}}))

	var res Response
	require.NoError(t, readFrame(conn, MaxResponseBytes, "response", &res, false))
	assert.Contains(t, res.Error, `unknown field "arguments"`)
	assert.Empty(t, res.Result)
}

// TestTrailingBytesOnARequestAreRefused: a request line is one object and nothing
// more; a second object or stray bytes after it are refused rather than ignored.
func TestTrailingBytesOnARequestAreRefused(t *testing.T) {
	_, path := serve(t, basicRegistry())

	for _, line := range []string{
		`{"version":1,"command":"echo"} junk` + "\n",
		`{"version":1,"command":"echo"}{"version":1,"command":"boom"}` + "\n",
	} {
		conn, err := dial(path, time.Second)
		require.NoError(t, err)
		_, err = conn.Write([]byte(line))
		require.NoError(t, err)

		var res Response
		require.NoError(t, readFrame(conn, MaxResponseBytes, "response", &res, false))
		assert.Contains(t, res.Error, "unexpected data after the object", line)
		conn.Close()
	}
}

// TestTextOutputKeepsTheBytes: a text rendering travels as the bytes the command wrote.
// A JSON string would have had to be UTF-8, and a byte that is not would have come out
// as U+FFFD, where the ssh server passes it through.
func TestTextOutputKeepsTheBytes(t *testing.T) {
	reg := commands.New()
	raw := []byte{'n', 'a', 'm', 'e', ' ', 0xff, 0xfe, '\n'}
	reg.Register(&commands.Command{
		Name:             "raw",
		ShortDescription: "writes what a certificate held",
		Run:              func(fs any, a []string) (commands.Result, error) { return commands.Value("raw"), nil },
		Text: func(v any, w io.Writer) error {
			_, err := w.Write(raw)
			return err
		},
	})
	_, path := serve(t, reg)

	res, err := (&Client{Path: path}).Invoke("raw", nil, nil, "text")
	require.NoError(t, err)
	assert.Empty(t, res.Error)
	assert.Equal(t, raw, res.Text)
	assert.Empty(t, res.Result, "text is not also carried as JSON")
}
