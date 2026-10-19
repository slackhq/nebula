package commands

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// notWithheld is a stand in for a surface's own policy, which the registry knows nothing
// of; see Command.Identity for the one the info API applies.
func notWithheld(c *Command) bool { return c.Name != "withheld" }

const testReason = "this surface does not run commands that write"

// textLine is a Text renderer for test commands whose result is one string.
func textLine(v any, w io.Writer) error {
	_, err := io.WriteString(w, v.(string)+"\n")
	return err
}

func testRegistry() *Registry {
	r := New()
	r.Register(&Command{
		Name:             "served",
		ShortDescription: "a command this surface serves",
		Run: func(fs any, a []string) (Result, error) {
			return Value("read " + strings.Join(a, ",")), nil
		},
		Text: textLine,
	})
	r.Register(&Command{
		Name:             "withheld",
		ShortDescription: "a command this surface withholds",
		Run: func(fs any, a []string) (Result, error) {
			return Value("wrote"), nil
		},
		Text: textLine,
	})
	return r
}

// TestFilterKeepsWhatKeepSays: the copy holds the commands keep accepted, and help.
func TestFilterKeepsWhatKeepSays(t *testing.T) {
	ro := testRegistry().Filter(notWithheld, testReason)

	names := make([]string, 0)
	for _, c := range ro.All() {
		names = append(names, string(c.Name))
	}

	assert.ElementsMatch(t, []string{"help", "served"}, names)
}

// TestRefusesWithheldByName covers a client that knows a command exists and asks for it
// anyway. The filter lives on the serving side, so the answer must not depend on what
// the client was told was available.
func TestRefusesWithheldByName(t *testing.T) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	w := Output{Out: out, Err: errOut}

	err := testRegistry().Filter(notWithheld, testReason).DispatchArgs([]string{"withheld"}, w)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "withheld is not available on this surface")
	assert.Empty(t, out.String(), "a withheld command must produce no output")
	assert.Contains(t, errOut.String(), "withheld is not available on this surface")
	assert.Contains(t, errOut.String(), testReason,
		"the registry should render the explanation the filter supplied, not one of its own")
}

// TestWithheldIsNotReportedAsUnknown keeps the two cases distinct: an operator who
// mistypes and one who asked for a real command should not get the same answer.
func TestWithheldIsNotReportedAsUnknown(t *testing.T) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	err := testRegistry().Filter(notWithheld, testReason).DispatchArgs([]string{"no-such-command"}, Output{Out: out, Err: errOut})

	var f *Failure
	require.ErrorAs(t, err, &f, "an unknown command is a failure to the surface")
	assert.Contains(t, out.String(), "did not understand: no-such-command")
}

// paramRegistry holds one command with a bool flag and a duration flag, and reports what
// the command saw when it ran.
func paramRegistry(t *testing.T) (*Registry, *[]paramsSeen) {
	t.Helper()

	var seen []paramsSeen
	r := New()
	r.Register(&Command{
		Name:             "set",
		ShortDescription: "sets things",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := paramsSeen{}
			fl.BoolVar(&s.Verbose, "verbose", false, "say more")
			fl.DurationVar(&s.Wait, "wait", 0, "how long")
			return fl, &s
		},
		Run: func(fs any, a []string) (Result, error) {
			seen = append(seen, *fs.(*paramsSeen))
			return Value("ok"), nil
		},
	})

	return r, &seen
}

type paramsSeen struct {
	Verbose bool
	Wait    time.Duration
}

// TestInvokeReportsParametersInNameOrder: parameters arrive as an unordered object, so
// with two bad ones the error must not depend on map iteration. Name order decides.
func TestInvokeReportsParametersInNameOrder(t *testing.T) {
	r, _ := paramRegistry(t)

	cases := map[string]struct {
		params map[string]string
		want   string
	}{
		"two unknown":               {map[string]string{"zed": "1", "alpha": "1"}, `set has no parameter "alpha"`},
		"unknown before bad bool":   {map[string]string{"aaa": "1", "verbose": "maybe"}, `set has no parameter "aaa"`},
		"bad bool before unknown":   {map[string]string{"verbose": "maybe", "zzz": "1"}, `verbose: expected a boolean, got "maybe"`},
		"bad value before bad bool": {map[string]string{"wait": "soon", "verbose": "maybe"}, `verbose: expected a boolean`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Enough runs that a map-order dependence would show.
			for i := 0; i < 50; i++ {
				_, err := Invoke(Request{Command: r.Get("set"), Params: tc.params})
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.want)
			}
		})
	}
}

// TestInvokeWithABadParameterSetsNothing: a request with any bad parameter must not run
// the command, and must leave nothing behind for the next request to see. The good
// parameter sorts before the bad one, so a one-pass Invoke would have applied it.
func TestInvokeWithABadParameterSetsNothing(t *testing.T) {
	r, seen := paramRegistry(t)

	_, err := Invoke(Request{Command: r.Get("set"), Params: map[string]string{"verbose": "true", "wait": "soon"}})
	require.ErrorContains(t, err, "wait:")
	assert.Empty(t, *seen, "the command must not run with a partial parameter set")

	v, err := Invoke(Request{Command: r.Get("set")})
	require.NoError(t, err)
	assert.Equal(t, "ok", v.Value)
	require.Len(t, *seen, 1)
	assert.Equal(t, paramsSeen{}, (*seen)[0], "nothing from the failed request carried over")

	_, err = Invoke(Request{Command: r.Get("set"), Params: map[string]string{"verbose": "true", "wait": "2s"}})
	require.NoError(t, err)
	require.Len(t, *seen, 2)
	assert.Equal(t, paramsSeen{Verbose: true, Wait: 2 * time.Second}, (*seen)[1])
}

func TestHelpListsOnlyServedCommands(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, testRegistry().Filter(notWithheld, testReason).DispatchArgs(nil, MergedOutput(out)))

	assert.Contains(t, out.String(), "served")
	assert.NotContains(t, out.String(), "withheld")
}

// TestDispatchReportsUnparseableLine pins that a line shlex rejects says so on Err rather
// than coming back silent, so an operator with an unbalanced quote learns the quote is the
// problem instead of assuming the command is broken.
func TestDispatchReportsUnparseableLine(t *testing.T) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	testRegistry().Dispatch(`served "unterminated`, Output{Out: out, Err: errOut})
	assert.Empty(t, out.String())
	assert.Contains(t, errOut.String(), "could not parse the command line")
}

// TestRegisterRejectsReservedFlags: a command that declares a reserved flag is refused
// at Register rather than when an operator first runs it; see reservedFlags.
func TestRegisterRejectsReservedFlags(t *testing.T) {
	for _, name := range []string{"json", "pretty", "h", "help", "config", "socket"} {
		t.Run(name, func(t *testing.T) {
			r := New()
			assert.PanicsWithValue(t, "commands: clash declares reserved flag -"+name, func() {
				r.Register(&Command{
					Name: "clash",
					Flags: func() (*flag.FlagSet, any) {
						fl := flag.NewFlagSet("clash", flag.ContinueOnError)
						fl.Bool(name, false, "")
						return fl, nil
					},
					Run: func(fs any, a []string) (Result, error) { return Nothing(), nil },
				})
			})
		})
	}
}

// TestRegistryIsSafeForConcurrentUse runs the operations the surfaces perform, filtering
// and cloning per request or session, against a stream of registrations. It exists to
// be run under the race detector: the map underneath is not goroutine safe.
func TestRegistryIsSafeForConcurrentUse(t *testing.T) {
	r := testRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				r.Register(&Command{
					Name:             Name("late-" + strings.Repeat("a", i) + "-" + strings.Repeat("b", j)),
					ShortDescription: "registered after the surfaces started",
					Run:              func(fs any, a []string) (Result, error) { return Nothing(), nil },
				})
			}
		}(i)
	}

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				f := r.Filter(notWithheld, testReason)
				_ = f.Get("served")
				_ = f.Schema()
				_ = r.Clone().Match("late-")
			}
		}()
	}

	wg.Wait()

	f := r.Filter(notWithheld, testReason)
	assert.Len(t, f.Match("late-"), 8*50, "every late registration is visible once the writers finish")
}

// TestCloneHelpSeesCloneCommands: the ssh session registers logout on its clone, and
// the source does not learn of it. Help on the clone answers for the clone, and -h on a
// command prints what `help <name>` does, on a clone as on the source: both render
// through WriteCommandHelp, and Clone rebinds help to the copy.
func TestCloneHelpSeesCloneCommands(t *testing.T) {
	r := testRegistry()
	c := r.Clone()
	c.Register(&Command{
		Name:             Logout,
		ShortDescription: "ends the session",
		Run:              func(fs any, a []string) (Result, error) { return Nothing(), nil },
	})
	assert.Nil(t, r.Get(Logout), "the source is not affected")

	out := &bytes.Buffer{}
	require.NoError(t, c.DispatchArgs([]string{"help"}, MergedOutput(out)))
	assert.Contains(t, out.String(), "logout")

	for _, name := range []string{"logout", "served"} {
		flag := &bytes.Buffer{}
		c.Dispatch(name+" -h", MergedOutput(flag))
		cmd := &bytes.Buffer{}
		c.Dispatch("help "+name, MergedOutput(cmd))
		assert.Equal(t, cmd.String(), flag.String(), name)
		assert.Contains(t, flag.String(), name+" - ", name)
	}
}

// TestThenRunsAfterTheReply pins the order Then exists for: Run's line is on the writer
// before the action begins, Then's Result follows it, and Then's outcome is the
// command's.
func TestThenRunsAfterTheReply(t *testing.T) {
	out := &bytes.Buffer{}
	seen := "never ran"
	outcome := Did("acted")

	r := New()
	r.Register(&Command{
		Name:             "act",
		ShortDescription: "replies, then acts",
		Run: func(fs any, a []string) (Result, error) {
			return Did("about to act"), nil
		},
		Then: func() Result {
			seen = out.String()
			return outcome
		},
	})

	require.NoError(t, r.DispatchArgs([]string{"act"}, MergedOutput(out)))
	assert.Equal(t, "about to act\n", seen, "the line was written before the action")
	assert.Equal(t, "about to act\nacted\n", out.String())

	out.Reset()
	outcome = Failed("could not act")
	var f *Failure
	require.ErrorAs(t, r.DispatchArgs([]string{"act"}, MergedOutput(out)), &f)
	assert.Equal(t, "about to act\ncould not act\n", out.String())

	// In JSON only the outcome travels: one document for the program that asked.
	out.Reset()
	require.ErrorAs(t, r.DispatchArgs([]string{"act", "-json"}, MergedOutput(out)), &f)
	assert.JSONEq(t, `{"ok":false,"reason":"could not act"}`, out.String())

	// A Run that refused is the outcome; the action does not happen.
	ran := false
	r.Register(&Command{
		Name:             "refuse",
		ShortDescription: "refuses, so never acts",
		Run: func(fs any, a []string) (Result, error) {
			return Failed("not like that"), nil
		},
		Then: func() Result {
			ran = true
			return Did("acted anyway")
		},
	})
	out.Reset()
	require.ErrorAs(t, r.DispatchArgs([]string{"refuse"}, MergedOutput(out)), &f)
	assert.Equal(t, "not like that\n", out.String())
	assert.False(t, ran)
	out.Reset()
	require.ErrorAs(t, r.DispatchArgs([]string{"refuse", "-json"}, MergedOutput(out)), &f)
	assert.JSONEq(t, `{"ok":false,"reason":"not like that"}`, out.String())
	assert.False(t, ran)
}

// TestWriteCommandHelpIsTheOneRendering pins the layout both `help <command>` on the
// daemon and `-h` in the client print, so the two cannot drift apart again.
func TestWriteCommandHelpIsTheOneRendering(t *testing.T) {
	cs := CommandSchema{
		Name:  "change-remote",
		Short: "changes a remote",
		Help:  "Give it an address.",
		Flags: []FlagSchema{
			{Name: "address", Usage: "the new remote", Default: "1.2.3.4:4242"},
			{Name: "by-index", Bool: true, Usage: "match by index"},
			{Name: "json", Bool: true, Usage: "outputs as json"},
		},
	}

	out := &bytes.Buffer{}
	require.NoError(t, WriteCommandHelp(cs, out))

	assert.Equal(t, "change-remote - changes a remote\n"+
		"  Give it an address.\n"+
		"  -address string\n    \tthe new remote (default 1.2.3.4:4242)\n"+
		"  -by-index\n    \tmatch by index\n"+
		"  -json\n    \toutputs as json\n", out.String())
}

// addrFlags is the flag struct of a test command that takes -address.
type addrFlags struct{ Address string }

// TestHelpFlagIsReadWhereParseReadsIt: -h asks for help only where the line's parser
// reads it as a flag. As a flag's value or after -- it reaches the command as the
// operand it is, and help is rendered by the same function `help <command>` uses.
func TestHelpFlagIsReadWhereParseReadsIt(t *testing.T) {
	var seen []string
	r := New()
	r.Register(Flagged(&Command{Name: "x", ShortDescription: "takes an address"},
		func(fl *flag.FlagSet, s *addrFlags) { fl.StringVar(&s.Address, "address", "", "an address") },
		func(s *addrFlags, a []string) (Result, error) {
			seen = append(seen, s.Address+"|"+strings.Join(a, ","))
			return Nothing(), nil
		}))

	for _, line := range []string{"x -h", "x -help", "x --help", "x 10.0.0.1 -h", "x -address=1 -h"} {
		out := &bytes.Buffer{}
		r.Dispatch(line, MergedOutput(out))
		assert.Contains(t, out.String(), "x - takes an address\n", line)
		assert.Contains(t, out.String(), "-address string", line)
	}
	assert.Empty(t, seen, "asking for help must not run the command")

	for _, line := range []string{"x -address -h", "x -- -h"} {
		out := &bytes.Buffer{}
		r.Dispatch(line, MergedOutput(out))
		assert.Empty(t, out.String(), line)
	}
	assert.Equal(t, []string{"-h|", "|-h"}, seen)
}

// TestBadFlagIsAnsweredWithTheCommandsHelp: a flag the command does not have is reported
// on the error stream followed by the command's usage, in the rendering help uses.
func TestBadFlagIsAnsweredWithTheCommandsHelp(t *testing.T) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	r := New()
	r.Register(&Command{Name: "x", ShortDescription: "has no flags", Run: func(fs any, a []string) (Result, error) { return Nothing(), nil }})

	require.Error(t, r.DispatchArgs([]string{"x", "-nope"}, Output{Out: out, Err: errOut}))
	assert.Empty(t, out.String())
	assert.Equal(t, "flag provided but not defined: -nope\nx - has no flags\n  -json\n    \toutputs as json\n  -pretty\n    \tpretty prints json, assumes -json\n", errOut.String())
}

// TestRunErrorIsShown: an error Run returns reaches the person at the prompt on the
// error stream, as well as the surface that logs it.
func TestRunErrorIsShown(t *testing.T) {
	r := New()
	r.Register(&Command{
		Name:             "broken",
		ShortDescription: "cannot do what it is asked",
		Run: func(fs any, a []string) (Result, error) {
			return Result{}, errors.New("no certificate is loaded")
		},
	})

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	require.EqualError(t, r.DispatchArgs([]string{"broken"}, Output{Out: out, Err: errOut}), "no certificate is loaded")
	assert.Empty(t, out.String())
	assert.Equal(t, "no certificate is loaded\n", errOut.String())
}
