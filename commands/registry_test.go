package commands

import (
	"bytes"
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
	r := testRegistry().Filter(notWithheld, testReason)
	help := r.Get(Help)
	res, err := Invoke(Request{Command: help})
	require.NoError(t, err)
	out := &bytes.Buffer{}
	require.NoError(t, Render(help, res, FormatText, out))

	assert.Contains(t, out.String(), "served")
	assert.NotContains(t, out.String(), "withheld")
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
// per request, against a stream of registrations. It exists to be run under the race
// detector: the map underneath is not goroutine safe.
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
			}
		}()
	}

	wg.Wait()

	f := r.Filter(notWithheld, testReason)
	assert.Len(t, f.All(), 8*50+2, "every late registration is visible once the writers finish, beside help and served")
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
