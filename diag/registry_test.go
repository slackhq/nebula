package diag

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testFlags struct {
	Json bool
}

// testCommand builds a command carrying a flag set, recording what the callback was actually
// handed so a test can assert on it.
func testCommand(name string, seen *any, args *[]string) *Command {
	return &Command{
		Name:             name,
		ShortDescription: name + " short description",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			f := &testFlags{}
			fl.BoolVar(&f.Json, "json", false, "outputs json")
			return fl, f
		},
		Callback: func(fs any, a []string, w StringWriter) error {
			if seen != nil {
				*seen = fs
			}
			if args != nil {
				*args = a
			}
			return w.WriteLine("ran " + name)
		},
	}
}

func newTestRegistry(t *testing.T) (*Registry, *bytes.Buffer, StringWriter) {
	t.Helper()
	buf := &bytes.Buffer{}
	return NewRegistry(), buf, NewWriter(buf)
}

func TestRegistryDispatch(t *testing.T) {
	t.Run("a new registry knows help and nothing else", func(t *testing.T) {
		r, buf, w := newTestRegistry(t)

		require.NoError(t, r.DispatchArgs([]string{"help"}, w))
		assert.Contains(t, buf.String(), "help -")
	})

	t.Run("empty args dump the command list, matching an empty line on the console", func(t *testing.T) {
		r, buf, w := newTestRegistry(t)
		r.RegisterCommand(testCommand("do-thing", nil, nil))

		require.NoError(t, r.DispatchArgs(nil, w))
		assert.Contains(t, buf.String(), "Available commands:")
		assert.Contains(t, buf.String(), "do-thing - do-thing short description")
	})

	t.Run("an unknown command reports ErrUnknownCommand and still tells the user", func(t *testing.T) {
		r, buf, w := newTestRegistry(t)

		err := r.DispatchArgs([]string{"nope"}, w)
		require.ErrorIs(t, err, ErrUnknownCommand)
		assert.Contains(t, buf.String(), "Did not understand: nope")
		assert.Contains(t, buf.String(), "Available commands:")
	})

	// This is the hazard the ctl transport has to preserve: every callback in ssh.go begins by
	// type asserting fs to its own concrete flags struct. Reach a callback without going
	// through Command.Flags and every one of them fails.
	t.Run("a callback is handed the concrete struct its Flags callback returned", func(t *testing.T) {
		var seen any
		r, _, w := newTestRegistry(t)
		r.RegisterCommand(testCommand("do-thing", &seen, nil))

		require.NoError(t, r.DispatchArgs([]string{"do-thing", "-json"}, w))

		flags, ok := seen.(*testFlags)
		require.True(t, ok, "callback was handed %T, not *testFlags", seen)
		assert.True(t, flags.Json)
	})

	t.Run("positional arguments survive flag parsing", func(t *testing.T) {
		var args []string
		r, _, w := newTestRegistry(t)
		r.RegisterCommand(testCommand("do-thing", nil, &args))

		require.NoError(t, r.DispatchArgs([]string{"do-thing", "-json", "10.0.0.1"}, w))
		assert.Equal(t, []string{"10.0.0.1"}, args)
	})

	// Documents stdlib flag behaviour rather than endorsing it: parsing stops at the first
	// positional, so a flag written after one is silently a positional too.
	t.Run("a flag after a positional is not parsed as a flag", func(t *testing.T) {
		var seen any
		var args []string
		r, _, w := newTestRegistry(t)
		r.RegisterCommand(testCommand("do-thing", &seen, &args))

		require.NoError(t, r.DispatchArgs([]string{"do-thing", "10.0.0.1", "-json"}, w))
		assert.False(t, seen.(*testFlags).Json)
		assert.Equal(t, []string{"10.0.0.1", "-json"}, args)
	})

	t.Run("a bad flag reports ErrUsage and writes the usage text", func(t *testing.T) {
		r, buf, w := newTestRegistry(t)
		r.RegisterCommand(testCommand("do-thing", nil, nil))

		err := r.DispatchArgs([]string{"do-thing", "-nope"}, w)
		require.ErrorIs(t, err, ErrUsage)
		assert.Contains(t, buf.String(), "flag provided but not defined")
	})

	t.Run("-h anywhere routes to help instead of running the command", func(t *testing.T) {
		var seen any
		r, buf, w := newTestRegistry(t)
		r.RegisterCommand(testCommand("do-thing", &seen, nil))

		require.NoError(t, r.DispatchArgs([]string{"do-thing", "-h"}, w))
		assert.Nil(t, seen, "the callback should not have run")
		assert.Contains(t, buf.String(), "do-thing - do-thing short description")
		assert.Contains(t, buf.String(), "-json")
	})

	t.Run("Dispatch splits a line the way a shell would", func(t *testing.T) {
		var args []string
		r, _, w := newTestRegistry(t)
		r.RegisterCommand(testCommand("do-thing", nil, &args))

		require.NoError(t, r.Dispatch(`do-thing "/tmp/a path.pb.gz"`, w))
		assert.Equal(t, []string{"/tmp/a path.pb.gz"}, args)
	})

	t.Run("Match returns names by prefix for tab completion", func(t *testing.T) {
		r, _, _ := newTestRegistry(t)
		r.RegisterCommand(testCommand("print-cert", nil, nil))
		r.RegisterCommand(testCommand("print-tunnel", nil, nil))
		r.RegisterCommand(testCommand("version", nil, nil))

		assert.Equal(t, []string{"print-cert", "print-tunnel"}, r.Match("print-"))
	})
}

// A clone is what keeps the ssh session's `logout` command from being visible to every other
// session, and to nebula ctl.
func TestRegistryCloneIsolation(t *testing.T) {
	parent, _, w := newTestRegistry(t)
	parent.RegisterCommand(testCommand("shared", nil, nil))

	child := parent.Clone()
	child.RegisterCommand(testCommand("logout", nil, nil))

	require.NoError(t, child.DispatchArgs([]string{"logout"}, w))

	buf := &bytes.Buffer{}
	err := parent.DispatchArgs([]string{"logout"}, NewWriter(buf))
	assert.ErrorIs(t, err, ErrUnknownCommand)

	buf.Reset()
	require.NoError(t, child.DispatchArgs([]string{"shared"}, NewWriter(buf)))
	assert.True(t, strings.HasPrefix(buf.String(), "ran shared"))
}
