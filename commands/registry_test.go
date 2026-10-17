package commands

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRegistry() *Registry {
	r := New()
	r.Register(&Command{
		Name:             "served",
		ShortDescription: "a command this surface serves",
		Callback: func(fs any, a []string, w StringWriter) error {
			return w.WriteLine("read " + strings.Join(a, ","))
		},
	})
	r.Register(&Command{
		Name:             "withheld",
		ShortDescription: "a command this surface withholds",
		Callback: func(fs any, a []string, w StringWriter) error {
			return w.WriteLine("wrote")
		},
	})
	return r
}

// TestFlagUsageGoesToTheWriter pins that a parse failure's usage lands on the command's
// writer.
func TestFlagUsageGoesToTheWriter(t *testing.T) {
	r := New()
	r.Register(&Command{
		Name:             "emit",
		ShortDescription: "emits",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			fl.Bool("json", false, "emit json")
			return fl, nil
		},
		Callback: func(fs any, a []string, w StringWriter) error { return nil },
	})

	merged := &bytes.Buffer{}
	require.Error(t, r.DispatchArgs([]string{"emit", "-nope"}, NewStringWriter(merged)))
	assert.Contains(t, merged.String(), "flag provided but not defined")
}

// TestDispatchReportsUnparseableLine: a line shlex rejects, an unbalanced quote, is a
// failure the user is told about.
func TestDispatchReportsUnparseableLine(t *testing.T) {
	out := &bytes.Buffer{}
	err := testRegistry().Dispatch(`served "unterminated`, NewStringWriter(out))

	var f *Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, f.Msg+"\n", out.String())
	assert.Contains(t, out.String(), "could not parse the command line: ")
}

// TestFailTellsTheUserAndTheSurface: Fail writes the message and returns it as a Failure;
// when the write fails, the user heard nothing, so the write error is what comes back.
func TestFailTellsTheUserAndTheSurface(t *testing.T) {
	out := &bytes.Buffer{}
	err := Fail(NewStringWriter(out), "no such tunnel")
	var f *Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, "no such tunnel", f.Msg)
	assert.Equal(t, "no such tunnel\n", out.String())

	err = Fail(NewStringWriter(failingWriter{}), "no such tunnel")
	require.EqualError(t, err, "gone")
	assert.NotErrorAs(t, err, &f)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("gone") }

// TestAllSortsByName: registration order does not matter.
func TestAllSortsByName(t *testing.T) {
	r := New()
	for _, n := range []Name{"zz", Version, "aa", ChangeRemote} {
		r.Register(&Command{Name: n})
	}

	var got []Name
	for _, c := range r.All() {
		got = append(got, c.Name)
	}
	assert.Equal(t, []Name{"aa", ChangeRemote, Help, Version, "zz"}, got)
}

// TestHelpFlagAgreesWithHelpCommand pins that -h answers through the registered help
// command, and that help on a clone describes the clone: a command registered only there
// is known to both -h and `help <name>`, and one withheld from it is known to neither.
func TestHelpFlagAgreesWithHelpCommand(t *testing.T) {
	r := testRegistry()
	c := r.Clone()
	c.Register(&Command{
		Name:             Logout,
		ShortDescription: "ends the session",
		Callback:         func(fs any, a []string, w StringWriter) error { return nil },
	})

	flag := &bytes.Buffer{}
	c.Dispatch("logout -h", NewStringWriter(flag))
	cmd := &bytes.Buffer{}
	c.Dispatch("help logout", NewStringWriter(cmd))
	assert.Equal(t, cmd.String(), flag.String())
	assert.Equal(t, "logout - ends the session\n", flag.String())

	// The source never learns of it.
	src := &bytes.Buffer{}
	r.Dispatch("help logout", NewStringWriter(src))
	assert.Equal(t, "Command not available logout\n", src.String())

	// And a command both hold is described either way.
	flag.Reset()
	c.Dispatch("served -h", NewStringWriter(flag))
	assert.Equal(t, "served - a command this surface serves\n", flag.String())
}

// TestCloneHelpListsTheClone: the command list help prints is the clone's, so a clone
// that withholds a command does not name it, and the source still does.
func TestCloneHelpListsTheClone(t *testing.T) {
	r := testRegistry()
	c := New()
	c.Register(r.Get("served"))
	c = c.Clone()

	out := &bytes.Buffer{}
	c.Dispatch("help", NewStringWriter(out))
	assert.Equal(t, "Available commands:\n"+
		"help - prints available commands or help <command> for specific usage info\n"+
		"served - a command this surface serves\n\n", out.String())

	out.Reset()
	c.Dispatch("help withheld", NewStringWriter(out))
	assert.Equal(t, "Command not available withheld\n", out.String())

	out.Reset()
	r.Dispatch("help withheld", NewStringWriter(out))
	assert.Equal(t, "withheld - a command this surface withholds\n", out.String())
}

// TestDispatchReturnsTheCommandsError: what the callback returns reaches the caller, so
// a surface can log it.
func TestDispatchReturnsTheCommandsError(t *testing.T) {
	r := New()
	r.Register(&Command{
		Name: "fails",
		Callback: func(fs any, a []string, w StringWriter) error {
			return errors.New("boom")
		},
	})

	out := &bytes.Buffer{}
	require.EqualError(t, r.Dispatch("fails", NewStringWriter(out)), "boom")
	assert.Empty(t, out.String(), "a command's own error is not shown; the command speaks for itself")
}

// TestUnknownCommandNamesTheWord: only the first word is looked up, so only it is
// reported, followed by the command list, and the line is a failure to the surface.
func TestUnknownCommandNamesTheWord(t *testing.T) {
	out := &bytes.Buffer{}
	err := testRegistry().Dispatch(`nope "with args"`, NewStringWriter(out))
	var f *Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, "did not understand: nope", f.Msg)
	assert.True(t, strings.HasPrefix(out.String(), "did not understand: nope\nAvailable commands:\n"), out.String())
}
