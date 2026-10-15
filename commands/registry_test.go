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

// TestDispatchDropsUnparseableLine pins sshd's behaviour for a line shlex rejects: no
// answer at all. An operator with an unbalanced quote gets silence, as they always have.
func TestDispatchDropsUnparseableLine(t *testing.T) {
	out := &bytes.Buffer{}
	testRegistry().Dispatch(`served "unterminated`, NewStringWriter(out))
	assert.Empty(t, out.String())
}

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
// a surface can log it, and an unparseable line reports why nothing was answered.
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
	assert.Error(t, r.Dispatch(`fails "unterminated`, NewStringWriter(out)))
	assert.Empty(t, out.String())
}

// TestUnknownCommandNamesTheWord: only the first word is looked up, so only it is
// reported, followed by the command list.
func TestUnknownCommandNamesTheWord(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, testRegistry().Dispatch(`nope "with args"`, NewStringWriter(out)))
	assert.True(t, strings.HasPrefix(out.String(), "did not understand: nope\nAvailable commands:\n"), out.String())
}
