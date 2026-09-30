package commands

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// notWithheld is a stand in for a surface's own policy; these tests use ForProfiling
// because it is the only such flag today, not because the registry knows about it.
func notWithheld(c *Command) bool { return !c.ForProfiling }

const testReason = "this surface does not run profiling commands"

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
		ForProfiling:     true,
		Callback: func(fs any, a []string, w StringWriter) error {
			return w.WriteLine("wrote")
		},
	})
	return r
}

// TestLocalSocketServesEverythingElse: the surface serves commands by default and
// withholds only those that write files on the host.
func TestLocalSocketServesEverythingElse(t *testing.T) {
	ro := testRegistry().Filter(notWithheld, testReason)

	names := make([]string, 0)
	for _, c := range ro.All() {
		names = append(names, string(c.Name))
	}

	assert.ElementsMatch(t, []string{"help", "served"}, names)
}

func TestUnannotatedCommandIsServed(t *testing.T) {
	r := New()
	r.Register(&Command{
		Name:             "plain",
		ShortDescription: "a command with no annotations",
		Callback: func(fs any, a []string, w StringWriter) error {
			return nil
		},
	})

	cmd := r.Filter(notWithheld, testReason).Get("plain")
	assert.NotNil(t, cmd, "commands reach the local socket unless they say otherwise")
}

func TestProfilingCommandIsWithheld(t *testing.T) {
	r := New()
	r.Register(&Command{
		Name:             "save-a-profile",
		ShortDescription: "drives the profiler",
		ForProfiling:     true,
		Callback: func(fs any, a []string, w StringWriter) error {
			return nil
		},
	})

	cmd := r.Filter(notWithheld, testReason).Get("save-a-profile")
	assert.Nil(t, cmd, "a profiling command must not reach the local socket")
}

// TestRefusesWithheldByName covers a client that knows a command exists and asks for it
// anyway. The filter lives on the serving side, so the answer must not depend on what
// the client was told was available.
func TestRefusesWithheldByName(t *testing.T) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	w := NewSplitStringWriter(out, errOut)

	err := testRegistry().Filter(notWithheld, testReason).DispatchArgs([]string{"withheld"}, "", w)

	assert.ErrorIs(t, err, ErrWithheld)
	assert.Empty(t, out.String(), "a withheld command must produce no output")
	assert.Contains(t, errOut.String(), "withheld is not available on this surface")
	assert.Contains(t, errOut.String(), testReason,
		"the registry should render the explanation the filter supplied, not one of its own")
}

// TestWithheldIsNotReportedAsUnknown keeps the two cases distinct: an operator who
// mistypes and one who asked for a real command should not get the same answer.
func TestWithheldIsNotReportedAsUnknown(t *testing.T) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	err := testRegistry().Filter(notWithheld, testReason).DispatchArgs([]string{"no-such-command"}, "", NewSplitStringWriter(out, errOut))

	require.NoError(t, err)
	assert.Contains(t, out.String(), "did not understand: no-such-command")
}

// TestSplitWriterKeepsOutputParseable is why the writer grew Err(): usage text on the
// same stream as -json output would corrupt it.
func TestSplitWriterKeepsOutputParseable(t *testing.T) {
	r := New()
	r.Register(&Command{
		Name:             "emit",
		ShortDescription: "emits json",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			fl.Bool("json", false, "emit json")
			return fl, nil
		},
		Callback: func(fs any, a []string, w StringWriter) error {
			return w.Write(`{"ok":true}`)
		},
	})

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	require.Error(t, r.DispatchArgs([]string{"emit", "-nope"}, "", NewSplitStringWriter(out, errOut)))

	assert.Empty(t, out.String(), "flag errors must not land on the output stream")
	assert.Contains(t, errOut.String(), "flag provided but not defined")
}

// TestMergedWriterPreservesSshBehavior: the ssh surface points both streams at one
// channel, and must keep seeing a single merged stream.
func TestMergedWriterPreservesSshBehavior(t *testing.T) {
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
	require.Error(t, r.DispatchArgs([]string{"emit", "-nope"}, "", NewStringWriter(merged)))
	assert.Contains(t, merged.String(), "flag provided but not defined")
}

func TestHelpListsOnlyServedCommands(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, testRegistry().Filter(notWithheld, testReason).Help(nil, NewStringWriter(out)))

	assert.Contains(t, out.String(), "served")
	assert.NotContains(t, out.String(), "withheld")
}

func TestDispatchHelpFlag(t *testing.T) {
	out := &bytes.Buffer{}
	testRegistry().Dispatch("served -h", NewStringWriter(out))
	assert.Contains(t, out.String(), "served - a command this surface serves")
}

// TestDispatchReportsUnparseableLine pins that a line shlex rejects says so on Err rather
// than coming back silent, so an operator with an unbalanced quote learns the quote is the
// problem instead of assuming the command is broken.
func TestDispatchReportsUnparseableLine(t *testing.T) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	testRegistry().Dispatch(`served "unterminated`, NewSplitStringWriter(out, errOut))
	assert.Empty(t, out.String())
	assert.Contains(t, errOut.String(), "could not parse command line")
}

func TestCloneDoesNotAffectOriginal(t *testing.T) {
	r := testRegistry()
	c := r.Clone()
	c.Register(&Command{Name: "logout", ShortDescription: "ends the session"})

	assert.Nil(t, r.Get(Logout))
}

// TestCloneHelpSeesCloneCommands: help on a clone answers for the clone. The ssh session
// registers logout on its clone, and `help logout` has to find it.
func TestCloneHelpSeesCloneCommands(t *testing.T) {
	c := testRegistry().Clone()
	c.Register(&Command{Name: "logout", ShortDescription: "ends the session"})

	out := &bytes.Buffer{}
	require.NoError(t, c.DispatchArgs([]string{"help", "logout"}, "", NewStringWriter(out)))
	assert.Contains(t, out.String(), "ends the session")

	out.Reset()
	require.NoError(t, c.DispatchArgs([]string{"help"}, "", NewStringWriter(out)))
	assert.Contains(t, out.String(), "logout")
}

func TestIsHelpRequestAcceptsEveryHelpSpelling(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-help"}, {"--help"}, {"x", "-h"}} {
		assert.True(t, IsHelpRequest(args), "%v", args)
	}
	for _, args := range [][]string{nil, {}, {"help"}, {"-hx"}, {"x"}} {
		assert.False(t, IsHelpRequest(args), "%v", args)
	}
}
