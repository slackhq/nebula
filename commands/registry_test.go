package commands

import (
	"bytes"
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
