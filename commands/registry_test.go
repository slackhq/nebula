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
	require.Error(t, r.DispatchArgs([]string{"emit", "-nope"}, "", NewStringWriter(merged)))
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
