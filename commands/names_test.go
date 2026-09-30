package commands

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKnownIsOneOfEach: a name listed twice would be displayed twice.
func TestKnownIsOneOfEach(t *testing.T) {
	seen := map[Name]bool{}
	for _, n := range Known {
		assert.False(t, seen[n], "%s is listed twice", n)
		seen[n] = true
		assert.True(t, n.IsKnown())
	}
	assert.False(t, Name("served").IsKnown())
}

// TestAllListsInDisplayOrder: Known's order wins regardless of registration order, and
// a name Known does not place follows, sorted.
func TestAllListsInDisplayOrder(t *testing.T) {
	r := New()
	for _, n := range []Name{"zz-extra", Version, "aa-extra", ChangeRemote} {
		r.Register(&Command{Name: n, Callback: func(fs any, a []string, w StringWriter) error { return nil }})
	}

	var got []Name
	for _, c := range r.All() {
		got = append(got, c.Name)
	}
	require.Equal(t, []Name{ChangeRemote, Help, Version, "aa-extra", "zz-extra"}, got)

	// The command list follows the same order.
	out := &bytes.Buffer{}
	r.DumpCommands(NewStringWriter(out))
	assert.Equal(t, "Available commands:\n"+
		"change-remote - \n"+
		"help - prints available commands or help <command> for specific usage info\n"+
		"version - \n"+
		"aa-extra - \n"+
		"zz-extra - \n\n", out.String())
}
