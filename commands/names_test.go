package commands

import (
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
		r.Register(&Command{Name: n, Run: func(fs any, a []string) (Result, error) { return Nothing(), nil }})
	}

	var got []Name
	for _, c := range r.All() {
		got = append(got, c.Name)
	}
	require.Equal(t, []Name{ChangeRemote, Help, Version, "aa-extra", "zz-extra"}, got)

	// Help, the schema and a filtered copy all follow the same order.
	var schema []Name
	for _, cs := range r.Schema() {
		schema = append(schema, cs.Name)
	}
	assert.Equal(t, got, schema)

	var filtered []Name
	for _, c := range r.Filter(func(c *Command) bool { return c.Name != Version }, testReason).All() {
		filtered = append(filtered, c.Name)
	}
	assert.Equal(t, []Name{ChangeRemote, Help, "aa-extra", "zz-extra"}, filtered)
}
