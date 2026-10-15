//go:build linux && !android && !e2e_testing

package cpupick

import (
	"slices"
	"testing"

	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultSkipsAvoided(t *testing.T) {
	allowed, err := util.AllowedCPUs()
	require.NoError(t, err)
	if len(allowed) < 2 {
		t.Skip("requires at least two allowed CPUs")
	}
	avoid := allowed[:len(allowed)/2]
	for key := range uint64(16) {
		got := Default(len(allowed), key, avoid, nil)
		require.NotEmpty(t, got)
		for _, cpu := range got {
			assert.NotContains(t, avoid, cpu, "key %d", key)
			assert.Contains(t, allowed, cpu, "key %d", key)
		}
	}
	assert.Nil(t, Default(2, 0, allowed, nil), "avoiding everything leaves nothing to suggest")

	// Without avoid every allowed CPU stays in play
	got := Default(len(allowed), 0, nil, nil)
	slices.Sort(got)
	assert.Equal(t, allowed, got)
}
