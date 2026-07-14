package nebula

import (
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/assert"
)

func TestParseCpuAffinity(t *testing.T) {
	l := test.NewLogger()

	// newConfig returns a config.C with tun.cpu_affinity set to v. A nil v
	// leaves the key unset.
	newConfig := func(v any) *config.C {
		c := config.NewC(l)
		if v != nil {
			c.Settings["tun"] = map[string]any{"cpu_affinity": v}
		}
		return c
	}

	// unset -> nil (listenIn falls back to spreading across the allowed set)
	assert.Nil(t, parseCpuAffinity(newConfig(nil), l, 1))

	// Pick a CPU we're actually allowed to run on so a valid list survives
	// validation regardless of the host's affinity mask.
	allowed, _ := util.AllowedCPUs()
	validCPU := 0
	if len(allowed) > 0 {
		validCPU = allowed[0]
	}

	// valid list -> parsed through unchanged
	assert.Equal(t, []int{validCPU, validCPU}, parseCpuAffinity(newConfig([]any{validCPU, validCPU}), l, 2))

	// a negative entry is out of range on every platform -> disables the override
	assert.Nil(t, parseCpuAffinity(newConfig([]any{validCPU, -1}), l, 2))

	// a non-integer entry -> disables the override
	assert.Nil(t, parseCpuAffinity(newConfig([]any{validCPU, "not-a-cpu"}), l, 2))

	// a CPU id outside the allowed set -> disables the override. Only assertable
	// where we can enumerate the allowed set (e.g. linux); 1<<20 is far beyond
	// any representable CPU id so it can never be in the mask.
	if len(allowed) > 0 {
		assert.Nil(t, parseCpuAffinity(newConfig([]any{1 << 20}), l, 1))
	}
}
