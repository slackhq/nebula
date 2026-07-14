package nebula

import (
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/assert"
)

func TestChooseIRQFreeCPUs(t *testing.T) {
	irq := map[int]bool{0: true, 1: true, 2: true, 3: true}

	// Plenty of IRQ-free CPUs: take the first `routines` of them in order.
	assert.Equal(t, []int{4, 5}, chooseIRQFreeCPUs([]int{0, 1, 2, 3, 4, 5, 6}, irq, 2))

	// Exactly enough.
	assert.Equal(t, []int{4, 5, 6}, chooseIRQFreeCPUs([]int{0, 1, 2, 3, 4, 5, 6}, irq, 3))

	// Not enough IRQ-free CPUs: nil, caller keeps the old default rather
	// than doubling readers up on shared cores.
	assert.Nil(t, chooseIRQFreeCPUs([]int{0, 1, 2, 3, 4}, irq, 2))

	// No IRQ info at all behaves like a plain prefix of allowed.
	assert.Equal(t, []int{0, 1}, chooseIRQFreeCPUs([]int{0, 1, 2}, map[int]bool{}, 2))

	// Non-contiguous allowed set (cgroup cpuset) with holes.
	assert.Equal(t, []int{9, 12}, chooseIRQFreeCPUs([]int{1, 3, 9, 12}, map[int]bool{1: true, 3: true}, 2))
}

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
