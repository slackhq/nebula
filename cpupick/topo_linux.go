//go:build linux

package cpupick

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// readTopology probes the NUMA node and physical-core layout of cpus from
// sysfs. Anything sysfs won't say degrades toward flatTopology: an unknown
// node becomes node 0, an unknown core becomes a core of its own — either
// way the corresponding arrange rule becomes a no-op instead of a wrong
// answer.
func readTopology(cpus []int) topology {
	return readTopologyFrom("/sys/devices/system/node", "/sys/devices/system/cpu", cpus)
}

func readTopologyFrom(nodeDir, cpuDir string, cpus []int) topology {
	coreOf, zeroCore := coreGroups(cpuDir, cpus)
	return topology{
		nodeOf:   numaNodes(nodeDir, cpus),
		coreOf:   coreOf,
		zeroCore: zeroCore,
	}
}

// numaNodes maps each cpu to its NUMA node via
// /sys/devices/system/node/nodeN/cpulist. CPUs no node claims (or no node
// dirs at all: VMs, non-NUMA kernels) land on node 0.
func numaNodes(nodeDir string, cpus []int) map[int]int {
	out := make(map[int]int, len(cpus))
	for _, c := range cpus {
		out[c] = 0
	}
	entries, err := os.ReadDir(nodeDir)
	if err != nil {
		return out
	}
	want := make(map[int]bool, len(cpus))
	for _, c := range cpus {
		want[c] = true
	}
	for _, e := range entries {
		id, ok := strings.CutPrefix(e.Name(), "node")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(id)
		if err != nil {
			continue // has_cpu, possible, ... share the prefix
		}
		b, err := os.ReadFile(filepath.Join(nodeDir, e.Name(), "cpulist"))
		if err != nil {
			continue
		}
		list, err := parseCPUList(strings.TrimSpace(string(b)))
		if err != nil {
			continue
		}
		for _, c := range list {
			if want[c] {
				out[c] = n
			}
		}
	}
	return out
}

// coreGroups maps each cpu to a dense physical-core id derived from its
// (physical_package_id, core_id) pair — core_id alone repeats across
// sockets. CPUs whose topology files are unreadable get a core of their own.
// The second return is the group id of the core CPU 0 lives on, or -1 when
// that can't be determined; CPU 0's own files are consulted even when 0 is
// not a candidate, so its SMT siblings are recognized under cpusets that
// exclude CPU 0 itself.
func coreGroups(cpuDir string, cpus []int) (map[int]int, int) {
	type pkgCore struct{ pkg, core int }
	pairOf := func(cpu int) (pkgCore, bool) {
		topoDir := filepath.Join(cpuDir, fmt.Sprintf("cpu%d", cpu), "topology")
		pkg, err1 := readIntFile(filepath.Join(topoDir, "physical_package_id"))
		core, err2 := readIntFile(filepath.Join(topoDir, "core_id"))
		if err1 != nil || err2 != nil {
			return pkgCore{}, false
		}
		return pkgCore{pkg, core}, true
	}

	ids := map[pkgCore]int{}
	out := make(map[int]int, len(cpus))
	next := 0
	for _, cpu := range cpus {
		k, ok := pairOf(cpu)
		if !ok {
			out[cpu] = next
			next++
			continue
		}
		id, ok := ids[k]
		if !ok {
			id = next
			next++
			ids[k] = id
		}
		out[cpu] = id
	}

	zeroCore := -1
	if k, ok := pairOf(0); ok {
		if id, ok := ids[k]; ok {
			zeroCore = id
		}
	}
	return out, zeroCore
}
