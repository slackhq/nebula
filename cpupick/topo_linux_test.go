//go:build linux

package cpupick

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// fakeTopoSysfs builds nodeDir/cpuDir trees. nodes maps node id -> cpulist
// string; cores maps cpu -> (package, core) pair.
func fakeTopoSysfs(t *testing.T, nodes map[int]string, cores map[int][2]int) (string, string) {
	t.Helper()
	base := t.TempDir()
	nodeDir := filepath.Join(base, "node")
	cpuDir := filepath.Join(base, "cpu")
	for n, list := range nodes {
		d := filepath.Join(nodeDir, fmt.Sprintf("node%d", n))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "cpulist"), []byte(list+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for cpu, pc := range cores {
		d := filepath.Join(cpuDir, fmt.Sprintf("cpu%d", cpu), "topology")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "physical_package_id"), fmt.Appendf(nil, "%d\n", pc[0]), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "core_id"), fmt.Appendf(nil, "%d\n", pc[1]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return nodeDir, cpuDir
}

func TestReadTopology(t *testing.T) {
	// Two nodes; SMT pairs (0,4),(1,5) on node 0 and (2,6),(3,7) on node 1.
	// core_id repeats across packages on purpose: the pair must disambiguate.
	nodeDir, cpuDir := fakeTopoSysfs(t,
		map[int]string{0: "0-1,4-5", 1: "2-3,6-7"},
		map[int][2]int{
			0: {0, 0}, 4: {0, 0}, 1: {0, 1}, 5: {0, 1},
			2: {1, 0}, 6: {1, 0}, 3: {1, 1}, 7: {1, 1},
		})
	cpus := []int{0, 1, 2, 3, 4, 5, 6, 7}
	topo := readTopologyFrom(nodeDir, cpuDir, cpus)

	for _, c := range []int{0, 1, 4, 5} {
		if topo.nodeOf[c] != 0 {
			t.Errorf("cpu %d on node %d, want 0", c, topo.nodeOf[c])
		}
	}
	for _, c := range []int{2, 3, 6, 7} {
		if topo.nodeOf[c] != 1 {
			t.Errorf("cpu %d on node %d, want 1", c, topo.nodeOf[c])
		}
	}
	pairs := [][2]int{{0, 4}, {1, 5}, {2, 6}, {3, 7}}
	for _, p := range pairs {
		if topo.coreOf[p[0]] != topo.coreOf[p[1]] {
			t.Errorf("siblings %v not grouped: %d vs %d", p, topo.coreOf[p[0]], topo.coreOf[p[1]])
		}
	}
	if topo.coreOf[0] == topo.coreOf[2] {
		t.Error("cross-package cores with equal core_id must not merge")
	}
	if topo.zeroCore != topo.coreOf[0] {
		t.Errorf("zeroCore = %d, want %d", topo.zeroCore, topo.coreOf[0])
	}
}

func TestReadTopologyZeroCoreWithoutZeroCandidate(t *testing.T) {
	// CPU 0 is not a candidate (cpuset excludes it) but its sibling 4 is:
	// zeroCore must still identify their shared core.
	nodeDir, cpuDir := fakeTopoSysfs(t,
		map[int]string{0: "0-7"},
		map[int][2]int{0: {0, 0}, 4: {0, 0}, 1: {0, 1}, 5: {0, 1}})
	topo := readTopologyFrom(nodeDir, cpuDir, []int{1, 4, 5})
	if topo.zeroCore < 0 || topo.coreOf[4] != topo.zeroCore {
		t.Errorf("zeroCore = %d, coreOf[4] = %d; sibling of CPU 0 not identified", topo.zeroCore, topo.coreOf[4])
	}
	if topo.coreOf[1] == topo.zeroCore {
		t.Error("cpu 1 wrongly grouped with CPU 0's core")
	}
}

func TestReadTopologyMissingSysfs(t *testing.T) {
	base := t.TempDir()
	cpus := []int{0, 1, 2}
	topo := readTopologyFrom(filepath.Join(base, "nope"), filepath.Join(base, "also-nope"), cpus)
	seen := map[int]bool{}
	for _, c := range cpus {
		if topo.nodeOf[c] != 0 {
			t.Errorf("cpu %d node = %d, want 0", c, topo.nodeOf[c])
		}
		if seen[topo.coreOf[c]] {
			t.Errorf("cpu %d shares a fallback core group", c)
		}
		seen[topo.coreOf[c]] = true
	}
	if topo.zeroCore != -1 {
		t.Errorf("zeroCore = %d, want -1 when unknown", topo.zeroCore)
	}
}
