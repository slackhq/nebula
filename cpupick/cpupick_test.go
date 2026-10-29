package cpupick

import (
	"slices"
	"testing"
)

// pairTopo builds a topology where consecutive candidate pairs are SMT
// siblings: (cpus[0],cpus[1]) share a core, (cpus[2],cpus[3]) the next, ...
// All CPUs land on node 0.
func pairTopo(cpus []int) topology {
	t := topology{
		nodeOf:   make(map[int]int, len(cpus)),
		coreOf:   make(map[int]int, len(cpus)),
		zeroCore: -1,
	}
	for i, c := range cpus {
		t.nodeOf[c] = 0
		t.coreOf[c] = i / 2
		if c == 0 {
			t.zeroCore = i / 2
		}
	}
	return t
}

func TestArrangeDemotesZeroForEveryKey(t *testing.T) {
	candidates := []int{0, 1, 2, 3, 4, 5, 6, 7}
	for key := range uint64(64) {
		got := arrange(candidates, flatTopology(candidates), 4, splitmix64(key))
		if len(got) != len(candidates) {
			t.Fatalf("key %d: len=%d want %d", key, len(got), len(candidates))
		}
		if got[0] == 0 {
			t.Errorf("key %d: CPU 0 at the front: %v", key, got)
		}
		if got[len(got)-1] != 0 {
			t.Errorf("key %d: CPU 0 not demoted to last: %v", key, got)
		}
		sorted := slices.Clone(got)
		slices.Sort(sorted)
		if !slices.Equal(sorted, candidates) {
			t.Errorf("key %d: not a permutation: %v", key, got)
		}
	}
}

func TestArrangeDemotesZeroSiblings(t *testing.T) {
	// Pairs (0,1),(2,3),(4,5),(6,7): CPU 0's core — 0 and its sibling 1 —
	// must tail the list, sibling ahead of 0 itself.
	candidates := []int{0, 1, 2, 3, 4, 5, 6, 7}
	for key := range uint64(64) {
		got := arrange(candidates, pairTopo(candidates), 2, splitmix64(key))
		n := len(got)
		if got[n-1] != 0 || got[n-2] != 1 {
			t.Fatalf("key %d: tail = %v, want [... 1 0]", key, got)
		}
	}
}

func TestArrangeZeroSiblingWithoutZero(t *testing.T) {
	// CPU 0 excluded (cpuset) but its sibling 1 remains: the sibling still
	// tails the list when the topology knows which core CPU 0 lives on.
	candidates := []int{1, 2, 3, 4, 5}
	topo := pairTopo([]int{0, 1, 2, 3, 4, 5})
	got := arrange(candidates, topo, 2, splitmix64(7))
	if got[len(got)-1] != 1 {
		t.Errorf("CPU 0's sibling not demoted: %v", got)
	}
}

func TestArrangeRotatesByKey(t *testing.T) {
	candidates := []int{1, 2, 3, 4, 5, 6, 7, 8}
	seen := map[int]bool{}
	for key := range uint64(64) {
		seen[arrange(candidates, flatTopology(candidates), 4, splitmix64(key))[0]] = true
	}
	// 64 hashed keys over 8 slots must hit more than one starting CPU, or
	// co-located instances would all stack again.
	if len(seen) < 2 {
		t.Errorf("rotation never varied across keys: %v", seen)
	}
}

func TestArrangeStableForSameKey(t *testing.T) {
	candidates := []int{0, 2, 4, 6}
	topo := flatTopology(candidates)
	a := arrange(candidates, topo, 2, splitmix64(4242))
	b := arrange(candidates, topo, 2, splitmix64(4242))
	if !slices.Equal(a, b) {
		t.Errorf("same key ordered differently: %v vs %v", a, b)
	}
}

func TestArrangeZeroOnly(t *testing.T) {
	if got := arrange([]int{0}, flatTopology([]int{0}), 1, splitmix64(7)); !slices.Equal(got, []int{0}) {
		t.Errorf("sole CPU 0 must survive: %v", got)
	}
}

func TestArrangeSMTSiblingsLast(t *testing.T) {
	// Pairs (1,2),(3,4),(5,6),(7,8): the first four picks must cover four
	// distinct physical cores before any sibling repeats.
	candidates := []int{1, 2, 3, 4, 5, 6, 7, 8}
	topo := pairTopo(candidates)
	for key := range uint64(16) {
		got := arrange(candidates, topo, 4, splitmix64(key))
		seen := map[int]bool{}
		for _, c := range got[:4] {
			g := topo.coreOf[c]
			if seen[g] {
				t.Fatalf("key %d: sibling before all cores covered: %v", key, got)
			}
			seen[g] = true
		}
	}
}

func TestArrangeNUMAConfinesToOneNode(t *testing.T) {
	// Two nodes of four; both fit routines=3, so the result must sit
	// entirely inside one of them, and the hash must pick both across keys.
	candidates := []int{1, 2, 3, 4, 10, 11, 12, 13}
	topo := flatTopology(candidates)
	for _, c := range []int{10, 11, 12, 13} {
		topo.nodeOf[c] = 1
	}
	nodesSeen := map[int]bool{}
	for key := range uint64(32) {
		got := arrange(candidates, topo, 3, splitmix64(key))
		if len(got) != 4 {
			t.Fatalf("key %d: not confined to one node: %v", key, got)
		}
		n := topo.nodeOf[got[0]]
		for _, c := range got {
			if topo.nodeOf[c] != n {
				t.Fatalf("key %d: spans nodes: %v", key, got)
			}
		}
		nodesSeen[n] = true
	}
	if len(nodesSeen) != 2 {
		t.Errorf("hash never spread instances across nodes: %v", nodesSeen)
	}
}

func TestArrangeNUMASpansWhenNoNodeFits(t *testing.T) {
	candidates := []int{1, 2, 3, 4, 10, 11, 12, 13}
	topo := flatTopology(candidates)
	for _, c := range []int{10, 11, 12, 13} {
		topo.nodeOf[c] = 1
	}
	got := arrange(candidates, topo, 6, splitmix64(1))
	if len(got) != len(candidates) {
		t.Errorf("undersized nodes must span, got %v", got)
	}
}

func TestPickCandidates(t *testing.T) {
	allowed := []int{0, 1, 2, 3, 4, 5, 6, 7}
	perf := []int{4, 5}

	// Enough perf cores for every routine: only they are used.
	if got := pickCandidates(allowed, perf, 2); !slices.Equal(got, perf) {
		t.Errorf("perf filter not applied: %v", got)
	}
	// Perf filter too small for the routine count: discarded, everyone
	// gets their own core from the full allowed set.
	if got := pickCandidates(allowed, perf, 4); !slices.Equal(got, allowed) {
		t.Errorf("undersized perf filter not discarded: %v", got)
	}
}
