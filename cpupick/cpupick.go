// Package cpupick chooses which CPUs the tun reader threads pin to when the
// operator has not chosen for us (tun.cpu_affinity). The stock spread —
// allowed[i] for routine i — has two failure modes this package exists to fix:
//
//   - every co-located nebula starts its spread at allowed[0], so N instances
//     on one box stack their readers onto the same cores, and allowed[0] is
//     usually CPU 0, the core housekeeping and default IRQ affinity already
//     favor;
//   - on heterogeneous CPUs (ARM big.LITTLE, Intel P/E hybrids, AMD compact
//     cores) low IDs are not necessarily fast cores, and pinning an encrypt
//     thread to an efficiency core caps that queue's throughput.
//
// Default instead returns a preference-ordered pin list: the allowed set
// filtered to performance cores (when the platform distinguishes them and
// enough remain for every routine), confined to a single NUMA node and spread
// across distinct physical cores when the topology permits, CPU 0's physical
// core demoted to last resort, and the order rotated by a stable per-instance
// key so co-located instances spread instead of stacking.
package cpupick

import (
	"log/slog"

	"github.com/slackhq/nebula/util"
)

// topology is the slice of machine layout arrange consults: the NUMA node
// and the physical core behind each candidate CPU, plus which core CPU 0
// lives on (zeroCore, -1 when unknown — tracked separately because CPU 0's
// SMT sibling deserves demotion even when CPU 0 itself isn't a candidate).
// Probed from sysfs on Linux; flatTopology stands in when the platform can't
// say, which turns every topology rule into a no-op rather than a wrong
// answer.
type topology struct {
	nodeOf   map[int]int
	coreOf   map[int]int
	zeroCore int
}

// flatTopology places every CPU on node 0 and on a physical core of its own.
func flatTopology(cpus []int) topology {
	t := topology{
		nodeOf:   make(map[int]int, len(cpus)),
		coreOf:   make(map[int]int, len(cpus)),
		zeroCore: -1,
	}
	for i, c := range cpus {
		t.nodeOf[c] = 0
		t.coreOf[c] = i
		if c == 0 {
			t.zeroCore = i
		}
	}
	return t
}

// Default computes the pin order for `routines` tun readers. key is any
// stable per-instance value; the bound UDP port is ideal — distinct across
// co-located instances, stable across restarts so benchmark runs stay
// comparable. Returns nil when there is nothing useful to say (no affinity
// support on this platform, lookup failure); callers keep their existing
// fallback spread.
func Default(routines int, key uint64, l *slog.Logger) []int {
	allowed, err := util.AllowedCPUs()
	if err != nil || len(allowed) == 0 {
		return nil
	}
	perf, signal := perfCPUs(allowed)
	cands := pickCandidates(allowed, perf, routines)
	if len(cands) == 0 {
		return nil
	}
	if len(perf) < routines {
		signal = ""
	}
	cpus := arrange(cands, readTopology(cands), routines, splitmix64(key))
	if l != nil {
		l.Info("chose default pin CPUs for tun readers",
			"cpus", cpus[:min(routines, len(cpus))],
			"perfSignal", signal)
	}
	return cpus
}

// pickCandidates applies the enough-for-everyone guard: a perf filter that
// leaves fewer candidates than routines is discarded — giving every reader
// its own (possibly slow) core beats stacking two readers on a fast one.
func pickCandidates(allowed, perf []int, routines int) []int {
	if len(perf) < routines {
		return allowed
	}
	return perf
}

// arrange turns the candidate set into the final pin order:
//
//  1. NUMA: when at least one node holds enough candidates for every
//     routine, confine to one such node, chosen by the instance hash. The
//     readers share hostmap and cipher state, so splitting one instance
//     across nodes taxes every packet — and co-located instances that hash
//     to different nodes stop competing entirely. When no node is big
//     enough, span nodes rather than stack readers.
//  2. Rotate the preferred candidates by the hash so instances spread.
//  3. SMT: emit one thread per physical core before any of their siblings —
//     two encrypt threads on one core split its execution units. Siblings
//     still follow for the routines > cores case.
//  4. CPU 0's whole physical core goes last: housekeeping and default IRQ
//     noise on CPU 0 bleeds into its SMT sibling too. Within that tail the
//     sibling precedes CPU 0 itself, which only catches the bleed-through.
//
// The rotation happens before the SMT pass so each instance's one-per-core
// walk also starts at a different core, and CPU 0's core is excluded from
// the rotation so no hash value can put it back at the front.
func arrange(cands []int, topo topology, routines int, h uint64) []int {
	byNode := map[int][]int{}
	var nodes []int
	for _, c := range cands {
		n := topo.nodeOf[c]
		if _, ok := byNode[n]; !ok {
			nodes = append(nodes, n)
		}
		byNode[n] = append(byNode[n], c)
	}
	var eligible []int
	for _, n := range nodes {
		if len(byNode[n]) >= routines {
			eligible = append(eligible, n)
		}
	}
	if len(eligible) > 0 {
		cands = byNode[eligible[int(h%uint64(len(eligible)))]]
	}

	// Split off CPU 0's core: its siblings tail the list, CPU 0 tails them.
	preferred := make([]int, 0, len(cands))
	var zeroTail []int
	hasZero := false
	for _, c := range cands {
		switch {
		case c == 0:
			hasZero = true
		case topo.zeroCore >= 0 && topo.coreOf[c] == topo.zeroCore:
			zeroTail = append(zeroTail, c)
		default:
			preferred = append(preferred, c)
		}
	}
	if hasZero {
		zeroTail = append(zeroTail, 0)
	}
	if len(preferred) == 0 {
		return zeroTail // CPU 0's core is all we have
	}

	// The node pick consumed the low hash bits; rotate by the high ones so
	// the two choices stay independent.
	off := int((h >> 32) % uint64(len(preferred)))
	rot := make([]int, 0, len(preferred))
	rot = append(rot, preferred[off:]...)
	rot = append(rot, preferred[:off]...)

	seenCore := make(map[int]bool, len(rot))
	out := make([]int, 0, len(cands))
	var siblings []int
	for _, c := range rot {
		g := topo.coreOf[c]
		if seenCore[g] {
			siblings = append(siblings, c)
			continue
		}
		seenCore[g] = true
		out = append(out, c)
	}
	out = append(out, siblings...)
	out = append(out, zeroTail...)
	return out
}

// splitmix64 decorrelates instance keys before the selection modulos: ports
// on one box often share spacing (4242/4243, or round steps like +1000) that
// raw key%len arithmetic would fold onto the same offset.
func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}
