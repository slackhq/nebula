//go:build linux

package cpupick

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// capacityKeepPct is the cpu_capacity admission threshold, relative to the
// fastest allowed core. LITTLE cores are normalized to ~250-400 of the big
// core's 1024 while mid cores sit at ~75%+, so half of max separates little
// from the rest without splitting prime from mid on three-tier parts.
const capacityKeepPct = 50

// freqKeepPct is the cpuinfo_max_freq admission threshold. Favored-core
// turbo skew is 2-4% and ARM mid-vs-prime ~12%, while E-cores, LITTLE
// cores, and AMD compact cores all sit >= 20% below their siblings' max.
const freqKeepPct = 85

// perfCPUs partitions allowed into the subset that are "performance" cores,
// consulting (in order of authority):
//
//  1. cpu_capacity — arch_topology's normalized per-CPU capacity, exposed on
//     arm/arm64/riscv; the scheduler's own view of big vs LITTLE.
//  2. /sys/devices/cpu_core/cpus — the Intel hybrid P-core PMU mask, present
//     only on P/E parts (x86 has no cpu_capacity) and naming P cores outright.
//  3. cpuinfo_max_freq — the cross-vendor fallback; catches AMD compact
//     cores, which neither of the above covers.
//
// Returns allowed unchanged (signal "") when nothing distinguishes the
// cores: homogeneous parts, VMs without cpufreq, sysfs unavailable.
func perfCPUs(allowed []int) ([]int, string) {
	return perfCPUsFrom("/sys/devices/system/cpu", "/sys/devices/cpu_core/cpus", allowed)
}

func perfCPUsFrom(cpuDir, intelCoreMask string, allowed []int) ([]int, string) {
	if cpus, ok := byPerCPUValue(cpuDir, "cpu_capacity", allowed, capacityKeepPct); ok {
		return cpus, "cpu_capacity"
	}
	if cpus, ok := byIntelCoreMask(intelCoreMask, allowed); ok {
		return cpus, "intel_core_pmu"
	}
	if cpus, ok := byPerCPUValue(cpuDir, "cpufreq/cpuinfo_max_freq", allowed, freqKeepPct); ok {
		return cpus, "max_freq"
	}
	return allowed, ""
}

// byPerCPUValue keeps the allowed CPUs whose per-CPU sysfs value is at least
// keepPct percent of the maximum across allowed. Inconclusive (ok=false)
// when any CPU is missing the file or when every value is equal.
func byPerCPUValue(cpuDir, file string, allowed []int, keepPct int) ([]int, bool) {
	vals := make([]int, len(allowed))
	minV, maxV := 0, 0
	for i, cpu := range allowed {
		v, err := readIntFile(filepath.Join(cpuDir, fmt.Sprintf("cpu%d", cpu), file))
		if err != nil {
			return nil, false
		}
		vals[i] = v
		if i == 0 || v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	if minV == maxV {
		return nil, false // homogeneous by this signal; try the next one
	}
	keep := make([]int, 0, len(allowed))
	for i, cpu := range allowed {
		if vals[i]*100 >= maxV*keepPct {
			keep = append(keep, cpu)
		}
	}
	return keep, true
}

// byIntelCoreMask keeps the allowed CPUs named by the hybrid P-core PMU
// mask. Inconclusive when the file is absent (non-hybrid x86, other arches)
// or no allowed CPU is in the mask (the process was deliberately confined
// to E-cores; nothing useful to prefer within that).
func byIntelCoreMask(maskPath string, allowed []int) ([]int, bool) {
	b, err := os.ReadFile(maskPath)
	if err != nil {
		return nil, false
	}
	set, err := parseCPUList(strings.TrimSpace(string(b)))
	if err != nil || len(set) == 0 {
		return nil, false
	}
	pcore := make(map[int]bool, len(set))
	for _, c := range set {
		pcore[c] = true
	}
	keep := make([]int, 0, len(allowed))
	for _, cpu := range allowed {
		if pcore[cpu] {
			keep = append(keep, cpu)
		}
	}
	if len(keep) == 0 {
		return nil, false
	}
	return keep, true
}

// parseCPUList decodes the kernel's cpulist format ("0-7,16-23", "3") into
// individual CPU IDs. Empty input yields an empty list.
func parseCPUList(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}
	var out []int
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("bad cpulist entry %q: %w", part, err)
		}
		if !isRange {
			out = append(out, a)
			continue
		}
		b, err := strconv.Atoi(hi)
		if err != nil {
			return nil, fmt.Errorf("bad cpulist entry %q: %w", part, err)
		}
		if b < a || b-a > 8192 {
			return nil, fmt.Errorf("bad cpulist range %q", part)
		}
		for v := a; v <= b; v++ {
			out = append(out, v)
		}
	}
	return out, nil
}

func readIntFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
