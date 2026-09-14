//go:build linux

package cpupick

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// fakeSysfs builds a cpuDir tree with the given per-CPU file values.
// A nil map for a file means "file absent on every CPU".
func fakeSysfs(t *testing.T, capacity, maxFreq map[int]int) string {
	t.Helper()
	dir := t.TempDir()
	write := func(cpu int, rel string, v int) {
		p := filepath.Join(dir, fmt.Sprintf("cpu%d", cpu), rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, fmt.Appendf(nil, "%d\n", v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for cpu, v := range capacity {
		write(cpu, "cpu_capacity", v)
	}
	for cpu, v := range maxFreq {
		write(cpu, "cpufreq/cpuinfo_max_freq", v)
	}
	return dir
}

func writeCoreMask(t *testing.T, mask string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cpus")
	if err := os.WriteFile(p, []byte(mask+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPerfCPUsBigLittleCapacity(t *testing.T) {
	// 4 big (1024) + 4 LITTLE (~290): capacity is authoritative on ARM.
	dir := fakeSysfs(t, map[int]int{
		0: 1024, 1: 1024, 2: 1024, 3: 1024,
		4: 290, 5: 290, 6: 290, 7: 290,
	}, nil)
	got, signal := perfCPUsFrom(dir, filepath.Join(dir, "nope"), []int{0, 1, 2, 3, 4, 5, 6, 7})
	if signal != "cpu_capacity" {
		t.Fatalf("signal = %q", signal)
	}
	if !slices.Equal(got, []int{0, 1, 2, 3}) {
		t.Errorf("got %v", got)
	}
}

func TestPerfCPUsThreeTierKeepsMid(t *testing.T) {
	// prime (1024) + mid (~780) + little (~280): 50% keeps prime+mid.
	dir := fakeSysfs(t, map[int]int{
		0: 280, 1: 280, 2: 280, 3: 280,
		4: 780, 5: 780, 6: 780,
		7: 1024,
	}, nil)
	got, _ := perfCPUsFrom(dir, filepath.Join(dir, "nope"), []int{0, 1, 2, 3, 4, 5, 6, 7})
	if !slices.Equal(got, []int{4, 5, 6, 7}) {
		t.Errorf("got %v", got)
	}
}

func TestPerfCPUsIntelHybridMask(t *testing.T) {
	// No cpu_capacity on x86; the P-core PMU mask decides.
	dir := fakeSysfs(t, nil, nil)
	mask := writeCoreMask(t, "0-7")
	got, signal := perfCPUsFrom(dir, mask, []int{0, 1, 2, 3, 8, 9, 10, 11})
	if signal != "intel_core_pmu" {
		t.Fatalf("signal = %q", signal)
	}
	if !slices.Equal(got, []int{0, 1, 2, 3}) {
		t.Errorf("got %v", got)
	}
}

func TestPerfCPUsIntelMaskDisjointFallsThrough(t *testing.T) {
	// Confined to E-cores only: the mask can't help, and equal freqs below
	// mean nothing else distinguishes them either -> allowed unchanged.
	dir := fakeSysfs(t, nil, map[int]int{8: 4300000, 9: 4300000})
	mask := writeCoreMask(t, "0-7")
	got, signal := perfCPUsFrom(dir, mask, []int{8, 9})
	if signal != "" || !slices.Equal(got, []int{8, 9}) {
		t.Errorf("got %v signal %q", got, signal)
	}
}

func TestPerfCPUsMaxFreqCompactCores(t *testing.T) {
	// AMD-style compact cores: no capacity, no Intel mask; 3.3 vs 5.7 GHz.
	dir := fakeSysfs(t, nil, map[int]int{
		0: 5700000, 1: 5700000, 2: 3300000, 3: 3300000,
	})
	got, signal := perfCPUsFrom(dir, filepath.Join(dir, "nope"), []int{0, 1, 2, 3})
	if signal != "max_freq" {
		t.Fatalf("signal = %q", signal)
	}
	if !slices.Equal(got, []int{0, 1}) {
		t.Errorf("got %v", got)
	}
}

func TestPerfCPUsFavoredCoreSkewKept(t *testing.T) {
	// Turbo Boost Max favored cores run a few percent hot; they must not
	// shrink the candidate set to one or two cores.
	dir := fakeSysfs(t, nil, map[int]int{
		0: 5800000, 1: 5700000, 2: 5700000, 3: 5600000,
	})
	got, _ := perfCPUsFrom(dir, filepath.Join(dir, "nope"), []int{0, 1, 2, 3})
	if !slices.Equal(got, []int{0, 1, 2, 3}) {
		t.Errorf("favored-core skew filtered CPUs: %v", got)
	}
}

func TestPerfCPUsHomogeneousInconclusive(t *testing.T) {
	dir := fakeSysfs(t, nil, map[int]int{0: 3000000, 1: 3000000})
	got, signal := perfCPUsFrom(dir, filepath.Join(dir, "nope"), []int{0, 1})
	if signal != "" || !slices.Equal(got, []int{0, 1}) {
		t.Errorf("got %v signal %q", got, signal)
	}
}

func TestPerfCPUsNoSysfs(t *testing.T) {
	dir := t.TempDir()
	got, signal := perfCPUsFrom(dir, filepath.Join(dir, "nope"), []int{0, 1, 2})
	if signal != "" || !slices.Equal(got, []int{0, 1, 2}) {
		t.Errorf("got %v signal %q", got, signal)
	}
}

func TestParseCPUList(t *testing.T) {
	cases := []struct {
		in      string
		want    []int
		wantErr bool
	}{
		{"0-3", []int{0, 1, 2, 3}, false},
		{"0-1,16-17", []int{0, 1, 16, 17}, false},
		{"5", []int{5}, false},
		{"", nil, false},
		{"3-1", nil, true},
		{"a-b", nil, true},
		{"1,x", nil, true},
	}
	for _, c := range cases {
		got, err := parseCPUList(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%q: err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && !slices.Equal(got, c.want) {
			t.Errorf("%q: got %v want %v", c.in, got, c.want)
		}
	}
}
