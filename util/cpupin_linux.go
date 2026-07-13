//go:build linux && !android && !e2e_testing

package util

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// PinThreadToCPU restricts the calling OS thread to the given CPU via
// sched_setaffinity(2). Combined with runtime.LockOSThread on the
// goroutine, this prevents the kernel from migrating us across CPUs and
// in turn keeps every sendmmsg from this goroutine going through the
// same XPS-selected TX ring, eliminating the wire-side reorder that
// otherwise fragments one nebula flow across multiple rings.
func PinThreadToCPU(cpu int) error {
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Zero()
	set.Set(cpu)
	return unix.SchedSetaffinity(0, &set)
}

// AllowedCPUs returns the CPU IDs the calling process is currently allowed to
// run on, as reported by sched_getaffinity(2). Under a cgroup cpuset or a
// `taskset` mask the allowed IDs are frequently not the contiguous range
// 0..NumCPU-1 (e.g. pinned to CPUs 4-7: NumCPU reports 4 while the valid IDs
// are 4,5,6,7). Callers that need a real CPU to pin to must choose from this
// set rather than assuming i % NumCPU is runnable, or every pin fails.
func AllowedCPUs() ([]int, error) {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return nil, err
	}
	cpus := make([]int, 0, set.Count())
	for cpu := 0; cpu < len(set)*64; cpu++ {
		if set.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	return cpus, nil
}
