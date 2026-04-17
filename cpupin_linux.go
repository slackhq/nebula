//go:build linux && !android && !e2e_testing

package nebula

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// pinThreadToCPU restricts the calling OS thread to the given CPU via
// sched_setaffinity(2). Combined with runtime.LockOSThread on the
// goroutine, this prevents the kernel from migrating us across CPUs and
// in turn keeps every sendmmsg from this goroutine going through the
// same XPS-selected TX ring, eliminating the wire-side reorder that
// otherwise fragments one nebula flow across multiple rings.
func pinThreadToCPU(cpu int) error {
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Zero()
	set.Set(cpu)
	return unix.SchedSetaffinity(0, &set)
}
