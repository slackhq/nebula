//go:build linux && !android && !e2e_testing

package cpupick

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Avoid removes cpus from the affinity of every thread of the process, for use at startup. New threads inherit
// their parent's mask, so it repeats until a pass finds nothing left to change; a thread that exits meanwhile is
// skipped. Every mask is checked before any is changed. With apply false it only validates, for configuration tests.
// This affects the entire process, including other users of an embedded Nebula. Not wired up yet: tun.avoid_cpus
// only steers Default for now.
func Avoid(cpus []int, apply bool) error {
	const capacity = int(unsafe.Sizeof(unix.CPUSet{})) * 8
	for _, cpu := range cpus {
		if cpu < 0 || cpu >= capacity {
			return fmt.Errorf("CPU %d is out of range", cpu)
		}
	}
	if len(cpus) == 0 {
		return nil
	}
	for {
		masks, err := avoidingMasks(cpus)
		if err != nil || !apply || len(masks) == 0 {
			return err
		}
		for tid, mask := range masks {
			if err := unix.SchedSetaffinity(tid, &mask); err != nil && !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("set thread %d affinity: %w", tid, err)
			}
		}
	}
}

// avoidingMasks returns the mask without cpus of every thread whose mask has any of them.
func avoidingMasks(cpus []int) (map[int]unix.CPUSet, error) {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil, err
	}
	masks := make(map[int]unix.CPUSet, len(entries))
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			return nil, err
		}
		var mask unix.CPUSet
		err = unix.SchedGetaffinity(tid, &mask)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read thread %d affinity: %w", tid, err)
		}
		next := mask
		for _, cpu := range cpus {
			next.Clear(cpu)
		}
		if next.Count() == 0 {
			return nil, fmt.Errorf("avoid_cpus leaves thread %d with no allowed CPU", tid)
		}
		if next != mask {
			masks[tid] = next
		}
	}
	return masks, nil
}
