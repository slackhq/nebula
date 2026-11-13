//go:build linux && !android && !e2e_testing

package util

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestAvoidCPUs changes the affinity of the whole process, so it runs in a child, leaving the test runner untouched.
func TestAvoidCPUs(t *testing.T) {
	if os.Getenv("NEBULA_AVOID_CPU_TEST") != "1" {
		exe, err := os.Executable()
		require.NoError(t, err)
		cmd := exec.Command(exe, "-test.run=^TestAvoidCPUs$", "-test.v")
		cmd.Env = append(os.Environ(), "NEBULA_AVOID_CPU_TEST=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		return
	}
	allowed, err := AllowedCPUs()
	require.NoError(t, err)
	if len(allowed) < 2 {
		t.Skip("requires at least two allowed CPUs")
	}
	cpu := allowed[0]
	release := make(chan struct{})
	var wg sync.WaitGroup
	// lockThreads occupies 8 OS threads until release, so the runtime has to start more
	lockThreads := func() {
		var ready sync.WaitGroup
		for range 8 {
			ready.Add(1)
			wg.Go(func() {
				runtime.LockOSThread()
				ready.Done()
				<-release
			})
		}
		ready.Wait()
	}
	lockThreads()

	require.NoError(t, AvoidCPUs([]int{cpu}, false))
	after, err := AllowedCPUs()
	require.NoError(t, err)
	require.Equal(t, allowed, after, "configuration check must not mutate affinity")
	require.Error(t, AvoidCPUs(allowed, true), "must reject an empty mask before applying")
	require.NoError(t, AvoidCPUs([]int{cpu, cpu}, true))
	requireAvoided(t, cpu, allowed)
	// Existing threads stay locked while new ones inherit the restriction
	lockThreads()
	requireAvoided(t, cpu, allowed)
	close(release)
	wg.Wait()
}

// requireAvoided checks no thread may run on cpu, and every thread still may on some CPU of allowed only.
func requireAvoided(t *testing.T, cpu int, allowed []int) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/task")
	require.NoError(t, err)
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		require.NoError(t, err)
		var mask unix.CPUSet
		err = unix.SchedGetaffinity(tid, &mask)
		if err == unix.ESRCH {
			continue
		}
		require.NoError(t, err)
		require.False(t, mask.IsSet(cpu), "thread %d", tid)
		require.Positive(t, mask.Count())
		for id := range len(mask) * 64 {
			if mask.IsSet(id) {
				require.Contains(t, allowed, id, "must not widen the inherited mask")
			}
		}
	}
}

// TestAvoidCPUsRange checks the bounds of unix.CPUSet, whose words are 32 bits wide on 32-bit platforms.
func TestAvoidCPUsRange(t *testing.T) {
	capacity := int(unsafe.Sizeof(unix.CPUSet{})) * 8
	require.NoError(t, AvoidCPUs([]int{capacity - 1}, false))
	require.EqualError(t, AvoidCPUs([]int{capacity}, false), fmt.Sprintf("CPU %d is out of range", capacity))
	require.EqualError(t, AvoidCPUs([]int{-1}, false), "CPU -1 is out of range")
}
