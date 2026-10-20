//go:build windows

package nebula

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procQueryInterruptTime         = windows.NewLazySystemDLL("kernelbase.dll").NewProc("QueryInterruptTime")
	procQueryUnbiasedInterruptTime = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryUnbiasedInterruptTime")

	// QueryInterruptTime needs Windows 10; probe once and stay dormant on anything older.
	wakeClockAvailable = sync.OnceValue(func() bool {
		return procQueryInterruptTime.Find() == nil && procQueryUnbiasedInterruptTime.Find() == nil
	})
)

// suspendClockDelta returns interrupt time minus unbiased interrupt time, both in 100ns units. The unbiased count
// excludes time the system spends suspended while the biased one includes it, so the difference grows by exactly
// the time spent asleep.
//
// The pausing (unbiased) clock is read first so scheduling jitter between the two reads biases the delta positive;
// the wakeDetector clamps out the noise.
func suspendClockDelta() (time.Duration, bool) {
	if !wakeClockAvailable() {
		return 0, false
	}

	var unbiased, biased uint64
	if r1, _, _ := procQueryUnbiasedInterruptTime.Call(uintptr(unsafe.Pointer(&unbiased))); r1 == 0 {
		return 0, false
	}
	// Returns void, cannot fail once resolved.
	_, _, _ = procQueryInterruptTime.Call(uintptr(unsafe.Pointer(&biased)))
	return time.Duration(int64(biased-unbiased)) * 100, true
}
