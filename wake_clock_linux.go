//go:build linux

package nebula

import (
	"time"

	"golang.org/x/sys/unix"
)

// suspendClockDelta returns CLOCK_BOOTTIME - CLOCK_MONOTONIC. CLOCK_MONOTONIC pauses while the system is suspended
// and CLOCK_BOOTTIME does not, so the difference only ever grows, and only by time spent suspended. Both reads are
// vDSO calls, cheap enough for a hot ticker.
//
// The pausing clock is read first so scheduling jitter between the two reads biases the delta positive; the
// wakeDetector clamps out the noise.
func suspendClockDelta() (time.Duration, bool) {
	var mono, boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		return 0, false
	}
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return 0, false
	}
	return time.Duration(boot.Nano() - mono.Nano()), true
}
