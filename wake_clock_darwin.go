//go:build darwin

package nebula

import (
	"time"

	"golang.org/x/sys/unix"
)

// suspendClockDelta returns CLOCK_MONOTONIC - CLOCK_UPTIME_RAW. On macOS CLOCK_MONOTONIC keeps counting across
// system sleep while CLOCK_UPTIME_RAW (mach_absolute_time) pauses, so the difference grows by time spent asleep.
//
// The pausing clock is read first so scheduling jitter between the two reads biases the delta positive; the
// wakeDetector clamps out the noise.
//
// Caveat: on Apple Silicon the hardware timebase keeps ticking through sleep, which can make both clocks advance
// and the spread stay flat, leaving this detector blind. That fails safe (no clears, behavior as before); IOKit
// power notifications are the follow-up for full coverage on those machines.
func suspendClockDelta() (time.Duration, bool) {
	var uptime, mono unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_UPTIME_RAW, &uptime); err != nil {
		return 0, false
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		return 0, false
	}
	return time.Duration(mono.Nano() - uptime.Nano()), true
}
