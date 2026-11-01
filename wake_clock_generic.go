//go:build !linux && !darwin && !windows

package nebula

import "time"

// suspendClockDelta reports that this platform has no usable clock pair for detecting system sleep; the wake
// detector stays dormant and dead tunnels are left to the normal traffic checks.
func suspendClockDelta() (time.Duration, bool) {
	return 0, false
}
