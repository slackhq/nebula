package nebula

import "time"

// wakeDetector notices when the machine has returned from system sleep and measures how long it was suspended.
//
// It samples the spread between two kernel clocks: one that pauses across a suspend and one that keeps counting
// (suspendClockDelta, per platform). While the machine is awake the spread is constant no matter how starved,
// stopped, or stepped this process is — SIGSTOP, debugger pauses, scheduler starvation, and NTP adjustments move
// both clocks together or neither, so none of them can fake a wake. A true suspend is the only thing that grows
// the spread, and it grows by exactly the time spent suspended.
//
// Sample is intended to piggyback on a ticker the caller already runs; it costs two clock reads. It is not safe
// for concurrent use.
type wakeDetector struct {
	// read returns the current spread between the two clocks, false if this platform can't provide one.
	read   func() (time.Duration, bool)
	last   time.Duration
	primed bool
}

func newWakeDetector() *wakeDetector {
	return &wakeDetector{read: suspendClockDelta}
}

// Sample returns how long the machine was suspended since the previous call, 0 if it wasn't, and false if the
// platform has no way to tell. The first call primes the baseline and always reports 0.
func (w *wakeDetector) Sample() (time.Duration, bool) {
	delta, ok := w.read()
	if !ok {
		return 0, false
	}

	if !w.primed {
		w.primed = true
		w.last = delta
		return 0, true
	}

	slept := delta - w.last
	w.last = delta
	if slept < 0 {
		// The clock pair is read non-atomically so tiny negative jitter is possible; it is never a wake.
		slept = 0
	}
	return slept, true
}
