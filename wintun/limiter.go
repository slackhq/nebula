package wintun

import "time"

const (
	// defaultMaxSessionResets bounds in-process recovery from Wintun send-ring
	// corruption (a known race in wintun.sys 0.14.1 under concurrent sends).
	// Exceeding this within defaultSessionResetWindow trips the limiter so
	// Nebula tears down cleanly rather than flapping the link in a tight loop.
	defaultMaxSessionResets   = 5
	defaultSessionResetWindow = 10 * time.Second
)

// resetLimiter tracks session reset timestamps over a sliding time window.
// Callers must serialize access.
type resetLimiter struct {
	maxResets int
	window    time.Duration
	now       func() time.Time
	times     []time.Time
}

func newResetLimiter(maxResets int, window time.Duration, now func() time.Time) resetLimiter {
	if now == nil {
		now = time.Now
	}
	var times []time.Time
	if maxResets > 0 {
		times = make([]time.Time, 0, maxResets)
	}
	return resetLimiter{
		maxResets: maxResets,
		window:    window,
		now:       now,
		times:     times,
	}
}

func (l *resetLimiter) allow() bool {
	if l.maxResets <= 0 || l.window <= 0 {
		return false
	}
	now := l.now()
	keep := 0
	for _, t := range l.times {
		if now.Sub(t) < l.window {
			l.times[keep] = t
			keep++
		}
	}
	l.times = l.times[:keep]
	if len(l.times) >= l.maxResets {
		return false
	}
	l.times = append(l.times, now)
	return true
}
