package ratelimit

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"
)

// Limiter is a token bucket: `burst` calls are allowed at once, then one more per `every`.
// It counts the calls it denies and hands that count to the next allowed call.
//
// The budget belongs to the Limiter instance.
// Every Allow that returns true spends from it, whatever the caller then does.
//
// Time follows Go's monotonic clock.
//
// Create one Limiter for each thing you want to limit,
// sharing one between unrelated events lets the noisy one starve the quiet one.
//
// Check Allow before doing the work being limited, so a denied call stays cheap:
//
//	if denied, ok := probeLimiter.Allow(); ok {
//		sendProbe()
//		probesDenied.Inc(int64(denied))
//	}
//
// For log lines use logging.RateLimited, which attaches the denied count to the logger as "suppressed".
type Limiter struct {
	every  int64
	slack  int64
	tat    atomic.Int64
	denied atomic.Uint64
}

// maxSpan bounds `burst` * `every` to half of int64, leaving the other half for process uptime so the bucket
// math can't overflow.
const maxSpan = math.MaxInt64 / 2

// New returns a Limiter allowing `burst` calls at once and one more per `every`.
// A `burst` under 1 is 1, and an `every` of 0 or less never limits.
// It returns an error if `burst` * `every` is over about 146 years.
func New(burst int, every time.Duration) (*Limiter, error) {
	l := &Limiter{}
	if every > 0 {
		burst = max(burst, 1)
		if int64(burst) > maxSpan/int64(every) {
			return nil, fmt.Errorf("ratelimit: burst %d * every %v is too long", burst, every)
		}
		l.every = int64(every)
		l.slack = int64(burst-1) * l.every
	}
	return l, nil
}

var monoStart = time.Now()

func monoNow() int64 { return int64(time.Since(monoStart)) }

// Allow reports whether this call is allowed.
// If a token is available it spends it and returns the calls denied since the last allowed one, and true.
// Otherwise it returns 0 and false, and counts the denial.
// A nil Limiter allows everything.
func (l *Limiter) Allow() (uint64, bool) {
	if l == nil {
		return 0, true
	}
	return l.allow(monoNow())
}

// allow is Allow at a given monotonic time.
func (l *Limiter) allow(now int64) (uint64, bool) {
	// Concurrent Allow calls read the clock before racing for the bucket, so one can see a time another already spent
	// past and be denied. An unlimited Limiter must never deny, so it skips the bucket.
	if l.every == 0 {
		return 0, true
	}

	for {
		tat := l.tat.Load()
		next := max(tat, now)
		if next-now > l.slack {
			l.denied.Add(1)
			return 0, false
		}

		if l.tat.CompareAndSwap(tat, next+l.every) {
			return l.denied.Swap(0), true
		}
	}
}
