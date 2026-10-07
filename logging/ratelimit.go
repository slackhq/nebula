package logging

import "log/slog"

// RateLimiter is what RateLimited needs from a rate limiter, such as a *ratelimit.Limiter.
// Allow reports whether this call may proceed, and how many calls were denied since the last one that did.
type RateLimiter interface {
	Allow() (denied uint64, ok bool)
}

// RateLimited checks lim before anything is built.
// When allowed it returns l, with a "suppressed" count attached if lim denied calls since its last allowed one.
// A nil lim allows everything.
//
//	if l, ok := logging.RateLimited(f.l, f.udpTxErrLimiter); ok {
//		hostinfo.logger(l).Error("Failed to write outgoing packet", "error", err)
//	}
func RateLimited(l *slog.Logger, lim RateLimiter) (*slog.Logger, bool) {
	if lim == nil {
		return l, true
	}

	denied, ok := lim.Allow()
	if !ok {
		return nil, false
	}
	if denied > 0 {
		return l.With("suppressed", denied), true
	}
	return l, true
}
