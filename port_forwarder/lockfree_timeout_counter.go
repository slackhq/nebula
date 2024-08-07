package port_forwarder

import "sync/atomic"

type TimeoutCounter struct {
	counter   atomic.Uint32
	threshold uint32
}

func NewTimeoutCounter(threshold uint32) TimeoutCounter {
	return TimeoutCounter{
		counter:   atomic.Uint32{},
		threshold: threshold,
	}
}

func (tc *TimeoutCounter) Increment(step uint32) bool {
	tc.counter.Add(step)
	return tc.IsTimeout()
}

func (tc *TimeoutCounter) Reset() {
	tc.counter.Store(0)
}

func (tc *TimeoutCounter) IsTimeout() bool {
	return tc.counter.Load() > tc.threshold
}

type TimedConnection[C any] struct {
	connection      C
	timeout_counter TimeoutCounter
}
