package nebula

import (
	"context"
	"sync"
	"time"
)

// Scheduler is an allocation-conscious dispatch primitive for delayed work.
// Pending items are handed to time.AfterFunc, and ready items land on a worker
// channel for centralized dispatch in fire-time order.
//
// Pick a Scheduler when fire timing matters (exact deadlines, no bucketing) or when the scheduling
// rate is uneven enough that idle CPU matters. Each fire is a runtime-spawned goroutine running the callback before
// delivering to the worker, which is fine at sparse rates but adds up at line rate.
//
// Pick a TimerWheel when scheduling is high-rate and uniform: its O(1) insert, internal item cache,
// and bucket-batched dispatch are cheaper at scale.
// The caller drives the tick loop (Advance/Purge) and pays for fires at bucket boundaries rather than exact deadlines.
type Scheduler[T any] struct {
	queue chan T
	pool  sync.Pool
}

type schedItem[T any] struct {
	val   T
	ctx   context.Context
	s     *Scheduler[T]
	timer *time.Timer
	fire  func()
}

// NewScheduler builds a Scheduler whose worker channel is sized to queueSize.
// The buffer absorbs bursts of timers firing close together without
// blocking the runtime's callback goroutines on the worker.
func NewScheduler[T any](queueSize int) *Scheduler[T] {
	s := &Scheduler[T]{
		queue: make(chan T, queueSize),
	}
	s.pool.New = func() any {
		si := &schedItem[T]{s: s}
		// fire is allocated exactly once per pool-resident item.
		// The closure captures only `si`, which stays stable for the item's lifetime.
		si.fire = func() {
			select {
			case si.s.queue <- si.val:
			case <-si.ctx.Done():
			}
			var zero T
			si.val = zero
			si.ctx = nil
			si.s.pool.Put(si)
		}
		return si
	}
	return s
}

// Schedule arranges item to be delivered to the worker after delay.
// The runtime's timer heap handles the wait, so the scheduler itself burns no CPU while idle.
// The callback observes ctx: if ctx is cancelled before the timer fires, the item is dropped instead of queued.
func (s *Scheduler[T]) Schedule(ctx context.Context, item T, delay time.Duration) {
	si := s.pool.Get().(*schedItem[T])
	si.val = item
	si.ctx = ctx
	if si.timer == nil {
		si.timer = time.AfterFunc(delay, si.fire)
	} else {
		si.timer.Reset(delay)
	}
}

// Run drains the worker queue, calling fn for each item. Returns when ctx is cancelled.
// Tests that want deterministic timing should drive the queue directly rather than going through Schedule + Run.
func (s *Scheduler[T]) Run(ctx context.Context, fn func(T)) {
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-s.queue:
			fn(item)
		}
	}
}
