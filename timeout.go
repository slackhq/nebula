package nebula

import (
	"sync"
	"time"
)

// How many timer objects should be cached
const timerCacheMax = 50000

type TimerWheel[T any] struct {
	// Current tick
	current int

	// Cheat on finding the length of the wheel
	wheelLen int

	// Last time we ticked, since we are lazy ticking
	lastTick *time.Time

	// Durations of a tick and the entire wheel
	tickDuration  time.Duration
	wheelDuration time.Duration

	// The actual wheel which is just a set of singly linked lists, head/tail pointers
	wheel []*TimeoutList[T]

	// Singly linked list of items that have timed out of the wheel
	expired *TimeoutList[T]

	// Item cache to avoid garbage collect
	itemCache   *TimeoutItem[T]
	itemsCached int
}

type LockingTimerWheel[T any] struct {
	m sync.Mutex
	t *TimerWheel[T]
}

// TimeoutList Represents a tick in the wheel
type TimeoutList[T any] struct {
	Head *TimeoutItem[T]
	Tail *TimeoutItem[T]
}

// TimeoutItem Represents an item within a tick
type TimeoutItem[T any] struct {
	Item T
	Next *TimeoutItem[T]
}

// NewTimerWheel Builds a timer wheel and identifies the tick duration and wheel duration from the provided values
// Purge must be called once per entry to actually remove anything
// The TimerWheel does not handle concurrency on its own.
// Locks around access to it must be used if multiple routines are manipulating it.
func NewTimerWheel[T any](min, max time.Duration) *TimerWheel[T] {
	//TODO provide an error
	//if min >= max {
	//	return nil
	//}

	// Round down and add 2 so we can have the smallest # of ticks in the wheel and still account for a full
	// max duration, even if our current tick is at the maximum position and the next item to be added is at maximum
	// timeout
	wLen := int((max / min) + 2)

	tw := TimerWheel[T]{
		wheelLen:      wLen,
		wheel:         make([]*TimeoutList[T], wLen),
		tickDuration:  min,
		wheelDuration: max,
		expired:       &TimeoutList[T]{},
	}

	for i := range tw.wheel {
		tw.wheel[i] = &TimeoutList[T]{}
	}

	return &tw
}

// NewLockingTimerWheel is version of TimerWheel that is safe for concurrent use with a small performance penalty
func NewLockingTimerWheel[T any](min, max time.Duration) *LockingTimerWheel[T] {
	return &LockingTimerWheel[T]{
		t: NewTimerWheel[T](min, max),
	}
}

// Add will add an item to the wheel in its proper timeout.
// Caller should Advance the wheel prior to ensure the proper slot is used.
func (tw *TimerWheel[T]) Add(v T, timeout time.Duration) *TimeoutItem[T] {
	i := tw.findWheel(timeout)

	// Try to fetch off the cache
	ti := tw.itemCache
	if ti != nil {
		tw.itemCache = ti.Next
		tw.itemsCached--
		ti.Next = nil
	} else {
		ti = &TimeoutItem[T]{}
	}

	// Relink and return
	ti.Item = v
	if tw.wheel[i].Tail == nil {
		tw.wheel[i].Head = ti
		tw.wheel[i].Tail = ti
	} else {
		tw.wheel[i].Tail.Next = ti
		tw.wheel[i].Tail = ti
	}

	return ti
}

// Purge removes and returns the first available expired item from the wheel and the 2nd argument is true.
// If no item is available then an empty T is returned and the 2nd argument is false.
func (tw *TimerWheel[T]) Purge() (T, bool) {
	if tw.expired.Head == nil {
		var na T
		return na, false
	}

	ti := tw.expired.Head
	tw.expired.Head = ti.Next

	if tw.expired.Head == nil {
		tw.expired.Tail = nil
	}

	// Clear out the items references
	ti.Next = nil

	// Maybe cache it for later
	if tw.itemsCached < timerCacheMax {
		ti.Next = tw.itemCache
		tw.itemCache = ti
		tw.itemsCached++
	}

	return ti.Item, true
}

// findWheel find the next position in the wheel for the provided timeout given the current tick
func (tw *TimerWheel[T]) findWheel(timeout time.Duration) (i int) {
	if timeout < tw.tickDuration {
		// Can't track anything below the set resolution
		timeout = tw.tickDuration
	} else if timeout > tw.wheelDuration {
		// We aren't handling timeouts greater than the wheels duration
		timeout = tw.wheelDuration
	}

	// Find the next highest, rounding up
	tick := int(((timeout - 1) / tw.tickDuration) + 1)

	// Add another tick since the current tick may almost be over then map it to the wheel from our
	// current position
	tick += tw.current + 1
	if tick >= tw.wheelLen {
		tick -= tw.wheelLen
	}

	return tick
}

// Advance will move the wheel forward by the appropriate number of ticks for the provided time and all items
// passed over will be moved to the expired list. Calling Purge is necessary to remove them entirely.
func (tw *TimerWheel[T]) Advance(now time.Time) {
	if tw.lastTick == nil {
		tw.lastTick = &now
	}

	// We want to round down
	ticks := int(now.Sub(*tw.lastTick) / tw.tickDuration)
	adv := ticks
	if ticks > tw.wheelLen {
		ticks = tw.wheelLen
	}

	for i := 0; i < ticks; i++ {
		tw.current++
		if tw.current >= tw.wheelLen {
			tw.current = 0
		}

		if tw.wheel[tw.current].Head != nil {
			// We need to append the expired items as to not starve evicting the oldest ones
			if tw.expired.Tail == nil {
				tw.expired.Head = tw.wheel[tw.current].Head
				tw.expired.Tail = tw.wheel[tw.current].Tail
			} else {
				tw.expired.Tail.Next = tw.wheel[tw.current].Head
				tw.expired.Tail = tw.wheel[tw.current].Tail
			}

			tw.wheel[tw.current].Head = nil
			tw.wheel[tw.current].Tail = nil
		}
	}

	// Advance the tick based on duration to avoid losing some accuracy
	newTick := tw.lastTick.Add(tw.tickDuration * time.Duration(adv))
	tw.lastTick = &newTick
}

func (lw *LockingTimerWheel[T]) Add(v T, timeout time.Duration) *TimeoutItem[T] {
	lw.m.Lock()
	defer lw.m.Unlock()
	return lw.t.Add(v, timeout)
}

func (lw *LockingTimerWheel[T]) Purge() (T, bool) {
	lw.m.Lock()
	defer lw.m.Unlock()
	return lw.t.Purge()
}

func (lw *LockingTimerWheel[T]) Advance(now time.Time) {
	lw.m.Lock()
	defer lw.m.Unlock()
	lw.t.Advance(now)
}
