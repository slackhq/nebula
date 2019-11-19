package nebula

import (
	"sync"
	"time"
)

// How many timer objects should be cached
const systemTimerCacheMax = 50000

type SystemTimerWheel struct {
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
	wheel []*SystemTimeoutList

	// Singly linked list of items that have timed out of the wheel
	expired *SystemTimeoutList

	// Item cache to avoid garbage collect
	itemCache   *SystemTimeoutItem
	itemsCached int

	lock sync.Mutex
}

// Represents a tick in the wheel
type SystemTimeoutList struct {
	Head *SystemTimeoutItem
	Tail *SystemTimeoutItem
}

// Represents an item within a tick
type SystemTimeoutItem struct {
	Item uint32
	Next *SystemTimeoutItem
}

// Builds a timer wheel and identifies the tick duration and wheel duration from the provided values
// Purge must be called once per entry to actually remove anything
func NewSystemTimerWheel(min, max time.Duration) *SystemTimerWheel {
	//TODO provide an error
	//if min >= max {
	//	return nil
	//}

	// Round down and add 1 so we can have the smallest # of ticks in the wheel and still account for a full
	// max duration
	wLen := int((max / min) + 1)

	tw := SystemTimerWheel{
		wheelLen:      wLen,
		wheel:         make([]*SystemTimeoutList, wLen),
		tickDuration:  min,
		wheelDuration: max,
		expired:       &SystemTimeoutList{},
	}

	for i := range tw.wheel {
		tw.wheel[i] = &SystemTimeoutList{}
	}

	return &tw
}

func (tw *SystemTimerWheel) Add(v uint32, timeout time.Duration) *SystemTimeoutItem {
	tw.lock.Lock()
	defer tw.lock.Unlock()

	// Check and see if we should progress the tick
	//tw.advance(time.Now())

	i := tw.findWheel(timeout)

	// Try to fetch off the cache
	ti := tw.itemCache
	if ti != nil {
		tw.itemCache = ti.Next
		ti.Next = nil
		tw.itemsCached--
	} else {
		ti = &SystemTimeoutItem{}
	}

	// Relink and return
	ti.Item = v
	ti.Next = tw.wheel[i].Head
	tw.wheel[i].Head = ti

	if tw.wheel[i].Tail == nil {
		tw.wheel[i].Tail = ti
	}

	return ti
}

func (tw *SystemTimerWheel) Purge() interface{} {
	tw.lock.Lock()
	defer tw.lock.Unlock()

	if tw.expired.Head == nil {
		return nil
	}

	ti := tw.expired.Head
	tw.expired.Head = ti.Next

	if tw.expired.Head == nil {
		tw.expired.Tail = nil
	}

	p := ti.Item

	// Clear out the items references
	ti.Item = 0
	ti.Next = nil

	// Maybe cache it for later
	if tw.itemsCached < systemTimerCacheMax {
		ti.Next = tw.itemCache
		tw.itemCache = ti
		tw.itemsCached++
	}

	return p
}

func (tw *SystemTimerWheel) findWheel(timeout time.Duration) (i int) {
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

func (tw *SystemTimerWheel) advance(now time.Time) {
	tw.lock.Lock()
	defer tw.lock.Unlock()

	if tw.lastTick == nil {
		tw.lastTick = &now
	}

	// We want to round down
	ticks := int(now.Sub(*tw.lastTick) / tw.tickDuration)
	//l.Infoln("Ticks: ", ticks)
	for i := 0; i < ticks; i++ {
		tw.current++
		//l.Infoln("Tick: ", tw.current)
		if tw.current >= tw.wheelLen {
			tw.current = 0
		}

		// We need to append the expired items as to not starve evicting the oldest ones
		if tw.expired.Tail == nil {
			tw.expired.Head = tw.wheel[tw.current].Head
			tw.expired.Tail = tw.wheel[tw.current].Tail
		} else {
			tw.expired.Tail.Next = tw.wheel[tw.current].Head
			if tw.wheel[tw.current].Tail != nil {
				tw.expired.Tail = tw.wheel[tw.current].Tail
			}
		}

		//l.Infoln("Head: ", tw.expired.Head, "Tail: ", tw.expired.Tail)
		tw.wheel[tw.current].Head = nil
		tw.wheel[tw.current].Tail = nil

		tw.lastTick = &now
	}
}
