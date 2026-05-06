package nebula

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	mathbits "math/bits"

	"github.com/rcrowley/go-metrics"
)

const bitsPerWord = 64

// Bits is a sliding-window anti-replay tracker. The window is stored as a
// circular bitmap packed into uint64 words (8x denser than a []bool), so a
// length-N window costs N/8 bytes. length must be a power of two.
type Bits struct {
	length             uint64
	lengthMask         uint64
	current            uint64
	bits               []uint64
	lostCounter        metrics.Counter
	dupeCounter        metrics.Counter
	outOfWindowCounter metrics.Counter
}

func NewBits(length uint64) *Bits {
	if length == 0 || length&(length-1) != 0 {
		panic(fmt.Sprintf("Bits length must be a power of two, got %d", length))
	}

	nWords := length / bitsPerWord
	if nWords == 0 {
		nWords = 1
	}
	b := &Bits{
		length:             length,
		lengthMask:         length - 1,
		bits:               make([]uint64, nWords),
		current:            0,
		lostCounter:        metrics.GetOrRegisterCounter("network.packets.lost", nil),
		dupeCounter:        metrics.GetOrRegisterCounter("network.packets.duplicate", nil),
		outOfWindowCounter: metrics.GetOrRegisterCounter("network.packets.out_of_window", nil),
	}

	// There is no counter value 0, mark it to avoid counting a lost packet later.
	b.bits[0] = 1
	return b
}

func (b *Bits) get(i uint64) bool {
	pos := i & b.lengthMask
	//bit-shifting by 6 because i is a bit index, not a u64 index, and we need to find the u64 without bit in it
	return b.bits[pos>>6]&(uint64(1)<<(pos&63)) != 0
}

func (b *Bits) set(i uint64) {
	pos := i & b.lengthMask
	b.bits[pos>>6] |= uint64(1) << (pos & 63)
}

// clearRange clears `count` bits starting at circular position `startPos`
// (already masked to [0, length)) and returns how many of them were set
// before the clear. count must be in [1, length].
func (b *Bits) clearRange(startPos, count uint64) uint64 {
	wasSet := uint64(0)
	if count >= b.length {
		for _, w := range b.bits {
			wasSet += uint64(mathbits.OnesCount64(w))
		}
		clear(b.bits)
		return wasSet
	}

	pos := startPos
	remaining := count

	// handle the potential partial word before pos becomes u64 aligned
	word := pos >> 6
	bit := pos & 63
	take := uint64(64) - bit
	if take > remaining {
		take = remaining
	}
	if take > b.length-pos {
		take = b.length - pos
	}
	var mask uint64
	if take == 64 {
		mask = math.MaxUint64
	} else {
		mask = ((uint64(1) << take) - 1) << bit
	}
	wasSet += uint64(mathbits.OnesCount64(b.bits[word] & mask))
	b.bits[word] &^= mask
	remaining -= take
	pos = (pos + take) & b.lengthMask

	// Clear whole words, keeping track of the number of set bits
	for remaining >= 64 {
		word = pos >> 6
		wasSet += uint64(mathbits.OnesCount64(b.bits[word]))
		b.bits[word] = 0
		remaining -= 64
		pos = (pos + 64) & b.lengthMask
	}

	// Clear the remaining partial word
	if remaining > 0 {
		word = pos >> 6
		mask = (uint64(1) << remaining) - 1
		wasSet += uint64(mathbits.OnesCount64(b.bits[word] & mask))
		b.bits[word] &^= mask
	}

	return wasSet
}

func (b *Bits) strictlyWithinWindow(i uint64) bool {
	// Handle the case where the window hasn't slid yet. This avoids u64 underflow.
	inWarmup := b.current < b.length
	if i < b.length && inWarmup {
		return true
	}

	// Next, if the packet is in-window, see if we've seen it before
	if i > b.current-b.length {
		return true
	}
	return false //not within window!
}

// Check returns true if i is within (or way out in front of) the window, and not a replay
func (b *Bits) Check(l *slog.Logger, i uint64) bool {
	// If i is the next number, return true.
	if i > b.current {
		return true
	}

	if b.strictlyWithinWindow(i) {
		return !b.get(i)
	}

	// Not within the window
	if l.Enabled(context.Background(), slog.LevelDebug) {
		l.Debug("rejected a packet (top)", "current", b.current, "incoming", i)
	}
	return false
}

// Update has three branches:
//   - i == b.current+1: fast path; advance the cursor by one and lose-count
//     the slot we just stomped (only past warmup; see the i > b.length guard
//     below).
//   - i  >  b.current+1: jump path; clear all slots between current and i
//     (or up to a full window's worth, whichever is smaller) via clearRange,
//     then mark i. Two arms here: a warmup arm that handles the very first
//     window before the cursor has slid, and a steady-state arm that treats
//     every cleared empty slot as a lost packet.
//   - i  <= b.current: in-window check for duplicates; out-of-window otherwise.
//
// NewBits seeds bits[0]=1 so counter 0 looks "received" — Update never
// clears that marker during warmup (clearRange skips position 0 when
// startPos=1), and once b.current >= b.length the marker is no longer
// consulted. The marker prevents a fictitious "lost" hit on the first real
// counter.
func (b *Bits) Update(l *slog.Logger, i uint64) bool {
	// Fast path: i is the next expected counter. Split out so the function
	// stays small and avoids paying for the slow paths' slog argument-build
	// stack frame on every call. The bit read/test/write is inlined to
	// touch the backing word once.
	if i == b.current+1 {
		pos := i & b.lengthMask
		word := pos >> 6
		mask := uint64(1) << (pos & 63)
		w := b.bits[word]
		if i > b.length && w&mask == 0 {
			b.lostCounter.Inc(1)
		}
		b.bits[word] = w | mask
		b.current = i
		return true
	}
	return b.updateSlow(l, i)
}

// updateSlow handles jumps, in-window backfill, dupes, and out-of-window.
func (b *Bits) updateSlow(l *slog.Logger, i uint64) bool {
	// If i is a jump, adjust the window, record lost, update current, and return true
	if i > b.current {
		end := i
		if end > b.current+b.length {
			end = b.current + b.length
		}
		count := end - b.current
		startPos := (b.current + 1) & b.lengthMask

		var lost int64
		if b.current >= b.length {
			// Steady state: every cleared slot is past warmup, so any unset
			// bit we evict is a lost packet from the previous cycle.
			wasSet := b.clearRange(startPos, count)
			lost = int64(count) - int64(wasSet)
		} else {
			// Warmup (the very first window). Some cleared slots represent
			// packets <= length where eviction is not "lost" in the usual
			// sense. This branch is taken at most once per connection so we
			// don't bother optimizing it.
			for n := b.current + 1; n <= end; n++ {
				if !b.get(n) && n > b.length {
					lost++
				}
			}
			b.clearRange(startPos, count)
		}

		// Anything past the new window can never be backfilled, so it's lost.
		if i > b.current+b.length {
			lost += int64(i - b.current - b.length)
		}
		b.lostCounter.Inc(lost)

		b.set(i)
		b.current = i
		return true
	}

	// If i is within the current window but below the current counter, check to see if it's a duplicate
	if b.strictlyWithinWindow(i) {
		pos := i & b.lengthMask
		word := pos >> 6
		mask := uint64(1) << (pos & 63)
		w := b.bits[word]
		if b.current == i || w&mask != 0 {
			if l.Enabled(context.Background(), slog.LevelDebug) {
				l.Debug("Receive window",
					"accepted", false,
					"currentCounter", b.current,
					"incomingCounter", i,
					"reason", "duplicate",
				)
			}
			b.dupeCounter.Inc(1)
			return false
		}

		b.bits[word] = w | mask
		return true
	}

	// In all other cases, fail and don't change current.
	b.outOfWindowCounter.Inc(1)
	if l.Enabled(context.Background(), slog.LevelDebug) {
		l.Debug("Receive window",
			"accepted", false,
			"currentCounter", b.current,
			"incomingCounter", i,
			"reason", "nonsense",
		)
	}
	return false
}
