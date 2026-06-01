package nebula

import (
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

// snapshot returns the bitmap as a []bool of length b.length, for readable
// test assertions against the now-packed []uint64 storage.
func (b *Bits) snapshot() []bool {
	out := make([]bool, b.length)
	for i := uint64(0); i < b.length; i++ {
		out[i] = b.get(i)
	}
	return out
}

func TestBitsRequiresPowerOfTwo(t *testing.T) {
	assert.Panics(t, func() { NewBits(10) })
	assert.Panics(t, func() { NewBits(0) })
	assert.NotPanics(t, func() { NewBits(1) })
	assert.NotPanics(t, func() { NewBits(16) })
	assert.NotPanics(t, func() { NewBits(1024) })
	assert.NotPanics(t, func() { NewBits(16384) })
}

func TestBits(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(16)
	assert.EqualValues(t, 16, b.length)

	// This is initialized to zero - receive one. This should work.
	assert.True(t, b.Check(l, 1))
	assert.True(t, b.Update(l, 1))
	assert.EqualValues(t, 1, b.current)
	g := []bool{true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false}
	assert.Equal(t, g, b.snapshot())

	// Receive two
	assert.True(t, b.Check(l, 2))
	assert.True(t, b.Update(l, 2))
	assert.EqualValues(t, 2, b.current)
	g = []bool{true, true, true, false, false, false, false, false, false, false, false, false, false, false, false, false}
	assert.Equal(t, g, b.snapshot())

	// Receive two again - it will fail
	assert.False(t, b.Check(l, 2))
	assert.False(t, b.Update(l, 2))
	assert.EqualValues(t, 2, b.current)

	// Jump ahead to 25, which clears the window and sets slot 25%16 = 9.
	assert.True(t, b.Check(l, 25))
	assert.True(t, b.Update(l, 25))
	assert.EqualValues(t, 25, b.current)
	g = []bool{false, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false}
	assert.Equal(t, g, b.snapshot())

	// Mark 24, which is in window (current 25, length 16, window covers [10,25]).
	assert.True(t, b.Check(l, 24))
	assert.True(t, b.Update(l, 24))
	assert.EqualValues(t, 25, b.current)
	g = []bool{false, false, false, false, false, false, false, false, true, true, false, false, false, false, false, false}
	assert.Equal(t, g, b.snapshot())

	// Mark 5, not allowed because 5 <= current-length (25-16=9).
	assert.False(t, b.Check(l, 5))
	assert.False(t, b.Update(l, 5))
	assert.EqualValues(t, 25, b.current)
	g = []bool{false, false, false, false, false, false, false, false, true, true, false, false, false, false, false, false}
	assert.Equal(t, g, b.snapshot())

	// Make sure we handle wrapping around once to the same slot. With
	// length=16, packets 1 and 17 share slot 1.
	b = NewBits(16)
	assert.True(t, b.Update(l, 1))
	assert.True(t, b.Update(l, 17))
	assert.Equal(t, []bool{false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false}, b.snapshot())

	// Walk through a few windows in order
	b = NewBits(16)
	for i := uint64(1); i <= 100; i++ {
		assert.True(t, b.Check(l, i), "Error while checking %v", i)
		assert.True(t, b.Update(l, i), "Error while updating %v", i)
	}

	assert.False(t, b.Check(l, 1), "Out of window check")
}

func TestBitsLargeJumps(t *testing.T) {
	l := test.NewLogger()

	// length=16. Update(55) from current=0:
	//   warmup, per-bit loop sees no n>16 with unset bits (slot 0 was set by
	//   NewBits and gets re-evaluated when n=16; n=16 is not strictly > 16),
	//   so the loop contributes 0. The jump exceeds the window so we record
	//   55 - 0 - 16 = 39 packets fell out the back.
	b := NewBits(16)
	b.lostCounter.Clear()
	assert.True(t, b.Update(l, 55))
	assert.Equal(t, int64(39), b.lostCounter.Count())

	// Update(100): clears 16 slots starting at slot 56%16=8. Only slot 7 (for
	// packet 55) was set, so 16 - 1 = 15 evicted slots had unset bits.
	// Plus 100 - 55 - 16 = 29 packets fell past the window. Total 44.
	assert.True(t, b.Update(l, 100))
	assert.Equal(t, int64(39+44), b.lostCounter.Count())

	// Update(200): same shape: 16 - 1 = 15 evicted unset, plus 200 - 100 - 16 = 84 past window. Total 99.
	assert.True(t, b.Update(l, 200))
	assert.Equal(t, int64(39+44+99), b.lostCounter.Count())
}

func TestBitsDupeCounter(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(16)
	b.lostCounter.Clear()
	b.dupeCounter.Clear()
	b.outOfWindowCounter.Clear()

	assert.True(t, b.Update(l, 1))
	assert.Equal(t, int64(0), b.dupeCounter.Count())

	assert.False(t, b.Update(l, 1))
	assert.Equal(t, int64(1), b.dupeCounter.Count())

	assert.True(t, b.Update(l, 2))
	assert.Equal(t, int64(1), b.dupeCounter.Count())

	assert.True(t, b.Update(l, 3))
	assert.Equal(t, int64(1), b.dupeCounter.Count())

	assert.False(t, b.Update(l, 1))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	assert.Equal(t, int64(2), b.dupeCounter.Count())
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())
}

func TestBitsOutOfWindowCounter(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(16)
	b.lostCounter.Clear()
	b.dupeCounter.Clear()
	b.outOfWindowCounter.Clear()

	// Jump to 20 (warmup branch + 4 past-window packets).
	assert.True(t, b.Update(l, 20))
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())

	// 9 single-step advances, each evicts a slot whose bit was cleared during
	// the jump above and whose value was never seen, so each contributes 1
	// to lostCounter.
	for n := uint64(21); n <= 29; n++ {
		assert.True(t, b.Update(l, n))
	}
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())

	// 0 is below current-length (29-16=13) so it falls outside the window.
	assert.False(t, b.Update(l, 0))
	assert.Equal(t, int64(1), b.outOfWindowCounter.Count())

	// 4 from the Update(20) jump + 9 from 21..29.
	assert.Equal(t, int64(13), b.lostCounter.Count())
	assert.Equal(t, int64(0), b.dupeCounter.Count())
	assert.Equal(t, int64(1), b.outOfWindowCounter.Count())
}

func TestBitsLostCounter(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(16)
	b.lostCounter.Clear()
	b.dupeCounter.Clear()
	b.outOfWindowCounter.Clear()

	// Walk 20..29 like the original, just with a bigger window. Same
	// reasoning as TestBitsOutOfWindowCounter: 4 past-window from Update(20),
	// then 9 more from the unit advances.
	for n := uint64(20); n <= 29; n++ {
		assert.True(t, b.Update(l, n))
	}
	assert.Equal(t, int64(13), b.lostCounter.Count())
	assert.Equal(t, int64(0), b.dupeCounter.Count())
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())

	b = NewBits(16)
	b.lostCounter.Clear()
	b.dupeCounter.Clear()
	b.outOfWindowCounter.Clear()

	// Update(15) clears the warmup window (no lost), sets slot 15.
	assert.True(t, b.Update(l, 15))
	assert.Equal(t, int64(0), b.lostCounter.Count())

	// Update(16): slot 0 was already set (NewBits seeded it), and 16 is not
	// strictly > length, so nothing is recorded as lost.
	assert.True(t, b.Update(l, 16))
	assert.Equal(t, int64(0), b.lostCounter.Count())

	// Update(17): we jumped straight from 0 to 15, so slot 1 was cleared
	// (and never re-set). 17 > 16 is past warmup, so packet 1 is recorded lost.
	assert.True(t, b.Update(l, 17))
	assert.Equal(t, int64(1), b.lostCounter.Count())

	// Fill in 18..30 in single steps. Each i evicts slot i%16. Slots 2..14
	// were all cleared during Update(15), and we never re-set any of them,
	// so each i in 18..30 is a fresh lost packet — 13 more.
	for n := uint64(18); n <= 30; n++ {
		assert.True(t, b.Update(l, n))
	}
	assert.Equal(t, int64(14), b.lostCounter.Count())

	// Jump ahead by exactly one window size.
	assert.True(t, b.Update(l, 46))
	// end = min(46, 30+16) = 46, count = 16, all slots cleared. Before the
	// jump every slot 0..15 had been set (Update(15), (16), (17), 18..30),
	// so wasSet=16 and 46 == current+length means no past-window slack:
	// lost contribution = 0.
	assert.Equal(t, int64(14), b.lostCounter.Count())

	// Walk 47..55. The Update(46) jump cleared every slot, so only slot 14
	// (for packet 46) is set when we start. Each subsequent unit step lands
	// on a slot that was cleared and is past warmup, so it counts as lost.
	// 9 more = 23.
	for n := uint64(47); n <= 55; n++ {
		assert.True(t, b.Update(l, n))
	}
	assert.Equal(t, int64(23), b.lostCounter.Count())

	// Jump ahead by two windows: clears the window plus past-window loss.
	assert.True(t, b.Update(l, 87))
	// current=55, length=16. end = min(87, 71) = 71. count=16, all slots
	// cleared. Slots set before the clear are slots 14,15,0..7 (10 total).
	// Lost from clear = 16 - 10 = 6. Past window: 87 - 55 - 16 = 16. +22.
	assert.Equal(t, int64(45), b.lostCounter.Count())
	assert.Equal(t, int64(0), b.dupeCounter.Count())
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())
}

func TestBitsLostCounterIssue1(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(16)
	b.lostCounter.Clear()
	b.dupeCounter.Clear()
	b.outOfWindowCounter.Clear()

	// Receive 4, backfill 1, then 9, 2, 3, 5, 6, 7 (skip 8), 10, 11, 14.
	// Then jump to 25 — slot 25%16=9 is being evicted, but it had been set
	// (we received packet 9), so no spurious lost increment. The original
	// regression was about double-counting a missing packet when its slot
	// got cleared on a jump. With the jump path now using clearRange's
	// word-level wasSet count, the same semantics hold.
	assert.True(t, b.Update(l, 4))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	assert.True(t, b.Update(l, 1))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	assert.True(t, b.Update(l, 9))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	assert.True(t, b.Update(l, 2))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	assert.True(t, b.Update(l, 3))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	assert.True(t, b.Update(l, 5))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	assert.True(t, b.Update(l, 6))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	assert.True(t, b.Update(l, 7))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	// Skip packet 8.
	assert.True(t, b.Update(l, 10))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	assert.True(t, b.Update(l, 11))
	assert.Equal(t, int64(0), b.lostCounter.Count())

	assert.True(t, b.Update(l, 14))
	assert.Equal(t, int64(0), b.lostCounter.Count())

	// Jump to 25. With length=16, slot 25%16=9 corresponds to packet 9
	// (which we DID receive), so its bit is set and no lost++ from that
	// eviction. The trace below shows the only loss is packet 8.
	assert.True(t, b.Update(l, 25))
	// current was 14, i=25. end=min(25,30)=25. count=11. startPos=15.
	// steady? current=14<16, so warmup branch: per-bit n=15..25, count those
	// with !get(n) AND n>16. n=17..25 are >16. Among slots 17%16=1..25%16=9
	// did we set slots 1..9 (packets 1..9)? Yes for all but slot 8 (packet 8
	// was skipped). n=24 maps to slot 8 which is FALSE → lost++. All other
	// n in 17..25 map to slots that are set. n=16 is not strictly > 16. So
	// lost = 1.
	assert.Equal(t, int64(1), b.lostCounter.Count())

	// Fill in 12, 13, 15, 16. Each is below current=25 (in-window). 16 must
	// recheck slot 0 — it was set by NewBits and then cleared by the
	// Update(25) jump, so 16 backfills cleanly.
	assert.True(t, b.Update(l, 12))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 13))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 15))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 16))
	assert.Equal(t, int64(1), b.lostCounter.Count())

	// We missed packet 8 above and that loss is still recorded once, never
	// double-counted, never zeroed.
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.Equal(t, int64(0), b.dupeCounter.Count())
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())
}

// TestBitsWarmupOvershoot exercises the jump path's warmup arm with an
// overshoot past one full window. NewBits leaves current=0 with only slot 0
// "set" by the marker. Jumping straight to length+k must (a) clear every
// slot the jump straddles, (b) count only past-window slack (not the
// in-window slots, which never had a "lost" tenant during warmup), and
// (c) leave the cursor at the new counter so subsequent unit advances
// count from steady state. The marker bit at slot 0 is irrelevant once
// current >= length.
func TestBitsWarmupOvershoot(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(16)
	b.lostCounter.Clear()

	// Jump from current=0 to i=20 (length=16, overshoot=4).
	// Warmup arm: counts slots in [1..16] where bit unset and n>length.
	// Only n=16 was unset and >length: but slot 16%16=0 is the marker,
	// so b.get(16) reads bits[0]=1 and skips. Result: 0 lost from the loop.
	// Past-window: i - current - length = 20 - 0 - 16 = 4 lost.
	assert.True(t, b.Update(l, 20))
	assert.Equal(t, int64(4), b.lostCounter.Count())
	assert.Equal(t, uint64(20), b.current)

	// Steady state now (current=20 >= length=16). Unit advance to 21
	// stomps slot 21%16=5, which was cleared by the jump and not reset,
	// so this is +1 lost.
	assert.True(t, b.Update(l, 21))
	assert.Equal(t, int64(5), b.lostCounter.Count())
}

// TestBitsCheckAcrossWarmupBoundary pins the underflow trick in Check's
// in-window clause. While in warmup, b.current-b.length underflows uint64
// to a huge value so the first OR-clause is always false; the second
// clause (i < length && current < length) carries the in-window check.
// Once current >= length the regimes flip cleanly.
func TestBitsCheckAcrossWarmupBoundary(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(16)

	// Warmup: current=0. Check(0) must read the marker (set) and return false.
	assert.False(t, b.Check(l, 0), "marker slot should look already-received")
	// Warmup: any 0 < i < length is in-window and unset → accepted.
	for i := uint64(1); i < 16; i++ {
		assert.True(t, b.Check(l, i), "warmup in-window i=%d should be accepted", i)
	}
	// Warmup: i >= length but > current is "next number" so accepted.
	assert.True(t, b.Check(l, 16))
	assert.True(t, b.Check(l, 1_000_000))

	// Cross into steady state.
	assert.True(t, b.Update(l, 100))
	// Now current=100, length=16. In-window range is [85..100].
	// 84 is just outside: the underflow clause activates; 84 > 100-16=84 is false.
	// And the warmup clause is false (current >= length). So out of window.
	assert.False(t, b.Check(l, 84))
	// 85 sits at the boundary. 85 > 84 is true → in window, unset → accept.
	assert.True(t, b.Check(l, 85))
	// 100 is current itself; not strictly greater, in-window, but already set.
	assert.False(t, b.Check(l, 100))
	// Way out: clearly out of window.
	assert.False(t, b.Check(l, 50))
}

// TestBitsMarkerInvariant verifies the seeded bits[0]=1 marker behaves
// correctly across warmup and beyond. Update should never clear the marker
// during warmup (clearRange skips position 0 when startPos=1), and once
// current >= length the marker is no longer consulted by Check/Update on
// the live path — but it must still report counter 0 as a duplicate while
// we are in warmup.
func TestBitsMarkerInvariant(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(8)

	// Counter 0 is the seeded marker; Check sees it as already received.
	assert.False(t, b.Check(l, 0))
	// Update(0) at current=0 hits the duplicate branch.
	b.dupeCounter.Clear()
	assert.False(t, b.Update(l, 0))
	assert.Equal(t, int64(1), b.dupeCounter.Count())

	// Walk forward through warmup; the marker must remain set.
	for n := uint64(1); n <= 7; n++ {
		assert.True(t, b.Update(l, n))
	}
	// Position 0 (the marker) should still read as set because we never
	// cleared it; Update(0) still looks like a duplicate.
	assert.False(t, b.Check(l, 0))

	// Cross into steady state with a unit advance to 8: pos=0, evicts the
	// marker bit. The lost-counter guard (i > b.length) is false (8 == 8),
	// so this advance does NOT charge a lost packet — exactly what the
	// marker is there to prevent.
	b.lostCounter.Clear()
	assert.True(t, b.Update(l, 8))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	// The slot at pos 0 is now occupied by counter 8.
	assert.False(t, b.Check(l, 8))
}

// BenchmarkBitsUpdateInOrder is the steady-state hot path: each call is
// i == current+1.
func BenchmarkBitsUpdateInOrder(b *testing.B) {
	l := test.NewLogger()
	z := NewBits(16384)
	for n := 0; n < b.N; n++ {
		z.Update(l, uint64(n)+1)
	}
}

// BenchmarkBitsUpdateReorder simulates light reorder within the window:
// every other packet arrives one slot behind its predecessor (forces the
// in-window backfill branch).
func BenchmarkBitsUpdateReorder(b *testing.B) {
	l := test.NewLogger()
	z := NewBits(16384)
	for n := 0; n < b.N; n++ {
		base := uint64(n) * 2
		z.Update(l, base+2)
		z.Update(l, base+1)
	}
}

// BenchmarkBitsUpdateLargeJumps stresses the clearRange word-level path.
func BenchmarkBitsUpdateLargeJumps(b *testing.B) {
	l := test.NewLogger()
	z := NewBits(16384)
	for n := 0; n < b.N; n++ {
		z.Update(l, uint64(n+1)*1000)
	}
}
