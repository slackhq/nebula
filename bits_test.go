package nebula

import (
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

func TestBits(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(10)

	// make sure it is the right size
	assert.Len(t, b.bits, 10)

	// This is initialized to zero - receive one. This should work.
	assert.True(t, b.Check(l, 1))
	assert.True(t, b.Update(l, 1))
	assert.EqualValues(t, 1, b.current)
	g := []bool{true, true, false, false, false, false, false, false, false, false}
	assert.Equal(t, g, b.bits)

	// Receive two
	assert.True(t, b.Check(l, 2))
	assert.True(t, b.Update(l, 2))
	assert.EqualValues(t, 2, b.current)
	g = []bool{true, true, true, false, false, false, false, false, false, false}
	assert.Equal(t, g, b.bits)

	// Receive two again - it will fail
	assert.False(t, b.Check(l, 2))
	assert.False(t, b.Update(l, 2))
	assert.EqualValues(t, 2, b.current)

	// Jump ahead to 15, which should clear everything and set the 6th element
	assert.True(t, b.Check(l, 15))
	assert.True(t, b.Update(l, 15))
	assert.EqualValues(t, 15, b.current)
	g = []bool{false, false, false, false, false, true, false, false, false, false}
	assert.Equal(t, g, b.bits)

	// Mark 14, which is allowed because it is in the window
	assert.True(t, b.Check(l, 14))
	assert.True(t, b.Update(l, 14))
	assert.EqualValues(t, 15, b.current)
	g = []bool{false, false, false, false, true, true, false, false, false, false}
	assert.Equal(t, g, b.bits)

	// Mark 5, which is not allowed because it is not in the window
	assert.False(t, b.Check(l, 5))
	assert.False(t, b.Update(l, 5))
	assert.EqualValues(t, 15, b.current)
	g = []bool{false, false, false, false, true, true, false, false, false, false}
	assert.Equal(t, g, b.bits)

	// make sure we handle wrapping around once to the current position
	b = NewBits(10)
	assert.True(t, b.Update(l, 1))
	assert.True(t, b.Update(l, 11))
	assert.Equal(t, []bool{false, true, false, false, false, false, false, false, false, false}, b.bits)

	// Walk through a few windows in order
	b = NewBits(10)
	for i := uint64(1); i <= 100; i++ {
		assert.True(t, b.Check(l, i), "Error while checking %v", i)
		assert.True(t, b.Update(l, i), "Error while updating %v", i)
	}

	assert.False(t, b.Check(l, 1), "Out of window check")
}

func TestBitsLargeJumps(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(10)
	b.lostCounter.Clear()

	b = NewBits(10)
	b.lostCounter.Clear()
	assert.True(t, b.Update(l, 55)) // We saw packet 55 and can still track 45,46,47,48,49,50,51,52,53,54
	assert.Equal(t, int64(45), b.lostCounter.Count())

	assert.True(t, b.Update(l, 100)) // We saw packet 55 and 100 and can still track 90,91,92,93,94,95,96,97,98,99
	assert.Equal(t, int64(89), b.lostCounter.Count())

	assert.True(t, b.Update(l, 200)) // We saw packet 55, 100, and 200 and can still track 190,191,192,193,194,195,196,197,198,199
	assert.Equal(t, int64(188), b.lostCounter.Count())
}

func TestBitsDupeCounter(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(10)
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
	b := NewBits(10)
	b.lostCounter.Clear()
	b.dupeCounter.Clear()
	b.outOfWindowCounter.Clear()

	assert.True(t, b.Update(l, 20))
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())

	assert.True(t, b.Update(l, 21))
	assert.True(t, b.Update(l, 22))
	assert.True(t, b.Update(l, 23))
	assert.True(t, b.Update(l, 24))
	assert.True(t, b.Update(l, 25))
	assert.True(t, b.Update(l, 26))
	assert.True(t, b.Update(l, 27))
	assert.True(t, b.Update(l, 28))
	assert.True(t, b.Update(l, 29))
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())

	assert.False(t, b.Update(l, 0))
	assert.Equal(t, int64(1), b.outOfWindowCounter.Count())

	assert.Equal(t, int64(19), b.lostCounter.Count()) // packet 0 wasn't lost
	assert.Equal(t, int64(0), b.dupeCounter.Count())
	assert.Equal(t, int64(1), b.outOfWindowCounter.Count())
}

func TestBitsLostCounter(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(10)
	b.lostCounter.Clear()
	b.dupeCounter.Clear()
	b.outOfWindowCounter.Clear()

	assert.True(t, b.Update(l, 20))
	assert.True(t, b.Update(l, 21))
	assert.True(t, b.Update(l, 22))
	assert.True(t, b.Update(l, 23))
	assert.True(t, b.Update(l, 24))
	assert.True(t, b.Update(l, 25))
	assert.True(t, b.Update(l, 26))
	assert.True(t, b.Update(l, 27))
	assert.True(t, b.Update(l, 28))
	assert.True(t, b.Update(l, 29))
	assert.Equal(t, int64(19), b.lostCounter.Count()) // packet 0 wasn't lost
	assert.Equal(t, int64(0), b.dupeCounter.Count())
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())

	b = NewBits(10)
	b.lostCounter.Clear()
	b.dupeCounter.Clear()
	b.outOfWindowCounter.Clear()

	assert.True(t, b.Update(l, 9))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	// 10 will set 0 index, 0 was already set, no lost packets
	assert.True(t, b.Update(l, 10))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	// 11 will set 1 index, 1 was missed, we should see 1 packet lost
	assert.True(t, b.Update(l, 11))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	// Now let's fill in the window, should end up with 8 lost packets
	assert.True(t, b.Update(l, 12))
	assert.True(t, b.Update(l, 13))
	assert.True(t, b.Update(l, 14))
	assert.True(t, b.Update(l, 15))
	assert.True(t, b.Update(l, 16))
	assert.True(t, b.Update(l, 17))
	assert.True(t, b.Update(l, 18))
	assert.True(t, b.Update(l, 19))
	assert.Equal(t, int64(8), b.lostCounter.Count())

	// Jump ahead by a window size
	assert.True(t, b.Update(l, 29))
	assert.Equal(t, int64(8), b.lostCounter.Count())
	// Now lets walk ahead normally through the window, the missed packets should fill in
	assert.True(t, b.Update(l, 30))
	assert.True(t, b.Update(l, 31))
	assert.True(t, b.Update(l, 32))
	assert.True(t, b.Update(l, 33))
	assert.True(t, b.Update(l, 34))
	assert.True(t, b.Update(l, 35))
	assert.True(t, b.Update(l, 36))
	assert.True(t, b.Update(l, 37))
	assert.True(t, b.Update(l, 38))
	// 39 packets tracked, 22 seen, 17 lost
	assert.Equal(t, int64(17), b.lostCounter.Count())

	// Jump ahead by 2 windows, should have recording 1 full window missing
	assert.True(t, b.Update(l, 58))
	assert.Equal(t, int64(27), b.lostCounter.Count())
	// Now lets walk ahead normally through the window, the missed packets should fill in from this window
	assert.True(t, b.Update(l, 59))
	assert.True(t, b.Update(l, 60))
	assert.True(t, b.Update(l, 61))
	assert.True(t, b.Update(l, 62))
	assert.True(t, b.Update(l, 63))
	assert.True(t, b.Update(l, 64))
	assert.True(t, b.Update(l, 65))
	assert.True(t, b.Update(l, 66))
	assert.True(t, b.Update(l, 67))
	// 68 packets tracked, 32 seen, 36 missed
	assert.Equal(t, int64(36), b.lostCounter.Count())
	assert.Equal(t, int64(0), b.dupeCounter.Count())
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())
}

func TestBitsLostCounterIssue1(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(10)
	b.lostCounter.Clear()
	b.dupeCounter.Clear()
	b.outOfWindowCounter.Clear()

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
	// assert.True(t, b.Update(l, 8))
	assert.True(t, b.Update(l, 10))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	assert.True(t, b.Update(l, 11))
	assert.Equal(t, int64(0), b.lostCounter.Count())

	assert.True(t, b.Update(l, 14))
	assert.Equal(t, int64(0), b.lostCounter.Count())
	// Issue seems to be here, we reset missing packet 8 to false here and don't increment the lost counter
	assert.True(t, b.Update(l, 19))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 12))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 13))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 15))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 16))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 17))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 18))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 20))
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.True(t, b.Update(l, 21))

	// We missed packet 8 above
	assert.Equal(t, int64(1), b.lostCounter.Count())
	assert.Equal(t, int64(0), b.dupeCounter.Count())
	assert.Equal(t, int64(0), b.outOfWindowCounter.Count())
}

func BenchmarkBits(b *testing.B) {
	z := NewBits(10)
	for n := 0; n < b.N; n++ {
		for i := range z.bits {
			z.bits[i] = true
		}
		for i := range z.bits {
			z.bits[i] = false
		}

	}
}
