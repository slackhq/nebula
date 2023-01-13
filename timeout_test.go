package nebula

import (
	"testing"
	"time"

	"github.com/slackhq/nebula/firewall"
	"github.com/stretchr/testify/assert"
	"github.com/thepudds/fzgen/fuzzer"
)

func TestNewTimerWheel(t *testing.T) {
	// Make sure we get an object we expect
	tw := NewTimerWheel(time.Second, time.Second*10)
	assert.Equal(t, 12, tw.wheelLen)
	assert.Equal(t, 0, tw.current)
	assert.Nil(t, tw.lastTick)
	assert.Equal(t, time.Second*1, tw.tickDuration)
	assert.Equal(t, time.Second*10, tw.wheelDuration)
	assert.Len(t, tw.wheel, 12)

	// Assert the math is correct
	tw = NewTimerWheel(time.Second*3, time.Second*10)
	assert.Equal(t, 5, tw.wheelLen)

	tw = NewTimerWheel(time.Second*120, time.Minute*10)
	assert.Equal(t, 7, tw.wheelLen)
}

func Fuzz_TimerWheel_NewTimerWheel(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var min time.Duration
		var max time.Duration
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&min, &max)

		if min == 0 || max == 0 {
			t.Skip("We don't expect to handle a divide by zero")
		}

		if min < 0 || max < 0 {
			t.Skip("We expect min and max to be positive durations")
		}

		wLen := int((max / min) + 2)
		if max > time.Second*5 || wLen > 50_000_000 {
			t.Skip("Long time durations are not amenable to fuzzing")
		}

		t.Logf("min: %v\nmax: %v", min, max)

		NewTimerWheel(min, max)
	})
}

func TestTimerWheel_findWheel(t *testing.T) {
	tw := NewTimerWheel(time.Second, time.Second*10)
	assert.Len(t, tw.wheel, 12)

	// Current + tick + 1 since we don't know how far into current we are
	assert.Equal(t, 2, tw.findWheel(time.Second*1))

	// Scale up to min duration
	assert.Equal(t, 2, tw.findWheel(time.Millisecond*1))

	// Make sure we hit that last index
	assert.Equal(t, 11, tw.findWheel(time.Second*10))

	// Scale down to max duration
	assert.Equal(t, 11, tw.findWheel(time.Second*11))

	tw.current = 1
	// Make sure we account for the current position properly
	assert.Equal(t, 3, tw.findWheel(time.Second*1))
	assert.Equal(t, 0, tw.findWheel(time.Second*10))
}

func TestTimerWheel_Add(t *testing.T) {
	tw := NewTimerWheel(time.Second, time.Second*10)

	fp1 := firewall.Packet{}
	tw.Add(fp1, time.Second*1)

	// Make sure we set head and tail properly
	assert.NotNil(t, tw.wheel[2])
	assert.Equal(t, fp1, tw.wheel[2].Head.Packet)
	assert.Nil(t, tw.wheel[2].Head.Next)
	assert.Equal(t, fp1, tw.wheel[2].Tail.Packet)
	assert.Nil(t, tw.wheel[2].Tail.Next)

	// Make sure we only modify head
	fp2 := firewall.Packet{}
	tw.Add(fp2, time.Second*1)
	assert.Equal(t, fp2, tw.wheel[2].Head.Packet)
	assert.Equal(t, fp1, tw.wheel[2].Head.Next.Packet)
	assert.Equal(t, fp1, tw.wheel[2].Tail.Packet)
	assert.Nil(t, tw.wheel[2].Tail.Next)

	// Make sure we use free'd items first
	tw.itemCache = &TimeoutItem{}
	tw.itemsCached = 1
	tw.Add(fp2, time.Second*1)
	assert.Nil(t, tw.itemCache)
	assert.Equal(t, 0, tw.itemsCached)

	// Ensure that all configurations of a wheel does not result in calculating an overflow of the wheel
	for min := time.Duration(1); min < 100; min++ {
		for max := min; max < 100; max++ {
			tw = NewTimerWheel(min, max)

			for current := 0; current < tw.wheelLen; current++ {
				tw.current = current
				for timeout := time.Duration(0); timeout <= tw.wheelDuration; timeout++ {
					tick := tw.findWheel(timeout)
					if tick >= tw.wheelLen {
						t.Errorf("Min: %v; Max: %v; Wheel len: %v; Current Tick: %v; Insert timeout: %v; Calc tick: %v", min, max, tw.wheelLen, current, timeout, tick)
					}
				}
			}
		}
	}
}

func Fuzz_TimerWheel_Add(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var min time.Duration
		var max time.Duration
		var v firewall.Packet
		var timeout time.Duration
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&min, &max, &v, &timeout)

		tw := NewTimerWheel(min, max)
		tw.Add(v, timeout)
	})
}

func TestTimerWheel_Purge(t *testing.T) {
	// First advance should set the lastTick and do nothing else
	tw := NewTimerWheel(time.Second, time.Second*10)
	assert.Nil(t, tw.lastTick)
	tw.advance(time.Now())
	assert.NotNil(t, tw.lastTick)
	assert.Equal(t, 0, tw.current)

	fps := []firewall.Packet{
		{LocalIP: 1},
		{LocalIP: 2},
		{LocalIP: 3},
		{LocalIP: 4},
	}

	tw.Add(fps[0], time.Second*1)
	tw.Add(fps[1], time.Second*1)
	tw.Add(fps[2], time.Second*2)
	tw.Add(fps[3], time.Second*2)

	ta := time.Now().Add(time.Second * 3)
	lastTick := *tw.lastTick
	tw.advance(ta)
	assert.Equal(t, 3, tw.current)
	assert.True(t, tw.lastTick.After(lastTick))

	// Make sure we get all 4 packets back
	for i := 0; i < 4; i++ {
		p, has := tw.Purge()
		assert.True(t, has)
		assert.Equal(t, fps[i], p)
	}

	// Make sure there aren't any leftover
	_, ok := tw.Purge()
	assert.False(t, ok)
	assert.Nil(t, tw.expired.Head)
	assert.Nil(t, tw.expired.Tail)

	// Make sure we cached the free'd items
	assert.Equal(t, 4, tw.itemsCached)
	ci := tw.itemCache
	for i := 0; i < 4; i++ {
		assert.NotNil(t, ci)
		ci = ci.Next
	}
	assert.Nil(t, ci)

	// Lets make sure we roll over properly
	ta = ta.Add(time.Second * 5)
	tw.advance(ta)
	assert.Equal(t, 8, tw.current)

	ta = ta.Add(time.Second * 2)
	tw.advance(ta)
	assert.Equal(t, 10, tw.current)

	ta = ta.Add(time.Second * 1)
	tw.advance(ta)
	assert.Equal(t, 11, tw.current)

	ta = ta.Add(time.Second * 1)
	tw.advance(ta)
	assert.Equal(t, 0, tw.current)
}

func Fuzz_TimerWheel_Purge(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var min time.Duration
		var max time.Duration
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&min, &max)

		tw := NewTimerWheel(min, max)
		tw.Purge()
	})
}
