package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/firewall"
	"github.com/stretchr/testify/assert"
)

func TestNewTimerWheel(t *testing.T) {
	// Make sure we get an object we expect
	tw := NewTimerWheel[firewall.Packet](time.Second, time.Second*10)
	assert.Equal(t, 12, tw.wheelLen)
	assert.Equal(t, 0, tw.current)
	assert.Nil(t, tw.lastTick)
	assert.Equal(t, time.Second*1, tw.tickDuration)
	assert.Equal(t, time.Second*10, tw.wheelDuration)
	assert.Len(t, tw.wheel, 12)

	// Assert the math is correct
	tw = NewTimerWheel[firewall.Packet](time.Second*3, time.Second*10)
	assert.Equal(t, 5, tw.wheelLen)

	tw = NewTimerWheel[firewall.Packet](time.Second*120, time.Minute*10)
	assert.Equal(t, 7, tw.wheelLen)

	// Test empty purge of non nil items
	i, ok := tw.Purge()
	assert.Equal(t, firewall.Packet{}, i)
	assert.False(t, ok)

	// Test empty purges of nil items
	tw2 := NewTimerWheel[*int](time.Second, time.Second*10)
	i2, ok := tw2.Purge()
	assert.Nil(t, i2)
	assert.False(t, ok)

}

func TestTimerWheel_findWheel(t *testing.T) {
	tw := NewTimerWheel[firewall.Packet](time.Second, time.Second*10)
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
	tw := NewTimerWheel[firewall.Packet](time.Second, time.Second*10)

	fp1 := firewall.Packet{}
	tw.Add(fp1, time.Second*1)

	// Make sure we set head and tail properly
	assert.NotNil(t, tw.wheel[2])
	assert.Equal(t, fp1, tw.wheel[2].Head.Item)
	assert.Nil(t, tw.wheel[2].Head.Next)
	assert.Equal(t, fp1, tw.wheel[2].Tail.Item)
	assert.Nil(t, tw.wheel[2].Tail.Next)

	// Make sure we only modify head
	fp2 := firewall.Packet{}
	tw.Add(fp2, time.Second*1)
	assert.Equal(t, fp2, tw.wheel[2].Head.Item)
	assert.Equal(t, fp1, tw.wheel[2].Head.Next.Item)
	assert.Equal(t, fp1, tw.wheel[2].Tail.Item)
	assert.Nil(t, tw.wheel[2].Tail.Next)

	// Make sure we use free'd items first
	tw.itemCache = &TimeoutItem[firewall.Packet]{}
	tw.itemsCached = 1
	tw.Add(fp2, time.Second*1)
	assert.Nil(t, tw.itemCache)
	assert.Equal(t, 0, tw.itemsCached)

	// Ensure that all configurations of a wheel does not result in calculating an overflow of the wheel
	for min := time.Duration(1); min < 100; min++ {
		for max := min; max < 100; max++ {
			tw = NewTimerWheel[firewall.Packet](min, max)

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

func TestTimerWheel_Purge(t *testing.T) {
	// First advance should set the lastTick and do nothing else
	tw := NewTimerWheel[firewall.Packet](time.Second, time.Second*10)
	assert.Nil(t, tw.lastTick)
	tw.Advance(time.Now())
	assert.NotNil(t, tw.lastTick)
	assert.Equal(t, 0, tw.current)

	fps := []firewall.Packet{
		{LocalAddr: netip.MustParseAddr("0.0.0.1")},
		{LocalAddr: netip.MustParseAddr("0.0.0.2")},
		{LocalAddr: netip.MustParseAddr("0.0.0.3")},
		{LocalAddr: netip.MustParseAddr("0.0.0.4")},
	}

	tw.Add(fps[0], time.Second*1)
	tw.Add(fps[1], time.Second*1)
	tw.Add(fps[2], time.Second*2)
	tw.Add(fps[3], time.Second*2)

	ta := time.Now().Add(time.Second * 3)
	lastTick := *tw.lastTick
	tw.Advance(ta)
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

	// Let's make sure we roll over properly
	ta = ta.Add(time.Second * 5)
	tw.Advance(ta)
	assert.Equal(t, 8, tw.current)

	ta = ta.Add(time.Second * 2)
	tw.Advance(ta)
	assert.Equal(t, 10, tw.current)

	ta = ta.Add(time.Second * 1)
	tw.Advance(ta)
	assert.Equal(t, 11, tw.current)

	ta = ta.Add(time.Second * 1)
	tw.Advance(ta)
	assert.Equal(t, 0, tw.current)
}
