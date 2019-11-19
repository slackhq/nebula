package nebula

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewSystemTimerWheel(t *testing.T) {
	// Make sure we get an object we expect
	tw := NewSystemTimerWheel(time.Second, time.Second*10)
	assert.Equal(t, 11, tw.wheelLen)
	assert.Equal(t, 0, tw.current)
	assert.Nil(t, tw.lastTick)
	assert.Equal(t, time.Second*1, tw.tickDuration)
	assert.Equal(t, time.Second*10, tw.wheelDuration)
	assert.Len(t, tw.wheel, 11)

	// Assert the math is correct
	tw = NewSystemTimerWheel(time.Second*3, time.Second*10)
	assert.Equal(t, 4, tw.wheelLen)

	tw = NewSystemTimerWheel(time.Second*120, time.Minute*10)
	assert.Equal(t, 6, tw.wheelLen)
}

func TestSystemTimerWheel_findWheel(t *testing.T) {
	tw := NewSystemTimerWheel(time.Second, time.Second*10)
	assert.Len(t, tw.wheel, 11)

	// Current + tick + 1 since we don't know how far into current we are
	assert.Equal(t, 2, tw.findWheel(time.Second*1))

	// Scale up to min duration
	assert.Equal(t, 2, tw.findWheel(time.Millisecond*1))

	// Make sure we hit that last index
	assert.Equal(t, 0, tw.findWheel(time.Second*10))

	// Scale down to max duration
	assert.Equal(t, 0, tw.findWheel(time.Second*11))

	tw.current = 1
	// Make sure we account for the current position properly
	assert.Equal(t, 3, tw.findWheel(time.Second*1))
	assert.Equal(t, 1, tw.findWheel(time.Second*10))
}

func TestSystemTimerWheel_Add(t *testing.T) {
	tw := NewSystemTimerWheel(time.Second, time.Second*10)

	fp1 := ip2int(net.ParseIP("1.2.3.4"))
	tw.Add(fp1, time.Second*1)

	// Make sure we set head and tail properly
	assert.NotNil(t, tw.wheel[2])
	assert.Equal(t, fp1, tw.wheel[2].Head.Item)
	assert.Nil(t, tw.wheel[2].Head.Next)
	assert.Equal(t, fp1, tw.wheel[2].Tail.Item)
	assert.Nil(t, tw.wheel[2].Tail.Next)

	// Make sure we only modify head
	fp2 := ip2int(net.ParseIP("1.2.3.4"))
	tw.Add(fp2, time.Second*1)
	assert.Equal(t, fp2, tw.wheel[2].Head.Item)
	assert.Equal(t, fp1, tw.wheel[2].Head.Next.Item)
	assert.Equal(t, fp1, tw.wheel[2].Tail.Item)
	assert.Nil(t, tw.wheel[2].Tail.Next)

	// Make sure we use free'd items first
	tw.itemCache = &SystemTimeoutItem{}
	tw.itemsCached = 1
	tw.Add(fp2, time.Second*1)
	assert.Nil(t, tw.itemCache)
	assert.Equal(t, 0, tw.itemsCached)
}

func TestSystemTimerWheel_Purge(t *testing.T) {
	// First advance should set the lastTick and do nothing else
	tw := NewSystemTimerWheel(time.Second, time.Second*10)
	assert.Nil(t, tw.lastTick)
	tw.advance(time.Now())
	assert.NotNil(t, tw.lastTick)
	assert.Equal(t, 0, tw.current)

	fps := []uint32{9, 10, 11, 12}

	//fp1 := ip2int(net.ParseIP("1.2.3.4"))

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
		assert.Contains(t, fps, tw.Purge())
	}

	// Make sure there aren't any leftover
	assert.Nil(t, tw.Purge())
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
	assert.Equal(t, 0, tw.current)
}
