package nebula

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_NewHandshakeManagerVpnIP(t *testing.T) {
	l := NewTestLogger()
	_, tuncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, vpncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, localrange, _ := net.ParseCIDR("10.1.1.1/24")
	ip := ip2int(net.ParseIP("172.1.1.2"))
	preferredRanges := []*net.IPNet{localrange}
	mw := &mockEncWriter{}
	mainHM := NewHostMap(l, "test", vpncidr, preferredRanges)

	blah := NewHandshakeManager(l, tuncidr, preferredRanges, mainHM, &LightHouse{}, &udpConn{}, defaultHandshakeConfig)

	now := time.Now()
	blah.NextOutboundHandshakeTimerTick(now, mw)

	i := blah.AddVpnIP(ip)
	i.remotes = NewRemoteList()
	i.HandshakeReady = true

	// Adding something to pending should not affect the main hostmap
	assert.Len(t, mainHM.Hosts, 0)

	// Confirm they are in the pending index list
	assert.Contains(t, blah.pendingHostMap.Hosts, ip)

	// Jump ahead `HandshakeRetries` ticks, offset by one to get the sleep logic right
	for i := 1; i <= DefaultHandshakeRetries+1; i++ {
		now = now.Add(time.Duration(i) * DefaultHandshakeTryInterval)
		blah.NextOutboundHandshakeTimerTick(now, mw)
	}

	// Confirm they are still in the pending index list
	assert.Contains(t, blah.pendingHostMap.Hosts, ip)

	// Tick 1 more time, a minute will certainly flush it out
	blah.NextOutboundHandshakeTimerTick(now.Add(time.Minute), mw)

	// Confirm they have been removed
	assert.NotContains(t, blah.pendingHostMap.Hosts, ip)
}

func Test_NewHandshakeManagerTrigger(t *testing.T) {
	l := NewTestLogger()
	_, tuncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, vpncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, localrange, _ := net.ParseCIDR("10.1.1.1/24")
	ip := ip2int(net.ParseIP("172.1.1.2"))
	preferredRanges := []*net.IPNet{localrange}
	mw := &mockEncWriter{}
	mainHM := NewHostMap(l, "test", vpncidr, preferredRanges)
	lh := &LightHouse{addrMap: make(map[uint32]*RemoteList), l: l}

	blah := NewHandshakeManager(l, tuncidr, preferredRanges, mainHM, lh, &udpConn{}, defaultHandshakeConfig)

	now := time.Now()
	blah.NextOutboundHandshakeTimerTick(now, mw)

	assert.Equal(t, 0, testCountTimerWheelEntries(blah.OutboundHandshakeTimer))

	hi := blah.AddVpnIP(ip)
	hi.HandshakeReady = true
	assert.Equal(t, 1, testCountTimerWheelEntries(blah.OutboundHandshakeTimer))
	assert.Equal(t, 0, hi.HandshakeCounter, "Should not have attempted a handshake yet")

	// Trigger the same method the channel will but, this should set our remotes pointer
	blah.handleOutbound(ip, mw, true)
	assert.Equal(t, 1, hi.HandshakeCounter, "Trigger should have done a handshake attempt")
	assert.NotNil(t, hi.remotes, "Manager should have set my remotes pointer")

	// Make sure the trigger doesn't double schedule the timer entry
	assert.Equal(t, 1, testCountTimerWheelEntries(blah.OutboundHandshakeTimer))

	uaddr := NewUDPAddrFromString("10.1.1.1:4242")
	hi.remotes.unlockedPrependV4(ip, NewIp4AndPort(uaddr.IP, uint32(uaddr.Port)))

	// We now have remotes but only the first trigger should have pushed things forward
	blah.handleOutbound(ip, mw, true)
	assert.Equal(t, 1, hi.HandshakeCounter, "Trigger should have not done a handshake attempt")
	assert.Equal(t, 1, testCountTimerWheelEntries(blah.OutboundHandshakeTimer))
}

func testCountTimerWheelEntries(tw *SystemTimerWheel) (c int) {
	for _, i := range tw.wheel {
		n := i.Head
		for n != nil {
			c++
			n = n.Next
		}
	}
	return c
}

type mockEncWriter struct {
}

func (mw *mockEncWriter) SendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte) {
	return
}
