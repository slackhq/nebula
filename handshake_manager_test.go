package nebula

import (
	"net"
	"testing"
	"time"

	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
)

func Test_NewHandshakeManagerVpnIp(t *testing.T) {
	l := test.NewLogger()
	_, tuncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, vpncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, localrange, _ := net.ParseCIDR("10.1.1.1/24")
	ip := iputil.Ip2VpnIp(net.ParseIP("172.1.1.2"))
	preferredRanges := []*net.IPNet{localrange}
	mw := &mockEncWriter{}
	mainHM := NewHostMap(l, vpncidr, preferredRanges)
	lh := newTestLighthouse()

	blah := NewHandshakeManager(l, tuncidr, preferredRanges, mainHM, lh, &udp.NoopConn{}, defaultHandshakeConfig)

	now := time.Now()
	blah.NextOutboundHandshakeTimerTick(now, mw)

	var initCalled bool
	initFunc := func(*HostInfo) {
		initCalled = true
	}

	i := blah.AddVpnIp(ip, initFunc)
	assert.True(t, initCalled)

	initCalled = false
	i2 := blah.AddVpnIp(ip, initFunc)
	assert.False(t, initCalled)
	assert.Same(t, i, i2)

	i.remotes = NewRemoteList(nil)
	i.HandshakeReady = true

	// Adding something to pending should not affect the main hostmap
	assert.Len(t, mainHM.Hosts, 0)

	// Confirm they are in the pending index list
	assert.Contains(t, blah.vpnIps, ip)

	// Jump ahead `HandshakeRetries` ticks, offset by one to get the sleep logic right
	for i := 1; i <= DefaultHandshakeRetries+1; i++ {
		now = now.Add(time.Duration(i) * DefaultHandshakeTryInterval)
		blah.NextOutboundHandshakeTimerTick(now, mw)
	}

	// Confirm they are still in the pending index list
	assert.Contains(t, blah.vpnIps, ip)

	// Tick 1 more time, a minute will certainly flush it out
	blah.NextOutboundHandshakeTimerTick(now.Add(time.Minute), mw)

	// Confirm they have been removed
	assert.NotContains(t, blah.vpnIps, ip)
}

func testCountTimerWheelEntries(tw *LockingTimerWheel[iputil.VpnIp]) (c int) {
	for _, i := range tw.t.wheel {
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

func (mw *mockEncWriter) SendMessageToVpnIp(t header.MessageType, st header.MessageSubType, vpnIp iputil.VpnIp, p, nb, out []byte) {
	return
}

func (mw *mockEncWriter) SendVia(via *HostInfo, relay *Relay, ad, nb, out []byte, nocopy bool) {
	return
}

func (mw *mockEncWriter) SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hostinfo *HostInfo, p, nb, out []byte) {
	return
}

func (mw *mockEncWriter) Handshake(vpnIP iputil.VpnIp) {}
