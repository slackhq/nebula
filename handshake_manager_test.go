package nebula

import (
	"net"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/stretchr/testify/assert"
)

var indexes []uint32 = []uint32{1000, 2000, 3000, 4000}

//var ips []uint32 = []uint32{9000, 9999999, 3, 292394923}
var ips []uint32

func Test_NewHandshakeManagerIndex(t *testing.T) {
	_, tuncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, vpncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, localrange, _ := net.ParseCIDR("10.1.1.1/24")
	ips = []uint32{ip2int(net.ParseIP("172.1.1.2"))}
	preferredRanges := []*net.IPNet{localrange}
	mainHM := NewHostMap("test", vpncidr, preferredRanges)

	blah := NewHandshakeManager(tuncidr, preferredRanges, mainHM, newTestLighthouse(), &udpConn{}, defaultHandshakeConfig)

	now := time.Now()
	blah.NextInboundHandshakeTimerTick(now)

	// Add four indexes
	for _, v := range indexes {
		blah.AddIndex(v, &ConnectionState{})
	}
	// Confirm they are in the pending index list
	for _, v := range indexes {
		assert.Contains(t, blah.pendingHostMap.Indexes, uint32(v))
	}
	// Adding something to pending should not affect the main hostmap
	assert.Len(t, mainHM.Indexes, 0)
	// Jump ahead 8 seconds
	for i := 1; i <= DefaultHandshakeRetries; i++ {
		next_tick := now.Add(DefaultHandshakeTryInterval * time.Duration(i))
		blah.NextInboundHandshakeTimerTick(next_tick)
	}
	// Confirm they are still in the pending index list
	for _, v := range indexes {
		assert.Contains(t, blah.pendingHostMap.Indexes, uint32(v))
	}
	// Jump ahead 4 more seconds
	next_tick := now.Add(12 * time.Second)
	blah.NextInboundHandshakeTimerTick(next_tick)
	// Confirm they have been removed
	for _, v := range indexes {
		assert.NotContains(t, blah.pendingHostMap.Indexes, uint32(v))
	}
}

func Test_NewHandshakeManagerVpnIP(t *testing.T) {
	_, tuncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, vpncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, localrange, _ := net.ParseCIDR("10.1.1.1/24")
	ips = []uint32{ip2int(net.ParseIP("172.1.1.2"))}
	preferredRanges := []*net.IPNet{localrange}
	mw := &mockEncWriter{}
	mainHM := NewHostMap("test", vpncidr, preferredRanges)

	blah := NewHandshakeManager(tuncidr, preferredRanges, mainHM, newTestLighthouse(), &udpConn{}, defaultHandshakeConfig)

	now := time.Now()
	blah.NextOutboundHandshakeTimerTick(now, mw)

	// Add four "IPs" - which are just uint32s
	for _, v := range ips {
		blah.AddVpnIP(v)
	}
	// Adding something to pending should not affect the main hostmap
	assert.Len(t, mainHM.Hosts, 0)
	// Confirm they are in the pending index list
	for _, v := range ips {
		assert.Contains(t, blah.pendingHostMap.Hosts, uint32(v))
	}

	// Jump ahead `HandshakeRetries` ticks
	cumulative := time.Duration(0)
	for i := 0; i <= DefaultHandshakeRetries+1; i++ {
		cumulative += time.Duration(i)*DefaultHandshakeTryInterval + 1
		next_tick := now.Add(cumulative)
		//l.Infoln(next_tick)
		blah.NextOutboundHandshakeTimerTick(next_tick, mw)
	}

	// Confirm they are still in the pending index list
	for _, v := range ips {
		assert.Contains(t, blah.pendingHostMap.Hosts, uint32(v))
	}
	// Jump ahead 1 more second
	cumulative += time.Duration(DefaultHandshakeRetries+1) * DefaultHandshakeTryInterval
	next_tick := now.Add(cumulative)
	//l.Infoln(next_tick)
	blah.NextOutboundHandshakeTimerTick(next_tick, mw)
	// Confirm they have been removed
	for _, v := range ips {
		assert.NotContains(t, blah.pendingHostMap.Hosts, uint32(v))
	}
}

func Test_NewHandshakeManagerVpnIPcleanup(t *testing.T) {
	_, tuncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, vpncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, localrange, _ := net.ParseCIDR("10.1.1.1/24")
	vpnIP = ip2int(net.ParseIP("172.1.1.2"))
	preferredRanges := []*net.IPNet{localrange}
	mw := &mockEncWriter{}
	mainHM := NewHostMap("test", vpncidr, preferredRanges)

	blah := NewHandshakeManager(tuncidr, preferredRanges, mainHM, newTestLighthouse(), &udpConn{}, defaultHandshakeConfig)

	now := time.Now()
	blah.NextOutboundHandshakeTimerTick(now, mw)

	hostinfo := blah.AddVpnIP(vpnIP)
	// Pretned we have an index too
	blah.AddIndexHostInfo(12341234, hostinfo)
	assert.Contains(t, blah.pendingHostMap.Indexes, uint32(12341234))

	// Jump ahead `HandshakeRetries` ticks. Eviction should happen in pending
	// but not main hostmap
	cumulative := time.Duration(0)
	for i := 1; i <= DefaultHandshakeRetries+2; i++ {
		cumulative += DefaultHandshakeTryInterval * time.Duration(i)
		next_tick := now.Add(cumulative)
		blah.NextOutboundHandshakeTimerTick(next_tick, mw)
	}
	/*
		for i := 0; i <= HandshakeRetries+1; i++ {
			next_tick := now.Add(cumulative)
			//l.Infoln(next_tick)
			blah.NextOutboundHandshakeTimerTick(next_tick)
		}
	*/
	/*
		for i := 0; i <= HandshakeRetries+1; i++ {
			next_tick := now.Add(time.Duration(i) * time.Second)
			blah.NextOutboundHandshakeTimerTick(next_tick)
		}
	*/

	/*
		cumulative += HandshakeTryInterval*time.Duration(HandshakeRetries) + 3
		next_tick := now.Add(cumulative)
		l.Infoln(cumulative, next_tick)
		blah.NextOutboundHandshakeTimerTick(next_tick)
	*/
	assert.NotContains(t, blah.pendingHostMap.Hosts, uint32(vpnIP))
	assert.NotContains(t, blah.pendingHostMap.Indexes, uint32(12341234))
}

func Test_NewHandshakeManagerIndexcleanup(t *testing.T) {
	_, tuncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, vpncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, localrange, _ := net.ParseCIDR("10.1.1.1/24")
	preferredRanges := []*net.IPNet{localrange}
	mainHM := NewHostMap("test", vpncidr, preferredRanges)

	blah := NewHandshakeManager(tuncidr, preferredRanges, mainHM, newTestLighthouse(), &udpConn{}, defaultHandshakeConfig)

	now := time.Now()
	blah.NextInboundHandshakeTimerTick(now)

	hostinfo, _ := blah.AddIndex(12341234, &ConnectionState{})
	// Pretned we have an index too
	blah.pendingHostMap.AddVpnIPHostInfo(101010, hostinfo)
	assert.Contains(t, blah.pendingHostMap.Hosts, uint32(101010))

	for i := 1; i <= DefaultHandshakeRetries+2; i++ {
		next_tick := now.Add(DefaultHandshakeTryInterval * time.Duration(i))
		blah.NextInboundHandshakeTimerTick(next_tick)
	}

	next_tick := now.Add(DefaultHandshakeTryInterval*DefaultHandshakeRetries + 3)
	blah.NextInboundHandshakeTimerTick(next_tick)
	assert.NotContains(t, blah.pendingHostMap.Hosts, uint32(101010))
	assert.NotContains(t, blah.pendingHostMap.Indexes, uint32(12341234))
}

type mockEncWriter struct {
}

func (mw *mockEncWriter) SendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte) {
	return
}

func (mw *mockEncWriter) SendMessageToAll(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte) {
	return
}

func newTestLighthouse() *LightHouse {
	l := &LightHouse{}
	for i := range NebulaMeta_MessageType_name {
		l.metricLighthouseRx[i] = metrics.NilCounter{}
		l.metricLighthouseTx[i] = metrics.NilCounter{}
	}
	return l
}
