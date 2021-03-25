package nebula

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

/*
func TestHostInfoDestProbe(t *testing.T) {
	a, _ := net.ResolveUDPAddr("udp", "1.0.0.1:22222")
	d := NewHostInfoDest(a)

	// 999 probes that all return should give a 100% success rate
	for i := 0; i < 999; i++ {
		meh := d.Probe()
		d.ProbeReceived(meh)
	}
	assert.Equal(t, d.Grade(), float64(1))

	// 999 probes of which only half return should give a 50% success rate
	for i := 0; i < 999; i++ {
		meh := d.Probe()
		if i%2 == 0 {
			d.ProbeReceived(meh)
		}
	}
	assert.Equal(t, d.Grade(), float64(.5))

	// 999 probes of which none return should give a 0% success rate
	for i := 0; i < 999; i++ {
		d.Probe()
	}
	assert.Equal(t, d.Grade(), float64(0))

	// 999 probes of which only 1/4 return should give a 25% success rate
	for i := 0; i < 999; i++ {
		meh := d.Probe()
		if i%4 == 0 {
			d.ProbeReceived(meh)
		}
	}
	assert.Equal(t, d.Grade(), float64(.25))

	// 999 probes of which only half return and are duplicates should give a 50% success rate
	for i := 0; i < 999; i++ {
		meh := d.Probe()
		if i%2 == 0 {
			d.ProbeReceived(meh)
			d.ProbeReceived(meh)
		}
	}
	assert.Equal(t, d.Grade(), float64(.5))

	// 999 probes of which only way old replies return should give a 0% success rate
	for i := 0; i < 999; i++ {
		meh := d.Probe()
		d.ProbeReceived(meh - 101)
	}
	assert.Equal(t, d.Grade(), float64(0))

}
*/

func TestHostmap(t *testing.T) {
	_, myNet, _ := net.ParseCIDR("10.128.0.0/16")
	_, localToMe, _ := net.ParseCIDR("192.168.1.0/24")
	myNets := []*net.IPNet{myNet}
	preferredRanges := []*net.IPNet{localToMe}

	m := NewHostMap("test", myNet, preferredRanges)

	a := NewUDPAddrFromString("10.127.0.3:11111")
	b := NewUDPAddrFromString("1.0.0.1:22222")
	y := NewUDPAddrFromString("10.128.0.3:11111")
	m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), a)
	m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), b)
	m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), y)

	info, _ := m.QueryVpnIP(ip2int(net.ParseIP("10.128.1.1")))

	// There should be three remotes in the host map
	assert.Equal(t, 3, len(info.Remotes))

	// Adding an identical remote should not change the count
	m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), y)
	assert.Equal(t, 3, len(info.Remotes))

	// Adding a fresh remote should add one
	y = NewUDPAddrFromString("10.18.0.3:11111")
	m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), y)
	assert.Equal(t, 4, len(info.Remotes))

	// Query and reference remote should get the first one (and not nil)
	info, _ = m.QueryVpnIP(ip2int(net.ParseIP("10.128.1.1")))
	assert.NotNil(t, info.remote)

	// Promotion should ensure that the best remote is chosen (y)
	info.ForcePromoteBest(myNets)
	assert.True(t, myNet.Contains(info.remote.IP))

}

func TestHostmapdebug(t *testing.T) {
	_, myNet, _ := net.ParseCIDR("10.128.0.0/16")
	_, localToMe, _ := net.ParseCIDR("192.168.1.0/24")
	preferredRanges := []*net.IPNet{localToMe}
	m := NewHostMap("test", myNet, preferredRanges)

	a := NewUDPAddrFromString("10.127.0.3:11111")
	b := NewUDPAddrFromString("1.0.0.1:22222")
	y := NewUDPAddrFromString("10.128.0.3:11111")
	m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), a)
	m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), b)
	m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), y)

	//t.Errorf("%s", m.DebugRemotes(1))
}

func TestHostMap_rotateRemote(t *testing.T) {
	h := HostInfo{}
	// 0 remotes, no panic
	h.rotateRemote()
	assert.Nil(t, h.remote)

	// 1 remote, no panic
	h.unlockedAddRemote(NewUDPAddr(net.IP{1, 1, 1, 1}, 0))
	h.rotateRemote()
	assert.Equal(t, h.remote.IP, net.IP{1, 1, 1, 1})

	h.unlockedAddRemote(NewUDPAddr(net.IP{1, 1, 1, 2}, 0))
	h.unlockedAddRemote(NewUDPAddr(net.IP{1, 1, 1, 3}, 0))
	h.unlockedAddRemote(NewUDPAddr(net.IP{1, 1, 1, 4}, 0))

	//TODO: ensure we are copying and not storing the slice!

	// Rotate through those 3
	h.rotateRemote()
	assert.Equal(t, h.remote.IP, net.IP{1, 1, 1, 2})

	h.rotateRemote()
	assert.Equal(t, h.remote.IP, net.IP{1, 1, 1, 3})

	h.rotateRemote()
	assert.Equal(t, h.remote, &udpAddr{IP: net.IP{1, 1, 1, 4}, Port: 0})

	// Finally, we should start over
	h.rotateRemote()
	assert.Equal(t, h.remote, &udpAddr{IP: net.IP{1, 1, 1, 1}, Port: 0})
}

func BenchmarkHostmappromote2(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, myNet, _ := net.ParseCIDR("10.128.0.0/16")
		_, localToMe, _ := net.ParseCIDR("192.168.1.0/24")
		preferredRanges := []*net.IPNet{localToMe}
		m := NewHostMap("test", myNet, preferredRanges)
		y := NewUDPAddrFromString("10.128.0.3:11111")
		a := NewUDPAddrFromString("10.127.0.3:11111")
		g := NewUDPAddrFromString("1.0.0.1:22222")
		m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), a)
		m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), g)
		m.AddRemote(ip2int(net.ParseIP("10.128.1.1")), y)
	}
}
