package nebula

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

//TODO: Add a test to ensure udpAddr is copied and not reused

func TestOldIPv4Only(t *testing.T) {
	// This test ensures our new ipv6 enabled LH protobuf IpAndPorts works with the old style to enable backwards compatibility
	b := []byte{8, 129, 130, 132, 80, 16, 10}
	var m Ip4AndPort
	err := m.Unmarshal(b)
	assert.NoError(t, err)
	ip := netip.MustParseAddr("10.1.1.1")
	bp := ip.As4()
	assert.Equal(t, binary.BigEndian.Uint32(bp[:]), m.GetIp())
}

func TestNewLhQuery(t *testing.T) {
	myIp, err := netip.ParseAddr("192.1.1.1")
	assert.NoError(t, err)

	// Generating a new lh query should work
	a := NewLhQueryByInt(myIp)

	// The result should be a nebulameta protobuf
	assert.IsType(t, &NebulaMeta{}, a)

	// It should also Marshal fine
	b, err := a.Marshal()
	assert.Nil(t, err)

	// and then Unmarshal fine
	n := &NebulaMeta{}
	err = n.Unmarshal(b)
	assert.Nil(t, err)

}

func Test_lhStaticMapping(t *testing.T) {
	l := test.NewLogger()
	myVpnNet := netip.MustParsePrefix("10.128.0.1/16")
	lh1 := "10.128.0.2"

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[interface{}]interface{}{"hosts": []interface{}{lh1}}
	c.Settings["static_host_map"] = map[interface{}]interface{}{lh1: []interface{}{"1.1.1.1:4242"}}
	_, err := NewLightHouseFromConfig(context.Background(), l, c, myVpnNet, nil, nil)
	assert.Nil(t, err)

	lh2 := "10.128.0.3"
	c = config.NewC(l)
	c.Settings["lighthouse"] = map[interface{}]interface{}{"hosts": []interface{}{lh1, lh2}}
	c.Settings["static_host_map"] = map[interface{}]interface{}{lh1: []interface{}{"100.1.1.1:4242"}}
	_, err = NewLightHouseFromConfig(context.Background(), l, c, myVpnNet, nil, nil)
	assert.EqualError(t, err, "lighthouse 10.128.0.3 does not have a static_host_map entry")
}

func TestReloadLighthouseInterval(t *testing.T) {
	l := test.NewLogger()
	myVpnNet := netip.MustParsePrefix("10.128.0.1/16")
	lh1 := "10.128.0.2"

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"hosts":    []interface{}{lh1},
		"interval": "1s",
	}

	c.Settings["static_host_map"] = map[interface{}]interface{}{lh1: []interface{}{"1.1.1.1:4242"}}
	lh, err := NewLightHouseFromConfig(context.Background(), l, c, myVpnNet, nil, nil)
	assert.NoError(t, err)
	lh.ifce = &mockEncWriter{}

	// The first one routine is kicked off by main.go currently, lets make sure that one dies
	assert.NoError(t, c.ReloadConfigString("lighthouse:\n  interval: 5"))
	assert.Equal(t, int64(5), lh.interval.Load())

	// Subsequent calls are killed off by the LightHouse.Reload function
	assert.NoError(t, c.ReloadConfigString("lighthouse:\n  interval: 10"))
	assert.Equal(t, int64(10), lh.interval.Load())

	// If this completes then nothing is stealing our reload routine
	assert.NoError(t, c.ReloadConfigString("lighthouse:\n  interval: 11"))
	assert.Equal(t, int64(11), lh.interval.Load())
}

func BenchmarkLighthouseHandleRequest(b *testing.B) {
	l := test.NewLogger()
	myVpnNet := netip.MustParsePrefix("10.128.0.1/0")

	c := config.NewC(l)
	lh, err := NewLightHouseFromConfig(context.Background(), l, c, myVpnNet, nil, nil)
	if !assert.NoError(b, err) {
		b.Fatal()
	}

	hAddr := netip.MustParseAddrPort("4.5.6.7:12345")
	hAddr2 := netip.MustParseAddrPort("4.5.6.7:12346")

	vpnIp3 := netip.MustParseAddr("0.0.0.3")
	lh.addrMap[vpnIp3] = NewRemoteList(nil)
	lh.addrMap[vpnIp3].unlockedSetV4(
		vpnIp3,
		vpnIp3,
		[]*Ip4AndPort{
			NewIp4AndPortFromNetIP(hAddr.Addr(), hAddr.Port()),
			NewIp4AndPortFromNetIP(hAddr2.Addr(), hAddr2.Port()),
		},
		func(netip.Addr, *Ip4AndPort) bool { return true },
	)

	rAddr := netip.MustParseAddrPort("1.2.2.3:12345")
	rAddr2 := netip.MustParseAddrPort("1.2.2.3:12346")
	vpnIp2 := netip.MustParseAddr("0.0.0.3")
	lh.addrMap[vpnIp2] = NewRemoteList(nil)
	lh.addrMap[vpnIp2].unlockedSetV4(
		vpnIp3,
		vpnIp3,
		[]*Ip4AndPort{
			NewIp4AndPortFromNetIP(rAddr.Addr(), rAddr.Port()),
			NewIp4AndPortFromNetIP(rAddr2.Addr(), rAddr2.Port()),
		},
		func(netip.Addr, *Ip4AndPort) bool { return true },
	)

	mw := &mockEncWriter{}

	b.Run("notfound", func(b *testing.B) {
		lhh := lh.NewRequestHandler()
		req := &NebulaMeta{
			Type: NebulaMeta_HostQuery,
			Details: &NebulaMetaDetails{
				VpnIp:       4,
				Ip4AndPorts: nil,
			},
		}
		p, err := req.Marshal()
		assert.NoError(b, err)
		for n := 0; n < b.N; n++ {
			lhh.HandleRequest(rAddr, vpnIp2, p, mw)
		}
	})
	b.Run("found", func(b *testing.B) {
		lhh := lh.NewRequestHandler()
		req := &NebulaMeta{
			Type: NebulaMeta_HostQuery,
			Details: &NebulaMetaDetails{
				VpnIp:       3,
				Ip4AndPorts: nil,
			},
		}
		p, err := req.Marshal()
		assert.NoError(b, err)

		for n := 0; n < b.N; n++ {
			lhh.HandleRequest(rAddr, vpnIp2, p, mw)
		}
	})
}

func TestLighthouse_Memory(t *testing.T) {
	l := test.NewLogger()

	myUdpAddr0 := netip.MustParseAddrPort("10.0.0.2:4242")
	myUdpAddr1 := netip.MustParseAddrPort("192.168.0.2:4242")
	myUdpAddr2 := netip.MustParseAddrPort("172.16.0.2:4242")
	myUdpAddr3 := netip.MustParseAddrPort("100.152.0.2:4242")
	myUdpAddr4 := netip.MustParseAddrPort("24.15.0.2:4242")
	myUdpAddr5 := netip.MustParseAddrPort("192.168.0.2:4243")
	myUdpAddr6 := netip.MustParseAddrPort("192.168.0.2:4244")
	myUdpAddr7 := netip.MustParseAddrPort("192.168.0.2:4245")
	myUdpAddr8 := netip.MustParseAddrPort("192.168.0.2:4246")
	myUdpAddr9 := netip.MustParseAddrPort("192.168.0.2:4247")
	myUdpAddr10 := netip.MustParseAddrPort("192.168.0.2:4248")
	myUdpAddr11 := netip.MustParseAddrPort("192.168.0.2:4249")
	myVpnIp := netip.MustParseAddr("10.128.0.2")

	theirUdpAddr0 := netip.MustParseAddrPort("10.0.0.3:4242")
	theirUdpAddr1 := netip.MustParseAddrPort("192.168.0.3:4242")
	theirUdpAddr2 := netip.MustParseAddrPort("172.16.0.3:4242")
	theirUdpAddr3 := netip.MustParseAddrPort("100.152.0.3:4242")
	theirUdpAddr4 := netip.MustParseAddrPort("24.15.0.3:4242")
	theirVpnIp := netip.MustParseAddr("10.128.0.3")

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[interface{}]interface{}{"am_lighthouse": true}
	c.Settings["listen"] = map[interface{}]interface{}{"port": 4242}
	lh, err := NewLightHouseFromConfig(context.Background(), l, c, netip.MustParsePrefix("10.128.0.1/24"), nil, nil)
	assert.NoError(t, err)
	lhh := lh.NewRequestHandler()

	// Test that my first update responds with just that
	newLHHostUpdate(myUdpAddr0, myVpnIp, []netip.AddrPort{myUdpAddr1, myUdpAddr2}, lhh)
	r := newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.Ip4AndPorts, myUdpAddr1, myUdpAddr2)

	// Ensure we don't accumulate addresses
	newLHHostUpdate(myUdpAddr0, myVpnIp, []netip.AddrPort{myUdpAddr3}, lhh)
	r = newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.Ip4AndPorts, myUdpAddr3)

	// Grow it back to 2
	newLHHostUpdate(myUdpAddr0, myVpnIp, []netip.AddrPort{myUdpAddr1, myUdpAddr4}, lhh)
	r = newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.Ip4AndPorts, myUdpAddr1, myUdpAddr4)

	// Update a different host and ask about it
	newLHHostUpdate(theirUdpAddr0, theirVpnIp, []netip.AddrPort{theirUdpAddr1, theirUdpAddr2, theirUdpAddr3, theirUdpAddr4}, lhh)
	r = newLHHostRequest(theirUdpAddr0, theirVpnIp, theirVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.Ip4AndPorts, theirUdpAddr1, theirUdpAddr2, theirUdpAddr3, theirUdpAddr4)

	// Have both hosts ask about the other
	r = newLHHostRequest(theirUdpAddr0, theirVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.Ip4AndPorts, myUdpAddr1, myUdpAddr4)

	r = newLHHostRequest(myUdpAddr0, myVpnIp, theirVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.Ip4AndPorts, theirUdpAddr1, theirUdpAddr2, theirUdpAddr3, theirUdpAddr4)

	// Make sure we didn't get changed
	r = newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.Ip4AndPorts, myUdpAddr1, myUdpAddr4)

	// Ensure proper ordering and limiting
	// Send 12 addrs, get 10 back, the last 2 removed, allowing the duplicate to remain (clients dedupe)
	newLHHostUpdate(
		myUdpAddr0,
		myVpnIp,
		[]netip.AddrPort{
			myUdpAddr1,
			myUdpAddr2,
			myUdpAddr3,
			myUdpAddr4,
			myUdpAddr5,
			myUdpAddr5, //Duplicated on purpose
			myUdpAddr6,
			myUdpAddr7,
			myUdpAddr8,
			myUdpAddr9,
			myUdpAddr10,
			myUdpAddr11, // This should get cut
		}, lhh)

	r = newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(
		t,
		r.msg.Details.Ip4AndPorts,
		myUdpAddr1, myUdpAddr2, myUdpAddr3, myUdpAddr4, myUdpAddr5, myUdpAddr5, myUdpAddr6, myUdpAddr7, myUdpAddr8, myUdpAddr9,
	)

	// Make sure we won't add ips in our vpn network
	bad1 := netip.MustParseAddrPort("10.128.0.99:4242")
	bad2 := netip.MustParseAddrPort("10.128.0.100:4242")
	good := netip.MustParseAddrPort("1.128.0.99:4242")
	newLHHostUpdate(myUdpAddr0, myVpnIp, []netip.AddrPort{bad1, bad2, good}, lhh)
	r = newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.Ip4AndPorts, good)
}

func TestLighthouse_reload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	c.Settings["lighthouse"] = map[interface{}]interface{}{"am_lighthouse": true}
	c.Settings["listen"] = map[interface{}]interface{}{"port": 4242}
	lh, err := NewLightHouseFromConfig(context.Background(), l, c, netip.MustParsePrefix("10.128.0.1/24"), nil, nil)
	assert.NoError(t, err)

	nc := map[interface{}]interface{}{
		"static_host_map": map[interface{}]interface{}{
			"10.128.0.2": []interface{}{"1.1.1.1:4242"},
		},
	}
	rc, err := yaml.Marshal(nc)
	assert.NoError(t, err)
	c.ReloadConfigString(string(rc))

	err = lh.reload(c, false)
	assert.NoError(t, err)
}

func newLHHostRequest(fromAddr netip.AddrPort, myVpnIp, queryVpnIp netip.Addr, lhh *LightHouseHandler) testLhReply {
	//TODO: IPV6-WORK
	bip := queryVpnIp.As4()
	req := &NebulaMeta{
		Type: NebulaMeta_HostQuery,
		Details: &NebulaMetaDetails{
			VpnIp: binary.BigEndian.Uint32(bip[:]),
		},
	}

	b, err := req.Marshal()
	if err != nil {
		panic(err)
	}

	filter := NebulaMeta_HostQueryReply
	w := &testEncWriter{
		metaFilter: &filter,
	}
	lhh.HandleRequest(fromAddr, myVpnIp, b, w)
	return w.lastReply
}

func newLHHostUpdate(fromAddr netip.AddrPort, vpnIp netip.Addr, addrs []netip.AddrPort, lhh *LightHouseHandler) {
	//TODO: IPV6-WORK
	bip := vpnIp.As4()
	req := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotification,
		Details: &NebulaMetaDetails{
			VpnIp:       binary.BigEndian.Uint32(bip[:]),
			Ip4AndPorts: make([]*Ip4AndPort, len(addrs)),
		},
	}

	for k, v := range addrs {
		req.Details.Ip4AndPorts[k] = NewIp4AndPortFromNetIP(v.Addr(), v.Port())
	}

	b, err := req.Marshal()
	if err != nil {
		panic(err)
	}

	w := &testEncWriter{}
	lhh.HandleRequest(fromAddr, vpnIp, b, w)
}

//TODO: this is a RemoteList test
//func Test_lhRemoteAllowList(t *testing.T) {
//	l := NewLogger()
//	c := NewConfig(l)
//	c.Settings["remoteallowlist"] = map[interface{}]interface{}{
//		"10.20.0.0/12": false,
//	}
//	allowList, err := c.GetAllowList("remoteallowlist", false)
//	assert.Nil(t, err)
//
//	lh1 := "10.128.0.2"
//	lh1IP := net.ParseIP(lh1)
//
//	udpServer, _ := NewListener(l, "0.0.0.0", 0, true)
//
//	lh := NewLightHouse(l, true, &net.IPNet{IP: net.IP{0, 0, 0, 1}, Mask: net.IPMask{255, 255, 255, 0}}, []uint32{ip2int(lh1IP)}, 10, 10003, udpServer, false, 1, false)
//	lh.SetRemoteAllowList(allowList)
//
//	// A disallowed ip should not enter the cache but we should end up with an empty entry in the addrMap
//	remote1IP := net.ParseIP("10.20.0.3")
//	remotes := lh.unlockedGetRemoteList(ip2int(remote1IP))
//	remotes.unlockedPrependV4(ip2int(remote1IP), NewIp4AndPort(remote1IP, 4242))
//	assert.NotNil(t, lh.addrMap[ip2int(remote1IP)])
//	assert.Empty(t, lh.addrMap[ip2int(remote1IP)].CopyAddrs([]*net.IPNet{}))
//
//	// Make sure a good ip enters the cache and addrMap
//	remote2IP := net.ParseIP("10.128.0.3")
//	remote2UDPAddr := NewUDPAddr(remote2IP, uint16(4242))
//	lh.addRemoteV4(ip2int(remote2IP), ip2int(remote2IP), NewIp4AndPort(remote2UDPAddr.IP, uint32(remote2UDPAddr.Port)), false, false)
//	assertUdpAddrInArray(t, lh.addrMap[ip2int(remote2IP)].CopyAddrs([]*net.IPNet{}), remote2UDPAddr)
//
//	// Another good ip gets into the cache, ordering is inverted
//	remote3IP := net.ParseIP("10.128.0.4")
//	remote3UDPAddr := NewUDPAddr(remote3IP, uint16(4243))
//	lh.addRemoteV4(ip2int(remote2IP), ip2int(remote2IP), NewIp4AndPort(remote3UDPAddr.IP, uint32(remote3UDPAddr.Port)), false, false)
//	assertUdpAddrInArray(t, lh.addrMap[ip2int(remote2IP)].CopyAddrs([]*net.IPNet{}), remote2UDPAddr, remote3UDPAddr)
//
//	// If we exceed the length limit we should only have the most recent addresses
//	addedAddrs := []*udpAddr{}
//	for i := 0; i < 11; i++ {
//		remoteUDPAddr := NewUDPAddr(net.IP{10, 128, 0, 4}, uint16(4243+i))
//		lh.addRemoteV4(ip2int(remote2IP), ip2int(remote2IP), NewIp4AndPort(remoteUDPAddr.IP, uint32(remoteUDPAddr.Port)), false, false)
//		// The first entry here is a duplicate, don't add it to the assert list
//		if i != 0 {
//			addedAddrs = append(addedAddrs, remoteUDPAddr)
//		}
//	}
//
//	// We should only have the last 10 of what we tried to add
//	assert.True(t, len(addedAddrs) >= 10, "We should have tried to add at least 10 addresses")
//	assertUdpAddrInArray(
//		t,
//		lh.addrMap[ip2int(remote2IP)].CopyAddrs([]*net.IPNet{}),
//		addedAddrs[0],
//		addedAddrs[1],
//		addedAddrs[2],
//		addedAddrs[3],
//		addedAddrs[4],
//		addedAddrs[5],
//		addedAddrs[6],
//		addedAddrs[7],
//		addedAddrs[8],
//		addedAddrs[9],
//	)
//}

type testLhReply struct {
	nebType    header.MessageType
	nebSubType header.MessageSubType
	vpnIp      netip.Addr
	msg        *NebulaMeta
}

type testEncWriter struct {
	lastReply  testLhReply
	metaFilter *NebulaMeta_MessageType
}

func (tw *testEncWriter) SendVia(via *HostInfo, relay *Relay, ad, nb, out []byte, nocopy bool) {
}
func (tw *testEncWriter) Handshake(vpnIp netip.Addr) {
}

func (tw *testEncWriter) SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hostinfo *HostInfo, p, _, _ []byte) {
	msg := &NebulaMeta{}
	err := msg.Unmarshal(p)
	if tw.metaFilter == nil || msg.Type == *tw.metaFilter {
		tw.lastReply = testLhReply{
			nebType:    t,
			nebSubType: st,
			vpnIp:      hostinfo.vpnIp,
			msg:        msg,
		}
	}

	if err != nil {
		panic(err)
	}
}

func (tw *testEncWriter) SendMessageToVpnIp(t header.MessageType, st header.MessageSubType, vpnIp netip.Addr, p, _, _ []byte) {
	msg := &NebulaMeta{}
	err := msg.Unmarshal(p)
	if tw.metaFilter == nil || msg.Type == *tw.metaFilter {
		tw.lastReply = testLhReply{
			nebType:    t,
			nebSubType: st,
			vpnIp:      vpnIp,
			msg:        msg,
		}
	}

	if err != nil {
		panic(err)
	}
}

// assertIp4InArray asserts every address in want is at the same position in have and that the lengths match
func assertIp4InArray(t *testing.T, have []*Ip4AndPort, want ...netip.AddrPort) {
	if !assert.Len(t, have, len(want)) {
		return
	}

	for k, w := range want {
		//TODO: IPV6-WORK
		h := AddrPortFromIp4AndPort(have[k])
		if !(h == w) {
			assert.Fail(t, fmt.Sprintf("Response did not contain: %v at %v, found %v", w, k, h))
		}
	}
}
