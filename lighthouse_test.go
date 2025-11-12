package nebula

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestOldIPv4Only(t *testing.T) {
	// This test ensures our new ipv6 enabled LH protobuf IpAndPorts works with the old style to enable backwards compatibility
	b := []byte{8, 129, 130, 132, 80, 16, 10}
	var m V4AddrPort
	err := m.Unmarshal(b)
	require.NoError(t, err)
	ip := netip.MustParseAddr("10.1.1.1")
	bp := ip.As4()
	assert.Equal(t, binary.BigEndian.Uint32(bp[:]), m.GetAddr())
}

func Test_lhStaticMapping(t *testing.T) {
	l := test.NewLogger()
	myVpnNet := netip.MustParsePrefix("10.128.0.1/16")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}
	lh1 := "10.128.0.2"

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"hosts": []any{lh1}}
	c.Settings["static_host_map"] = map[string]any{lh1: []any{"1.1.1.1:4242"}}
	_, err := NewLightHouseFromConfig(context.Background(), l, c, cs, nil, nil)
	require.NoError(t, err)

	lh2 := "10.128.0.3"
	c = config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"hosts": []any{lh1, lh2}}
	c.Settings["static_host_map"] = map[string]any{lh1: []any{"100.1.1.1:4242"}}
	_, err = NewLightHouseFromConfig(context.Background(), l, c, cs, nil, nil)
	require.EqualError(t, err, "lighthouse 10.128.0.3 does not have a static_host_map entry")
}

func TestReloadLighthouseInterval(t *testing.T) {
	l := test.NewLogger()
	myVpnNet := netip.MustParsePrefix("10.128.0.1/16")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}
	lh1 := "10.128.0.2"

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{
		"hosts":    []any{lh1},
		"interval": "1s",
	}

	c.Settings["static_host_map"] = map[string]any{lh1: []any{"1.1.1.1:4242"}}
	lh, err := NewLightHouseFromConfig(context.Background(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.ifce = &mockEncWriter{}

	// The first one routine is kicked off by main.go currently, lets make sure that one dies
	require.NoError(t, c.ReloadConfigString("lighthouse:\n  interval: 5"))
	assert.Equal(t, int64(5), lh.interval.Load())

	// Subsequent calls are killed off by the LightHouse.Reload function
	require.NoError(t, c.ReloadConfigString("lighthouse:\n  interval: 10"))
	assert.Equal(t, int64(10), lh.interval.Load())

	// If this completes then nothing is stealing our reload routine
	require.NoError(t, c.ReloadConfigString("lighthouse:\n  interval: 11"))
	assert.Equal(t, int64(11), lh.interval.Load())
}

func BenchmarkLighthouseHandleRequest(b *testing.B) {
	l := test.NewLogger()
	myVpnNet := netip.MustParsePrefix("10.128.0.1/0")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	c := config.NewC(l)
	lh, err := NewLightHouseFromConfig(context.Background(), l, c, cs, nil, nil)
	require.NoError(b, err)

	hAddr := netip.MustParseAddrPort("4.5.6.7:12345")
	hAddr2 := netip.MustParseAddrPort("4.5.6.7:12346")

	vpnIp3 := netip.MustParseAddr("0.0.0.3")
	lh.addrMap[vpnIp3] = NewRemoteList([]netip.Addr{vpnIp3}, nil)
	lh.addrMap[vpnIp3].unlockedSetV4(
		vpnIp3,
		vpnIp3,
		[]*V4AddrPort{
			netAddrToProtoV4AddrPort(hAddr.Addr(), hAddr.Port()),
			netAddrToProtoV4AddrPort(hAddr2.Addr(), hAddr2.Port()),
		},
		func(netip.Addr, *V4AddrPort) bool { return true },
	)

	rAddr := netip.MustParseAddrPort("1.2.2.3:12345")
	rAddr2 := netip.MustParseAddrPort("1.2.2.3:12346")
	vpnIp2 := netip.MustParseAddr("0.0.0.3")
	lh.addrMap[vpnIp2] = NewRemoteList([]netip.Addr{vpnIp2}, nil)
	lh.addrMap[vpnIp2].unlockedSetV4(
		vpnIp3,
		vpnIp3,
		[]*V4AddrPort{
			netAddrToProtoV4AddrPort(rAddr.Addr(), rAddr.Port()),
			netAddrToProtoV4AddrPort(rAddr2.Addr(), rAddr2.Port()),
		},
		func(netip.Addr, *V4AddrPort) bool { return true },
	)

	mw := &mockEncWriter{}

	hi := []netip.Addr{vpnIp2}
	b.Run("notfound", func(b *testing.B) {
		lhh := lh.NewRequestHandler()
		req := &NebulaMeta{
			Type: NebulaMeta_HostQuery,
			Details: &NebulaMetaDetails{
				OldVpnAddr:  4,
				V4AddrPorts: nil,
			},
		}
		p, err := req.Marshal()
		require.NoError(b, err)
		for n := 0; n < b.N; n++ {
			lhh.HandleRequest(rAddr, hi, p, mw)
		}
	})
	b.Run("found", func(b *testing.B) {
		lhh := lh.NewRequestHandler()
		req := &NebulaMeta{
			Type: NebulaMeta_HostQuery,
			Details: &NebulaMetaDetails{
				OldVpnAddr:  3,
				V4AddrPorts: nil,
			},
		}
		p, err := req.Marshal()
		require.NoError(b, err)

		for n := 0; n < b.N; n++ {
			lhh.HandleRequest(rAddr, hi, p, mw)
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
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}
	lh, err := NewLightHouseFromConfig(context.Background(), l, c, cs, nil, nil)
	lh.ifce = &mockEncWriter{}
	require.NoError(t, err)
	lhh := lh.NewRequestHandler()

	// Test that my first update responds with just that
	newLHHostUpdate(myUdpAddr0, myVpnIp, []netip.AddrPort{myUdpAddr1, myUdpAddr2}, lhh)
	r := newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.V4AddrPorts, myUdpAddr1, myUdpAddr2)

	// Ensure we don't accumulate addresses
	newLHHostUpdate(myUdpAddr0, myVpnIp, []netip.AddrPort{myUdpAddr3}, lhh)
	r = newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.V4AddrPorts, myUdpAddr3)

	// Grow it back to 2
	newLHHostUpdate(myUdpAddr0, myVpnIp, []netip.AddrPort{myUdpAddr1, myUdpAddr4}, lhh)
	r = newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.V4AddrPorts, myUdpAddr1, myUdpAddr4)

	// Update a different host and ask about it
	newLHHostUpdate(theirUdpAddr0, theirVpnIp, []netip.AddrPort{theirUdpAddr1, theirUdpAddr2, theirUdpAddr3, theirUdpAddr4}, lhh)
	r = newLHHostRequest(theirUdpAddr0, theirVpnIp, theirVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.V4AddrPorts, theirUdpAddr1, theirUdpAddr2, theirUdpAddr3, theirUdpAddr4)

	// Have both hosts ask about the other
	r = newLHHostRequest(theirUdpAddr0, theirVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.V4AddrPorts, myUdpAddr1, myUdpAddr4)

	r = newLHHostRequest(myUdpAddr0, myVpnIp, theirVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.V4AddrPorts, theirUdpAddr1, theirUdpAddr2, theirUdpAddr3, theirUdpAddr4)

	// Make sure we didn't get changed
	r = newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.V4AddrPorts, myUdpAddr1, myUdpAddr4)

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
		r.msg.Details.V4AddrPorts,
		myUdpAddr1, myUdpAddr2, myUdpAddr3, myUdpAddr4, myUdpAddr5, myUdpAddr5, myUdpAddr6, myUdpAddr7, myUdpAddr8, myUdpAddr9,
	)

	// Make sure we won't add ips in our vpn network
	bad1 := netip.MustParseAddrPort("10.128.0.99:4242")
	bad2 := netip.MustParseAddrPort("10.128.0.100:4242")
	good := netip.MustParseAddrPort("1.128.0.99:4242")
	newLHHostUpdate(myUdpAddr0, myVpnIp, []netip.AddrPort{bad1, bad2, good}, lhh)
	r = newLHHostRequest(myUdpAddr0, myVpnIp, myVpnIp, lhh)
	assertIp4InArray(t, r.msg.Details.V4AddrPorts, good)
}

func TestLighthouse_reload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	lh, err := NewLightHouseFromConfig(context.Background(), l, c, cs, nil, nil)
	require.NoError(t, err)

	nc := map[string]any{
		"static_host_map": map[string]any{
			"10.128.0.2": []any{"1.1.1.1:4242"},
		},
	}
	rc, err := yaml.Marshal(nc)
	require.NoError(t, err)
	c.ReloadConfigString(string(rc))

	err = lh.reload(c, false)
	require.NoError(t, err)
}

func newLHHostRequest(fromAddr netip.AddrPort, myVpnIp, queryVpnIp netip.Addr, lhh *LightHouseHandler) testLhReply {
	req := &NebulaMeta{
		Type:    NebulaMeta_HostQuery,
		Details: &NebulaMetaDetails{},
	}

	if queryVpnIp.Is4() {
		bip := queryVpnIp.As4()
		req.Details.OldVpnAddr = binary.BigEndian.Uint32(bip[:])
	} else {
		req.Details.VpnAddr = netAddrToProtoAddr(queryVpnIp)
	}

	b, err := req.Marshal()
	if err != nil {
		panic(err)
	}

	filter := NebulaMeta_HostQueryReply
	w := &testEncWriter{
		metaFilter: &filter,
	}
	lhh.HandleRequest(fromAddr, []netip.Addr{myVpnIp}, b, w)
	return w.lastReply
}

func newLHHostUpdate(fromAddr netip.AddrPort, vpnIp netip.Addr, addrs []netip.AddrPort, lhh *LightHouseHandler) {
	req := &NebulaMeta{
		Type:    NebulaMeta_HostUpdateNotification,
		Details: &NebulaMetaDetails{},
	}

	if vpnIp.Is4() {
		bip := vpnIp.As4()
		req.Details.OldVpnAddr = binary.BigEndian.Uint32(bip[:])
	} else {
		req.Details.VpnAddr = netAddrToProtoAddr(vpnIp)
	}

	for _, v := range addrs {
		if v.Addr().Is4() {
			req.Details.V4AddrPorts = append(req.Details.V4AddrPorts, netAddrToProtoV4AddrPort(v.Addr(), v.Port()))
		} else {
			req.Details.V6AddrPorts = append(req.Details.V6AddrPorts, netAddrToProtoV6AddrPort(v.Addr(), v.Port()))
		}
	}

	b, err := req.Marshal()
	if err != nil {
		panic(err)
	}

	w := &testEncWriter{}
	lhh.HandleRequest(fromAddr, []netip.Addr{vpnIp}, b, w)
}

type testLhReply struct {
	nebType    header.MessageType
	nebSubType header.MessageSubType
	vpnIp      netip.Addr
	msg        *NebulaMeta
}

type testEncWriter struct {
	lastReply       testLhReply
	metaFilter      *NebulaMeta_MessageType
	protocolVersion cert.Version
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
			vpnIp:      hostinfo.vpnAddrs[0],
			msg:        msg,
		}
	}

	if err != nil {
		panic(err)
	}
}

func (tw *testEncWriter) SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, vpnIp netip.Addr, p, _, _ []byte) {
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

func (tw *testEncWriter) GetHostInfo(vpnIp netip.Addr) *HostInfo {
	return nil
}

func (tw *testEncWriter) GetCertState() *CertState {
	return &CertState{initiatingVersion: tw.protocolVersion}
}

// assertIp4InArray asserts every address in want is at the same position in have and that the lengths match
func assertIp4InArray(t *testing.T, have []*V4AddrPort, want ...netip.AddrPort) {
	if !assert.Len(t, have, len(want)) {
		return
	}

	for k, w := range want {
		h := protoV4AddrPortToNetAddrPort(have[k])
		if !(h == w) {
			assert.Fail(t, fmt.Sprintf("Response did not contain: %v at %v, found %v", w, k, h))
		}
	}
}

func Test_findNetworkUnion(t *testing.T) {
	var out netip.Addr
	var ok bool

	tenDot := netip.MustParsePrefix("10.0.0.0/8")
	oneSevenTwo := netip.MustParsePrefix("172.16.0.0/16")
	fe80 := netip.MustParsePrefix("fe80::/8")
	fc00 := netip.MustParsePrefix("fc00::/7")

	a1 := netip.MustParseAddr("10.0.0.1")
	afe81 := netip.MustParseAddr("fe80::1")

	//simple
	out, ok = findNetworkUnion([]netip.Prefix{tenDot}, []netip.Addr{a1})
	assert.True(t, ok)
	assert.Equal(t, out, a1)

	//mixed lengths
	out, ok = findNetworkUnion([]netip.Prefix{tenDot}, []netip.Addr{a1, afe81})
	assert.True(t, ok)
	assert.Equal(t, out, a1)
	out, ok = findNetworkUnion([]netip.Prefix{tenDot, oneSevenTwo}, []netip.Addr{a1})
	assert.True(t, ok)
	assert.Equal(t, out, a1)

	//mixed family
	out, ok = findNetworkUnion([]netip.Prefix{tenDot, oneSevenTwo, fe80}, []netip.Addr{a1})
	assert.True(t, ok)
	assert.Equal(t, out, a1)
	out, ok = findNetworkUnion([]netip.Prefix{tenDot, oneSevenTwo, fe80}, []netip.Addr{a1, afe81})
	assert.True(t, ok)
	assert.Equal(t, out, a1)

	//ordering
	out, ok = findNetworkUnion([]netip.Prefix{tenDot, oneSevenTwo, fe80}, []netip.Addr{afe81, a1})
	assert.True(t, ok)
	assert.Equal(t, out, a1)
	out, ok = findNetworkUnion([]netip.Prefix{fe80, tenDot, oneSevenTwo}, []netip.Addr{afe81, a1})
	assert.True(t, ok)
	assert.Equal(t, out, afe81)

	//some mismatches
	out, ok = findNetworkUnion([]netip.Prefix{tenDot, oneSevenTwo, fe80}, []netip.Addr{afe81})
	assert.True(t, ok)
	assert.Equal(t, out, afe81)
	out, ok = findNetworkUnion([]netip.Prefix{oneSevenTwo, fe80}, []netip.Addr{a1, afe81})
	assert.True(t, ok)
	assert.Equal(t, out, afe81)

	//falsey cases
	out, ok = findNetworkUnion([]netip.Prefix{oneSevenTwo, fe80}, []netip.Addr{a1})
	assert.False(t, ok)
	out, ok = findNetworkUnion([]netip.Prefix{fc00, fe80}, []netip.Addr{a1})
	assert.False(t, ok)
	out, ok = findNetworkUnion([]netip.Prefix{oneSevenTwo, fc00}, []netip.Addr{a1, afe81})
	assert.False(t, ok)
	out, ok = findNetworkUnion([]netip.Prefix{fc00}, []netip.Addr{a1, afe81})
	assert.False(t, ok)
}

func TestLighthouse_Dont_Delete_Static_Hosts(t *testing.T) {
	l := test.NewLogger()

	myUdpAddr2 := netip.MustParseAddrPort("1.2.3.4:4242")

	testSameHostNotStatic := netip.MustParseAddr("10.128.0.41")
	testStaticHost := netip.MustParseAddr("10.128.0.42")
	//myVpnIp := netip.MustParseAddr("10.128.0.2")

	c := config.NewC(l)
	lh1 := "10.128.0.2"
	c.Settings["lighthouse"] = map[string]any{
		"hosts":    []any{lh1},
		"interval": "1s",
	}

	c.Settings["listen"] = map[string]any{"port": 4242}
	c.Settings["static_host_map"] = map[string]any{
		lh1:           []any{"1.1.1.1:4242"},
		"10.128.0.42": []any{"1.2.3.4:4242"},
	}

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}
	lh, err := NewLightHouseFromConfig(context.Background(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.ifce = &mockEncWriter{}

	//test that we actually have the static entry:
	out := lh.Query(testStaticHost)
	assert.NotNil(t, out)
	assert.Equal(t, out.vpnAddrs[0], testStaticHost)
	out.Rebuild([]netip.Prefix{}) //why tho
	assert.Equal(t, out.addrs[0], myUdpAddr2)

	//bolt on a lower numbered primary IP
	am := lh.unlockedGetRemoteList([]netip.Addr{testStaticHost})
	am.vpnAddrs = []netip.Addr{testSameHostNotStatic, testStaticHost}
	lh.addrMap[testSameHostNotStatic] = am
	out.Rebuild([]netip.Prefix{}) //???

	//test that we actually have the static entry:
	out = lh.Query(testStaticHost)
	assert.NotNil(t, out)
	assert.Equal(t, out.vpnAddrs[0], testSameHostNotStatic)
	assert.Equal(t, out.vpnAddrs[1], testStaticHost)
	assert.Equal(t, out.addrs[0], myUdpAddr2)

	//test that we actually have the static entry for BOTH:
	out2 := lh.Query(testSameHostNotStatic)
	assert.Same(t, out2, out)

	//now do the delete
	lh.DeleteVpnAddrs([]netip.Addr{testSameHostNotStatic, testStaticHost})
	//verify
	out = lh.Query(testSameHostNotStatic)
	assert.NotNil(t, out)
	if out == nil {
		t.Fatal("expected non-nil query for the static host")
	}
	assert.Equal(t, out.vpnAddrs[0], testSameHostNotStatic)
	assert.Equal(t, out.vpnAddrs[1], testStaticHost)
	assert.Equal(t, out.addrs[0], myUdpAddr2)
}

func TestLighthouse_DeletesWork(t *testing.T) {
	l := test.NewLogger()

	myUdpAddr2 := netip.MustParseAddrPort("1.2.3.4:4242")
	testHost := netip.MustParseAddr("10.128.0.42")

	c := config.NewC(l)
	lh1 := "10.128.0.2"
	c.Settings["lighthouse"] = map[string]any{
		"hosts":    []any{lh1},
		"interval": "1s",
	}

	c.Settings["listen"] = map[string]any{"port": 4242}
	c.Settings["static_host_map"] = map[string]any{
		lh1: []any{"1.1.1.1:4242"},
	}

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}
	lh, err := NewLightHouseFromConfig(context.Background(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.ifce = &mockEncWriter{}

	//insert the host
	am := lh.unlockedGetRemoteList([]netip.Addr{testHost})
	am.vpnAddrs = []netip.Addr{testHost}
	am.addrs = []netip.AddrPort{myUdpAddr2}
	lh.addrMap[testHost] = am
	am.Rebuild([]netip.Prefix{}) //???

	//test that we actually have the entry:
	out := lh.Query(testHost)
	assert.NotNil(t, out)
	assert.Equal(t, out.vpnAddrs[0], testHost)
	out.Rebuild([]netip.Prefix{}) //why tho
	assert.Equal(t, out.addrs[0], myUdpAddr2)

	//now do the delete
	lh.DeleteVpnAddrs([]netip.Addr{testHost})
	//verify
	out = lh.Query(testHost)
	assert.Nil(t, out)
}
