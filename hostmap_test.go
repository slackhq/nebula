package nebula

//TODO: these are almost entirely RemoteList tests
//func TestHostmap(t *testing.T) {
//	l := NewTestLogger()
//	_, myNet, _ := net.ParseCIDR("10.128.0.0/16")
//	_, localToMe, _ := net.ParseCIDR("192.168.1.0/24")
//	myNets := []*net.IPNet{myNet}
//	preferredRanges := []*net.IPNet{localToMe}
//
//	m := NewHostMap(l, "test", myNet, preferredRanges)
//
//	a := NewUDPAddrFromString("10.127.0.3:11111")
//	b := NewUDPAddrFromString("1.0.0.1:22222")
//	y := NewUDPAddrFromString("10.128.0.3:11111")
//	m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), a)
//	m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), b)
//	m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), y)
//
//	info, _ := m.QueryVpnIP(ip2int(net.ParseIP("10.128.1.1")))
//
//	// There should be three remotes in the host map
//	assert.Equal(t, 3, len(info.Remotes))
//
//	// Adding an identical remote should not change the count
//	m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), y)
//	assert.Equal(t, 3, len(info.Remotes))
//
//	// Adding a fresh remote should add one
//	y = NewUDPAddrFromString("10.18.0.3:11111")
//	m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), y)
//	assert.Equal(t, 4, len(info.Remotes))
//
//	// Query and reference remote should get the first one (and not nil)
//	info, _ = m.QueryVpnIP(ip2int(net.ParseIP("10.128.1.1")))
//	assert.NotNil(t, info.remote)
//
//	// Promotion should ensure that the best remote is chosen (y)
//	info.ForcePromoteBest(myNets)
//	assert.True(t, myNet.Contains(info.remote.IP))
//}
//
//func TestHostmapdebug(t *testing.T) {
//	l := NewTestLogger()
//	_, myNet, _ := net.ParseCIDR("10.128.0.0/16")
//	_, localToMe, _ := net.ParseCIDR("192.168.1.0/24")
//	preferredRanges := []*net.IPNet{localToMe}
//	m := NewHostMap(l, "test", myNet, preferredRanges)
//
//	a := NewUDPAddrFromString("10.127.0.3:11111")
//	b := NewUDPAddrFromString("1.0.0.1:22222")
//	y := NewUDPAddrFromString("10.128.0.3:11111")
//	m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), a)
//	m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), b)
//	m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), y)
//
//	//t.Errorf("%s", m.DebugRemotes(1))
//}
//
//func TestHostMap_rotateRemote(t *testing.T) {
//	h := HostInfo{}
//	// 0 remotes, no panic
//	h.rotateRemote()
//	assert.Nil(t, h.remote)
//
//	// 1 remote, no panic
//	h.AddStaticRemote(NewUDPAddr(net.IP{1, 1, 1, 1}, 0))
//	h.rotateRemote()
//	assert.Equal(t, h.remote.IP, net.IP{1, 1, 1, 1})
//
//	h.AddStaticRemote(NewUDPAddr(net.IP{1, 1, 1, 2}, 0))
//	h.AddStaticRemote(NewUDPAddr(net.IP{1, 1, 1, 3}, 0))
//	h.AddStaticRemote(NewUDPAddr(net.IP{1, 1, 1, 4}, 0))
//
//	//TODO: ensure we are copying and not storing the slice!
//
//	// Rotate through those 3
//	h.rotateRemote()
//	assert.Equal(t, h.remote.IP, net.IP{1, 1, 1, 2})
//
//	h.rotateRemote()
//	assert.Equal(t, h.remote.IP, net.IP{1, 1, 1, 3})
//
//	h.rotateRemote()
//	assert.Equal(t, h.remote, &udpAddr{IP: net.IP{1, 1, 1, 4}, Port: 0})
//
//	// Finally, we should start over
//	h.rotateRemote()
//	assert.Equal(t, h.remote, &udpAddr{IP: net.IP{1, 1, 1, 1}, Port: 0})
//}
//
//func BenchmarkHostmappromote2(b *testing.B) {
//	l := NewTestLogger()
//	for n := 0; n < b.N; n++ {
//		_, myNet, _ := net.ParseCIDR("10.128.0.0/16")
//		_, localToMe, _ := net.ParseCIDR("192.168.1.0/24")
//		preferredRanges := []*net.IPNet{localToMe}
//		m := NewHostMap(l, "test", myNet, preferredRanges)
//		y := NewUDPAddrFromString("10.128.0.3:11111")
//		a := NewUDPAddrFromString("10.127.0.3:11111")
//		g := NewUDPAddrFromString("1.0.0.1:22222")
//		m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), a)
//		m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), g)
//		m.AddStaticRemote(ip2int(net.ParseIP("10.128.1.1")), y)
//	}
//}
