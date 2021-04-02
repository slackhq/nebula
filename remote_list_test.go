package nebula

import (
	"net"
	"testing"
)

//func TestRemoteList_UnlockedGetAddrs(t *testing.T) {
//	rl := NewRemoteList()
//	// Only add reported ips, ensures we don't panic on nil learned. Set replaces so make sure to use a new ownerVpnIp each time
//	rl.unlockedSetV4(0, []*Ip4AndPort{NewIp4AndPort(net.ParseIP("10.0.0.1"), 4242)})
//	rl.unlockedSetV4(1, []*Ip4AndPort{NewIp4AndPort(net.ParseIP("10.0.0.1"), 4243)})
//	rl.unlockedSetV4(2, []*Ip4AndPort{NewIp4AndPort(net.ParseIP("10.0.0.2"), 4242)})
//	rl.unlockedSetV4(3, []*Ip4AndPort{NewIp4AndPort(net.ParseIP("10.0.0.2"), 4242)})
//	rl.unlockedSetV4(4, []*Ip4AndPort{NewIp4AndPort(net.ParseIP("10.0.0.2"), 4243)})
//	rl.unlockedSetV4(5, []*Ip4AndPort{NewIp4AndPort(net.ParseIP("10.0.0.2"), 4243)})
//	//rl.unlockedDeduplicate()
//
//	f := rl.GetNext()
//	t.Log(f)
//	rl.GetNext()
//	rl.unlockedSetV4(6, []*Ip4AndPort{NewIp4AndPort(net.ParseIP("10.0.0.1"), 1)})
//	rl.GetNext()
//	t.Log(f)
//
//	a := make([]int, 10)
//	for i := 0; i < len(a); i++ {
//		a[i] = rand.Int()
//	}
//	sort.Slice(a, func(i, j int) bool {
//		if i < j {
//			t.Log("FUCKER", i, j)
//		}
//		if a[i] < a[j] {
//			return true
//		}
//
//		return false
//	})
//
//	//TODO: assert order
//}

func TestRemoteList_CopyAddrs(t *testing.T) {
	//TODO: you can't anymore. you are trying to assert sort order because 192.168.5.1 goes public v4 -> private v4 -> v6
	// it should go v6 -> public v4 -> private v4
	rl := NewRemoteList()
	rl.unlockedSetV4(
		0,
		[]*Ip4AndPort{
			{Ip: ip2int(net.ParseIP("70.191.182.92")), Port: 1475},
			{Ip: ip2int(net.ParseIP("172.17.0.182")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.17.1.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.18.0.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.19.0.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.31.0.1")), Port: 10101},
		},
		func(*Ip4AndPort) bool { return true },
	)

	rl.unlockedSetV6(
		0,
		[]*Ip6AndPort{
			NewIp6AndPort(net.ParseIP("1::1"), 1),
			NewIp6AndPort(net.ParseIP("1::1"), 2),
			NewIp6AndPort(net.ParseIP("1:100::1"), 1),
		},
		func(*Ip6AndPort) bool { return true },
	)

	rl.unlockedSort([]*net.IPNet{})
	t.Log(rl.addrs)
}
