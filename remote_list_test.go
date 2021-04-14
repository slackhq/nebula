package nebula

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoteList_Rebuild(t *testing.T) {
	rl := NewRemoteList()
	rl.unlockedSetV4(
		0,
		[]*Ip4AndPort{
			{Ip: ip2int(net.ParseIP("70.199.182.92")), Port: 1475}, // this is duped
			{Ip: ip2int(net.ParseIP("172.17.0.182")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.17.1.1")), Port: 10101}, // this is duped
			{Ip: ip2int(net.ParseIP("172.18.0.1")), Port: 10101}, // this is duped
			{Ip: ip2int(net.ParseIP("172.18.0.1")), Port: 10101}, // this is a dupe
			{Ip: ip2int(net.ParseIP("172.19.0.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.31.0.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.17.1.1")), Port: 10101},   // this is a dupe
			{Ip: ip2int(net.ParseIP("70.199.182.92")), Port: 1476}, // almost dupe of 0 with a diff port
			{Ip: ip2int(net.ParseIP("70.199.182.92")), Port: 1475}, // this is a dupe
		},
		func(*Ip4AndPort) bool { return true },
	)

	rl.unlockedSetV6(
		1,
		[]*Ip6AndPort{
			NewIp6AndPort(net.ParseIP("1::1"), 1), // this is duped
			NewIp6AndPort(net.ParseIP("1::1"), 2), // almost dupe of 0 with a diff port, also gets duped
			NewIp6AndPort(net.ParseIP("1:100::1"), 1),
			NewIp6AndPort(net.ParseIP("1::1"), 1), // this is a dupe
			NewIp6AndPort(net.ParseIP("1::1"), 2), // this is a dupe
		},
		func(*Ip6AndPort) bool { return true },
	)

	rl.Rebuild([]*net.IPNet{})
	assert.Len(t, rl.addrs, 10, "addrs contains too many entries")

	// ipv6 first, sorted lexically within
	assert.Equal(t, "[1::1]:1", rl.addrs[0].String())
	assert.Equal(t, "[1::1]:2", rl.addrs[1].String())
	assert.Equal(t, "[1:100::1]:1", rl.addrs[2].String())

	// ipv4 last, sorted by public first, then private, lexically within them
	assert.Equal(t, "70.199.182.92:1475", rl.addrs[3].String())
	assert.Equal(t, "70.199.182.92:1476", rl.addrs[4].String())
	assert.Equal(t, "172.17.0.182:10101", rl.addrs[5].String())
	assert.Equal(t, "172.17.1.1:10101", rl.addrs[6].String())
	assert.Equal(t, "172.18.0.1:10101", rl.addrs[7].String())
	assert.Equal(t, "172.19.0.1:10101", rl.addrs[8].String())
	assert.Equal(t, "172.31.0.1:10101", rl.addrs[9].String())

	// Now ensure we can hoist ipv4 up
	_, ipNet, err := net.ParseCIDR("0.0.0.0/0")
	assert.NoError(t, err)
	rl.Rebuild([]*net.IPNet{ipNet})
	assert.Len(t, rl.addrs, 10, "addrs contains too many entries")

	// ipv4 first, public then private, lexically within them
	assert.Equal(t, "70.199.182.92:1475", rl.addrs[0].String())
	assert.Equal(t, "70.199.182.92:1476", rl.addrs[1].String())
	assert.Equal(t, "172.17.0.182:10101", rl.addrs[2].String())
	assert.Equal(t, "172.17.1.1:10101", rl.addrs[3].String())
	assert.Equal(t, "172.18.0.1:10101", rl.addrs[4].String())
	assert.Equal(t, "172.19.0.1:10101", rl.addrs[5].String())
	assert.Equal(t, "172.31.0.1:10101", rl.addrs[6].String())

	// ipv6 last, sorted by public first, then private, lexically within them
	assert.Equal(t, "[1::1]:1", rl.addrs[7].String())
	assert.Equal(t, "[1::1]:2", rl.addrs[8].String())
	assert.Equal(t, "[1:100::1]:1", rl.addrs[9].String())

	// Ensure we can hoist a specific ipv4 range over anything else
	_, ipNet, err = net.ParseCIDR("172.17.0.0/16")
	assert.NoError(t, err)
	rl.Rebuild([]*net.IPNet{ipNet})
	assert.Len(t, rl.addrs, 10, "addrs contains too many entries")

	// Preferred ipv4 first
	assert.Equal(t, "172.17.0.182:10101", rl.addrs[0].String())
	assert.Equal(t, "172.17.1.1:10101", rl.addrs[1].String())

	// ipv6 next
	assert.Equal(t, "[1::1]:1", rl.addrs[2].String())
	assert.Equal(t, "[1::1]:2", rl.addrs[3].String())
	assert.Equal(t, "[1:100::1]:1", rl.addrs[4].String())

	// the remaining ipv4 last
	assert.Equal(t, "70.199.182.92:1475", rl.addrs[5].String())
	assert.Equal(t, "70.199.182.92:1476", rl.addrs[6].String())
	assert.Equal(t, "172.18.0.1:10101", rl.addrs[7].String())
	assert.Equal(t, "172.19.0.1:10101", rl.addrs[8].String())
	assert.Equal(t, "172.31.0.1:10101", rl.addrs[9].String())
}

func BenchmarkFullRebuild(b *testing.B) {
	rl := NewRemoteList()
	rl.unlockedSetV4(
		0,
		[]*Ip4AndPort{
			{Ip: ip2int(net.ParseIP("70.199.182.92")), Port: 1475},
			{Ip: ip2int(net.ParseIP("172.17.0.182")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.17.1.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.18.0.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.19.0.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.31.0.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.17.1.1")), Port: 10101},   // this is a dupe
			{Ip: ip2int(net.ParseIP("70.199.182.92")), Port: 1476}, // dupe of 0 with a diff port
		},
		func(*Ip4AndPort) bool { return true },
	)

	rl.unlockedSetV6(
		0,
		[]*Ip6AndPort{
			NewIp6AndPort(net.ParseIP("1::1"), 1),
			NewIp6AndPort(net.ParseIP("1::1"), 2), // dupe of 0 with a diff port
			NewIp6AndPort(net.ParseIP("1:100::1"), 1),
			NewIp6AndPort(net.ParseIP("1::1"), 1), // this is a dupe
		},
		func(*Ip6AndPort) bool { return true },
	)

	b.Run("no preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.shouldRebuild = true
			rl.Rebuild([]*net.IPNet{})
		}
	})

	_, ipNet, err := net.ParseCIDR("172.17.0.0/16")
	assert.NoError(b, err)
	b.Run("1 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.shouldRebuild = true
			rl.Rebuild([]*net.IPNet{ipNet})
		}
	})

	_, ipNet2, err := net.ParseCIDR("70.0.0.0/8")
	assert.NoError(b, err)
	b.Run("2 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.shouldRebuild = true
			rl.Rebuild([]*net.IPNet{ipNet, ipNet2})
		}
	})

	_, ipNet3, err := net.ParseCIDR("0.0.0.0/0")
	assert.NoError(b, err)
	b.Run("3 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.shouldRebuild = true
			rl.Rebuild([]*net.IPNet{ipNet, ipNet2, ipNet3})
		}
	})
}

func BenchmarkSortRebuild(b *testing.B) {
	rl := NewRemoteList()
	rl.unlockedSetV4(
		0,
		[]*Ip4AndPort{
			{Ip: ip2int(net.ParseIP("70.199.182.92")), Port: 1475},
			{Ip: ip2int(net.ParseIP("172.17.0.182")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.17.1.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.18.0.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.19.0.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.31.0.1")), Port: 10101},
			{Ip: ip2int(net.ParseIP("172.17.1.1")), Port: 10101},   // this is a dupe
			{Ip: ip2int(net.ParseIP("70.199.182.92")), Port: 1476}, // dupe of 0 with a diff port
		},
		func(*Ip4AndPort) bool { return true },
	)

	rl.unlockedSetV6(
		0,
		[]*Ip6AndPort{
			NewIp6AndPort(net.ParseIP("1::1"), 1),
			NewIp6AndPort(net.ParseIP("1::1"), 2), // dupe of 0 with a diff port
			NewIp6AndPort(net.ParseIP("1:100::1"), 1),
			NewIp6AndPort(net.ParseIP("1::1"), 1), // this is a dupe
		},
		func(*Ip6AndPort) bool { return true },
	)

	b.Run("no preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.shouldRebuild = true
			rl.Rebuild([]*net.IPNet{})
		}
	})

	_, ipNet, err := net.ParseCIDR("172.17.0.0/16")
	rl.Rebuild([]*net.IPNet{ipNet})

	assert.NoError(b, err)
	b.Run("1 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.Rebuild([]*net.IPNet{ipNet})
		}
	})

	_, ipNet2, err := net.ParseCIDR("70.0.0.0/8")
	rl.Rebuild([]*net.IPNet{ipNet, ipNet2})

	assert.NoError(b, err)
	b.Run("2 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.Rebuild([]*net.IPNet{ipNet, ipNet2})
		}
	})

	_, ipNet3, err := net.ParseCIDR("0.0.0.0/0")
	rl.Rebuild([]*net.IPNet{ipNet, ipNet2, ipNet3})

	assert.NoError(b, err)
	b.Run("3 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.Rebuild([]*net.IPNet{ipNet, ipNet2, ipNet3})
		}
	})
}
