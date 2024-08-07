package nebula

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoteList_Rebuild(t *testing.T) {
	rl := NewRemoteList(nil)
	rl.unlockedSetV4(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
		[]*Ip4AndPort{
			newIp4AndPortFromString("70.199.182.92:1475"), // this is duped
			newIp4AndPortFromString("172.17.0.182:10101"),
			newIp4AndPortFromString("172.17.1.1:10101"), // this is duped
			newIp4AndPortFromString("172.18.0.1:10101"), // this is duped
			newIp4AndPortFromString("172.18.0.1:10101"), // this is a dupe
			newIp4AndPortFromString("172.19.0.1:10101"),
			newIp4AndPortFromString("172.31.0.1:10101"),
			newIp4AndPortFromString("172.17.1.1:10101"),   // this is a dupe
			newIp4AndPortFromString("70.199.182.92:1476"), // almost dupe of 0 with a diff port
			newIp4AndPortFromString("70.199.182.92:1475"), // this is a dupe
		},
		func(netip.Addr, *Ip4AndPort) bool { return true },
	)

	rl.unlockedSetV6(
		netip.MustParseAddr("0.0.0.1"),
		netip.MustParseAddr("0.0.0.1"),
		[]*Ip6AndPort{
			newIp6AndPortFromString("[1::1]:1"), // this is duped
			newIp6AndPortFromString("[1::1]:2"), // almost dupe of 0 with a diff port, also gets duped
			newIp6AndPortFromString("[1:100::1]:1"),
			newIp6AndPortFromString("[1::1]:1"), // this is a dupe
			newIp6AndPortFromString("[1::1]:2"), // this is a dupe
		},
		func(netip.Addr, *Ip6AndPort) bool { return true },
	)

	rl.Rebuild([]netip.Prefix{})
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
	rl.Rebuild([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
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
	rl.Rebuild([]netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")})
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
	rl := NewRemoteList(nil)
	rl.unlockedSetV4(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
		[]*Ip4AndPort{
			newIp4AndPortFromString("70.199.182.92:1475"),
			newIp4AndPortFromString("172.17.0.182:10101"),
			newIp4AndPortFromString("172.17.1.1:10101"),
			newIp4AndPortFromString("172.18.0.1:10101"),
			newIp4AndPortFromString("172.19.0.1:10101"),
			newIp4AndPortFromString("172.31.0.1:10101"),
			newIp4AndPortFromString("172.17.1.1:10101"),   // this is a dupe
			newIp4AndPortFromString("70.199.182.92:1476"), // dupe of 0 with a diff port
		},
		func(netip.Addr, *Ip4AndPort) bool { return true },
	)

	rl.unlockedSetV6(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
		[]*Ip6AndPort{
			newIp6AndPortFromString("[1::1]:1"),
			newIp6AndPortFromString("[1::1]:2"), // dupe of 0 with a diff port
			newIp6AndPortFromString("[1:100::1]:1"),
			newIp6AndPortFromString("[1::1]:1"), // this is a dupe
		},
		func(netip.Addr, *Ip6AndPort) bool { return true },
	)

	b.Run("no preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.shouldRebuild = true
			rl.Rebuild([]netip.Prefix{})
		}
	})

	ipNet1 := netip.MustParsePrefix("172.17.0.0/16")
	b.Run("1 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.shouldRebuild = true
			rl.Rebuild([]netip.Prefix{ipNet1})
		}
	})

	ipNet2 := netip.MustParsePrefix("70.0.0.0/8")
	b.Run("2 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.shouldRebuild = true
			rl.Rebuild([]netip.Prefix{ipNet2})
		}
	})

	ipNet3 := netip.MustParsePrefix("0.0.0.0/0")
	b.Run("3 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.shouldRebuild = true
			rl.Rebuild([]netip.Prefix{ipNet1, ipNet2, ipNet3})
		}
	})
}

func BenchmarkSortRebuild(b *testing.B) {
	rl := NewRemoteList(nil)
	rl.unlockedSetV4(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
		[]*Ip4AndPort{
			newIp4AndPortFromString("70.199.182.92:1475"),
			newIp4AndPortFromString("172.17.0.182:10101"),
			newIp4AndPortFromString("172.17.1.1:10101"),
			newIp4AndPortFromString("172.18.0.1:10101"),
			newIp4AndPortFromString("172.19.0.1:10101"),
			newIp4AndPortFromString("172.31.0.1:10101"),
			newIp4AndPortFromString("172.17.1.1:10101"),   // this is a dupe
			newIp4AndPortFromString("70.199.182.92:1476"), // dupe of 0 with a diff port
		},
		func(netip.Addr, *Ip4AndPort) bool { return true },
	)

	rl.unlockedSetV6(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
		[]*Ip6AndPort{
			newIp6AndPortFromString("[1::1]:1"),
			newIp6AndPortFromString("[1::1]:2"), // dupe of 0 with a diff port
			newIp6AndPortFromString("[1:100::1]:1"),
			newIp6AndPortFromString("[1::1]:1"), // this is a dupe
		},
		func(netip.Addr, *Ip6AndPort) bool { return true },
	)

	b.Run("no preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.shouldRebuild = true
			rl.Rebuild([]netip.Prefix{})
		}
	})

	ipNet1 := netip.MustParsePrefix("172.17.0.0/16")
	rl.Rebuild([]netip.Prefix{ipNet1})

	b.Run("1 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.Rebuild([]netip.Prefix{ipNet1})
		}
	})

	ipNet2 := netip.MustParsePrefix("70.0.0.0/8")
	rl.Rebuild([]netip.Prefix{ipNet1, ipNet2})

	b.Run("2 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.Rebuild([]netip.Prefix{ipNet1, ipNet2})
		}
	})

	ipNet3 := netip.MustParsePrefix("0.0.0.0/0")
	rl.Rebuild([]netip.Prefix{ipNet1, ipNet2, ipNet3})

	b.Run("3 preferred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rl.Rebuild([]netip.Prefix{ipNet1, ipNet2, ipNet3})
		}
	})
}

func newIp4AndPortFromString(s string) *Ip4AndPort {
	a := netip.MustParseAddrPort(s)
	v4Addr := a.Addr().As4()
	return &Ip4AndPort{
		Ip:   binary.BigEndian.Uint32(v4Addr[:]),
		Port: uint32(a.Port()),
	}
}

func newIp6AndPortFromString(s string) *Ip6AndPort {
	a := netip.MustParseAddrPort(s)
	v6Addr := a.Addr().As16()
	return &Ip6AndPort{
		Hi:   binary.BigEndian.Uint64(v6Addr[:8]),
		Lo:   binary.BigEndian.Uint64(v6Addr[8:]),
		Port: uint32(a.Port()),
	}
}
