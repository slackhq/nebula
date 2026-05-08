package nebula

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trackedHostnameResults builds a *hostnamesResults with a known cancel function and a
// pre-populated ips map so tests can assert cancellation and verify previously-resolved
// IPs survive a cancel without spinning up a real DNS resolver.
func trackedHostnameResults(cancelFn func(), addrs ...string) *hostnamesResults {
	hr := &hostnamesResults{cancelFn: cancelFn}
	ips := map[netip.AddrPort]struct{}{}
	for _, a := range addrs {
		ips[netip.MustParseAddrPort(a)] = struct{}{}
	}
	hr.ips.Store(&ips)
	return hr
}

func TestRemoteList_Rebuild(t *testing.T) {
	rl := NewRemoteList([]netip.Addr{netip.MustParseAddr("0.0.0.0")}, nil)
	rl.unlockedSetV4(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
		[]*V4AddrPort{
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
		func(netip.Addr, *V4AddrPort) bool { return true },
	)

	rl.unlockedSetV6(
		netip.MustParseAddr("0.0.0.1"),
		netip.MustParseAddr("0.0.0.1"),
		[]*V6AddrPort{
			newIp6AndPortFromString("[1::1]:1"), // this is duped
			newIp6AndPortFromString("[1::1]:2"), // almost dupe of 0 with a diff port, also gets duped
			newIp6AndPortFromString("[1:100::1]:1"),
			newIp6AndPortFromString("[1::1]:1"), // this is a dupe
			newIp6AndPortFromString("[1::1]:2"), // this is a dupe
		},
		func(netip.Addr, *V6AddrPort) bool { return true },
	)

	rl.unlockedSetRelay(
		netip.MustParseAddr("0.0.0.1"),
		[]netip.Addr{
			netip.MustParseAddr("1::1"),
			netip.MustParseAddr("1.2.3.4"),
			netip.MustParseAddr("1.2.3.4"),
			netip.MustParseAddr("1::1"),
		},
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

	// assert relay deduplicated
	assert.Len(t, rl.relays, 2)
	assert.Equal(t, "1.2.3.4", rl.relays[0].String())
	assert.Equal(t, "1::1", rl.relays[1].String())

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

func TestRemoteList_ResetForOwner(t *testing.T) {
	ourselves := netip.MustParseAddr("10.0.0.1")
	otherOwner := netip.MustParseAddr("10.0.0.2")
	vpnAddr := netip.MustParseAddr("10.0.0.99")

	rl := NewRemoteList([]netip.Addr{vpnAddr}, nil)
	rl.unlockedSetV4(ourselves, vpnAddr,
		[]*V4AddrPort{newIp4AndPortFromString("1.1.1.1:4242")},
		func(netip.Addr, *V4AddrPort) bool { return true },
	)
	rl.unlockedSetV6(ourselves, vpnAddr,
		[]*V6AddrPort{newIp6AndPortFromString("[1::1]:4242")},
		func(netip.Addr, *V6AddrPort) bool { return true },
	)
	rl.unlockedSetV4(otherOwner, vpnAddr,
		[]*V4AddrPort{newIp4AndPortFromString("2.2.2.2:4242")},
		func(netip.Addr, *V4AddrPort) bool { return true },
	)

	canceled := 0
	hr := trackedHostnameResults(func() { canceled++ }, "3.3.3.3:4242")
	rl.Lock()
	rl.unlockedSetHostnamesResults(hr)
	rl.Unlock()

	rl.ResetForOwner(ourselves)

	rl.RLock()
	defer rl.RUnlock()
	assert.Empty(t, rl.cache[ourselves].v4.reported, "our v4 reported should be cleared")
	assert.Empty(t, rl.cache[ourselves].v6.reported, "our v6 reported should be cleared")
	assert.Len(t, rl.cache[otherOwner].v4.reported, 1, "other owner's contribution must be preserved")
	assert.Equal(t, "2.2.2.2:4242", protoV4AddrPortToNetAddrPort(rl.cache[otherOwner].v4.reported[0]).String())
	assert.Equal(t, 1, canceled, "DNS resolution goroutine should be canceled")
	assert.Same(t, hr, rl.hr, "hostnamesResults must be preserved so DNS-resolved IPs keep feeding addrs until replaced")
	assert.NotEmpty(t, rl.hr.GetAddrs(), "previously-resolved IPs should still be readable after cancel")
	assert.True(t, rl.shouldRebuild, "shouldRebuild must be set so the next Rebuild recomputes addrs")
}

func TestRemoteList_ResetForOwner_NoEntry(t *testing.T) {
	// An owner with no cache entry must not panic; shouldRebuild is still set and any
	// existing hostnamesResults is canceled.
	rl := NewRemoteList([]netip.Addr{netip.MustParseAddr("10.0.0.99")}, nil)
	canceled := 0
	rl.Lock()
	rl.unlockedSetHostnamesResults(trackedHostnameResults(func() { canceled++ }, "3.3.3.3:4242"))
	rl.Unlock()

	rl.ResetForOwner(netip.MustParseAddr("10.0.0.1"))

	rl.RLock()
	defer rl.RUnlock()
	assert.Equal(t, 1, canceled)
	assert.True(t, rl.shouldRebuild)
}

func TestRemoteList_ClearHostnameResults(t *testing.T) {
	rl := NewRemoteList([]netip.Addr{netip.MustParseAddr("10.0.0.99")}, nil)

	canceled := 0
	hr := trackedHostnameResults(func() { canceled++ }, "3.3.3.3:4242")
	rl.Lock()
	rl.unlockedSetHostnamesResults(hr)
	rl.Unlock()
	require.NotEmpty(t, hr.GetAddrs(), "hostnamesResults should have its fastrack IPs populated")

	rl.ClearHostnameResults()

	rl.RLock()
	defer rl.RUnlock()
	assert.Equal(t, 1, canceled, "DNS resolution goroutine should be canceled")
	assert.Nil(t, rl.hr, "hostnamesResults should be dropped")
	assert.True(t, rl.shouldRebuild)
}

func BenchmarkFullRebuild(b *testing.B) {
	rl := NewRemoteList([]netip.Addr{netip.MustParseAddr("0.0.0.0")}, nil)
	rl.unlockedSetV4(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
		[]*V4AddrPort{
			newIp4AndPortFromString("70.199.182.92:1475"),
			newIp4AndPortFromString("172.17.0.182:10101"),
			newIp4AndPortFromString("172.17.1.1:10101"),
			newIp4AndPortFromString("172.18.0.1:10101"),
			newIp4AndPortFromString("172.19.0.1:10101"),
			newIp4AndPortFromString("172.31.0.1:10101"),
			newIp4AndPortFromString("172.17.1.1:10101"),   // this is a dupe
			newIp4AndPortFromString("70.199.182.92:1476"), // dupe of 0 with a diff port
		},
		func(netip.Addr, *V4AddrPort) bool { return true },
	)

	rl.unlockedSetV6(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
		[]*V6AddrPort{
			newIp6AndPortFromString("[1::1]:1"),
			newIp6AndPortFromString("[1::1]:2"), // dupe of 0 with a diff port
			newIp6AndPortFromString("[1:100::1]:1"),
			newIp6AndPortFromString("[1::1]:1"), // this is a dupe
		},
		func(netip.Addr, *V6AddrPort) bool { return true },
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
	rl := NewRemoteList([]netip.Addr{netip.MustParseAddr("0.0.0.0")}, nil)
	rl.unlockedSetV4(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
		[]*V4AddrPort{
			newIp4AndPortFromString("70.199.182.92:1475"),
			newIp4AndPortFromString("172.17.0.182:10101"),
			newIp4AndPortFromString("172.17.1.1:10101"),
			newIp4AndPortFromString("172.18.0.1:10101"),
			newIp4AndPortFromString("172.19.0.1:10101"),
			newIp4AndPortFromString("172.31.0.1:10101"),
			newIp4AndPortFromString("172.17.1.1:10101"),   // this is a dupe
			newIp4AndPortFromString("70.199.182.92:1476"), // dupe of 0 with a diff port
		},
		func(netip.Addr, *V4AddrPort) bool { return true },
	)

	rl.unlockedSetV6(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
		[]*V6AddrPort{
			newIp6AndPortFromString("[1::1]:1"),
			newIp6AndPortFromString("[1::1]:2"), // dupe of 0 with a diff port
			newIp6AndPortFromString("[1:100::1]:1"),
			newIp6AndPortFromString("[1::1]:1"), // this is a dupe
		},
		func(netip.Addr, *V6AddrPort) bool { return true },
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

func newIp4AndPortFromString(s string) *V4AddrPort {
	a := netip.MustParseAddrPort(s)
	v4Addr := a.Addr().As4()
	return &V4AddrPort{
		Addr: binary.BigEndian.Uint32(v4Addr[:]),
		Port: uint32(a.Port()),
	}
}

func newIp6AndPortFromString(s string) *V6AddrPort {
	a := netip.MustParseAddrPort(s)
	v6Addr := a.Addr().As16()
	return &V6AddrPort{
		Hi:   binary.BigEndian.Uint64(v6Addr[:8]),
		Lo:   binary.BigEndian.Uint64(v6Addr[8:]),
		Port: uint32(a.Port()),
	}
}
