package nebula

import (
	"bytes"
	"errors"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFirewall(t *testing.T) {
	l := test.NewLogger()
	c := &dummyCert{}
	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	conntrack := fw.Conntrack
	assert.NotNil(t, conntrack)
	assert.NotNil(t, conntrack.Conns)
	assert.NotNil(t, conntrack.TimerWheel)
	assert.NotNil(t, fw.InRules)
	assert.NotNil(t, fw.OutRules)
	assert.Equal(t, time.Second, fw.TCPTimeout)
	assert.Equal(t, time.Minute, fw.UDPTimeout)
	assert.Equal(t, time.Hour, fw.DefaultTimeout)

	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)

	fw = NewFirewall(l, time.Second, time.Hour, time.Minute, c)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)

	fw = NewFirewall(l, time.Hour, time.Second, time.Minute, c)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)

	fw = NewFirewall(l, time.Hour, time.Minute, time.Second, c)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)

	fw = NewFirewall(l, time.Minute, time.Hour, time.Second, c)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)

	fw = NewFirewall(l, time.Minute, time.Second, time.Hour, c)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)
}

func TestFirewall_AddRule(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	c := &dummyCert{}
	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	assert.NotNil(t, fw.InRules)
	assert.NotNil(t, fw.OutRules)

	ti, err := netip.ParsePrefix("1.2.3.4/32")
	require.NoError(t, err)

	ti6, err := netip.ParsePrefix("fd12::34/128")
	require.NoError(t, err)

	require.NoError(t, fw.AddRule(true, firewall.ProtoTCP, 1, 1, []string{}, "", "", "", "", ""))
	// An empty rule is any
	assert.True(t, fw.InRules.TCP[1].Any.Any.Any)
	assert.Empty(t, fw.InRules.TCP[1].Any.Groups)
	assert.Empty(t, fw.InRules.TCP[1].Any.Hosts)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoUDP, 1, 1, []string{"g1"}, "", "", "", "", ""))
	assert.Nil(t, fw.InRules.UDP[1].Any.Any)
	assert.Contains(t, fw.InRules.UDP[1].Any.Groups[0].Groups, "g1")
	assert.Empty(t, fw.InRules.UDP[1].Any.Hosts)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoICMP, 1, 1, []string{}, "h1", "", "", "", ""))
	assert.Nil(t, fw.InRules.ICMP[1].Any.Any)
	assert.Empty(t, fw.InRules.ICMP[1].Any.Groups)
	assert.Contains(t, fw.InRules.ICMP[1].Any.Hosts, "h1")

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 1, 1, []string{}, "", ti.String(), "", "", ""))
	assert.Nil(t, fw.OutRules.AnyProto[1].Any.Any)
	_, ok := fw.OutRules.AnyProto[1].Any.CIDR.Get(ti)
	assert.True(t, ok)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 1, 1, []string{}, "", ti6.String(), "", "", ""))
	assert.Nil(t, fw.OutRules.AnyProto[1].Any.Any)
	_, ok = fw.OutRules.AnyProto[1].Any.CIDR.Get(ti6)
	assert.True(t, ok)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 1, 1, []string{}, "", "", ti.String(), "", ""))
	assert.NotNil(t, fw.OutRules.AnyProto[1].Any.Any)
	ok = fw.OutRules.AnyProto[1].Any.Any.LocalCIDR.Get(ti)
	assert.True(t, ok)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 1, 1, []string{}, "", "", ti6.String(), "", ""))
	assert.NotNil(t, fw.OutRules.AnyProto[1].Any.Any)
	ok = fw.OutRules.AnyProto[1].Any.Any.LocalCIDR.Get(ti6)
	assert.True(t, ok)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoUDP, 1, 1, []string{"g1"}, "", "", "", "ca-name", ""))
	assert.Contains(t, fw.InRules.UDP[1].CANames, "ca-name")

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoUDP, 1, 1, []string{"g1"}, "", "", "", "", "ca-sha"))
	assert.Contains(t, fw.InRules.UDP[1].CAShas, "ca-sha")

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "any", "", "", "", ""))
	assert.True(t, fw.OutRules.AnyProto[0].Any.Any.Any)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	anyIp, err := netip.ParsePrefix("0.0.0.0/0")
	require.NoError(t, err)

	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "", anyIp.String(), "", "", ""))
	assert.Nil(t, fw.OutRules.AnyProto[0].Any.Any)
	table, ok := fw.OutRules.AnyProto[0].Any.CIDR.Lookup(netip.MustParseAddr("1.1.1.1"))
	assert.True(t, table.Any)
	table, ok = fw.OutRules.AnyProto[0].Any.CIDR.Lookup(netip.MustParseAddr("9::9"))
	assert.False(t, ok)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	anyIp6, err := netip.ParsePrefix("::/0")
	require.NoError(t, err)

	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "", anyIp6.String(), "", "", ""))
	assert.Nil(t, fw.OutRules.AnyProto[0].Any.Any)
	table, ok = fw.OutRules.AnyProto[0].Any.CIDR.Lookup(netip.MustParseAddr("9::9"))
	assert.True(t, table.Any)
	table, ok = fw.OutRules.AnyProto[0].Any.CIDR.Lookup(netip.MustParseAddr("1.1.1.1"))
	assert.False(t, ok)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "", "any", "", "", ""))
	assert.True(t, fw.OutRules.AnyProto[0].Any.Any.Any)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "", "", anyIp.String(), "", ""))
	assert.False(t, fw.OutRules.AnyProto[0].Any.Any.Any)
	assert.True(t, fw.OutRules.AnyProto[0].Any.Any.LocalCIDR.Lookup(netip.MustParseAddr("1.1.1.1")))
	assert.False(t, fw.OutRules.AnyProto[0].Any.Any.LocalCIDR.Lookup(netip.MustParseAddr("9::9")))

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "", "", anyIp6.String(), "", ""))
	assert.False(t, fw.OutRules.AnyProto[0].Any.Any.Any)
	assert.True(t, fw.OutRules.AnyProto[0].Any.Any.LocalCIDR.Lookup(netip.MustParseAddr("9::9")))
	assert.False(t, fw.OutRules.AnyProto[0].Any.Any.LocalCIDR.Lookup(netip.MustParseAddr("1.1.1.1")))

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "", "", "any", "", ""))
	assert.True(t, fw.OutRules.AnyProto[0].Any.Any.Any)

	// Test error conditions
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.Error(t, fw.AddRule(true, math.MaxUint8, 0, 0, []string{}, "", "", "", "", ""))
	require.Error(t, fw.AddRule(true, firewall.ProtoAny, 10, 0, []string{}, "", "", "", "", ""))
}

func TestFirewall_Drop(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))
	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("1.2.3.4"),
		RemoteAddr: netip.MustParseAddr("1.2.3.4"),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}

	c := dummyCert{
		name:     "host1",
		networks: []netip.Prefix{netip.MustParsePrefix("1.2.3.4/24")},
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}
	h := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    &c,
				InvertedGroups: map[string]struct{}{"default-group": {}},
			},
		},
		vpnAddrs: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
	}
	h.buildNetworks(myVpnNetworksTable, &c)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	cp := cert.NewCAPool()

	// Drop outbound
	assert.Equal(t, ErrNoMatchingRule, fw.Drop(p, false, &h, cp, nil))
	// Allow inbound
	resetConntrack(fw)
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
	// Allow outbound because conntrack
	require.NoError(t, fw.Drop(p, false, &h, cp, nil))

	// test remote mismatch
	oldRemote := p.RemoteAddr
	p.RemoteAddr = netip.MustParseAddr("1.2.3.10")
	assert.Equal(t, fw.Drop(p, false, &h, cp, nil), ErrInvalidRemoteIP)
	p.RemoteAddr = oldRemote

	// ensure signer doesn't get in the way of group checks
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "", "signer-shasum"))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "", "signer-shasum-bad"))
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caSha doesn't drop on match
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "", "signer-shasum-bad"))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "", "signer-shasum"))
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))

	// ensure ca name doesn't get in the way of group checks
	cp.CAs["signer-shasum"] = &cert.CachedCertificate{Certificate: &dummyCert{name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "ca-good", ""))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "ca-good-bad", ""))
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caName doesn't drop on match
	cp.CAs["signer-shasum"] = &cert.CachedCertificate{Certificate: &dummyCert{name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "ca-good-bad", ""))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "ca-good", ""))
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func TestFirewall_DropV6(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("fd00::/7"))

	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("fd12::34"),
		RemoteAddr: netip.MustParseAddr("fd12::34"),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}

	c := dummyCert{
		name:     "host1",
		networks: []netip.Prefix{netip.MustParsePrefix("fd12::34/120")},
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}
	h := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    &c,
				InvertedGroups: map[string]struct{}{"default-group": {}},
			},
		},
		vpnAddrs: []netip.Addr{netip.MustParseAddr("fd12::34")},
	}
	h.buildNetworks(myVpnNetworksTable, &c)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	cp := cert.NewCAPool()

	// Drop outbound
	assert.Equal(t, ErrNoMatchingRule, fw.Drop(p, false, &h, cp, nil))
	// Allow inbound
	resetConntrack(fw)
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
	// Allow outbound because conntrack
	require.NoError(t, fw.Drop(p, false, &h, cp, nil))

	// test remote mismatch
	oldRemote := p.RemoteAddr
	p.RemoteAddr = netip.MustParseAddr("fd12::56")
	assert.Equal(t, fw.Drop(p, false, &h, cp, nil), ErrInvalidRemoteIP)
	p.RemoteAddr = oldRemote

	// ensure signer doesn't get in the way of group checks
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "", "signer-shasum"))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "", "signer-shasum-bad"))
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caSha doesn't drop on match
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "", "signer-shasum-bad"))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "", "signer-shasum"))
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))

	// ensure ca name doesn't get in the way of group checks
	cp.CAs["signer-shasum"] = &cert.CachedCertificate{Certificate: &dummyCert{name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "ca-good", ""))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "ca-good-bad", ""))
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caName doesn't drop on match
	cp.CAs["signer-shasum"] = &cert.CachedCertificate{Certificate: &dummyCert{name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "ca-good-bad", ""))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "ca-good", ""))
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func BenchmarkFirewallTable_match(b *testing.B) {
	f := &Firewall{}
	ft := FirewallTable{
		TCP: firewallPort{},
	}

	pfix := netip.MustParsePrefix("172.1.1.1/32")
	_ = ft.TCP.addRule(f, 10, 10, []string{"good-group"}, "good-host", pfix.String(), "", "", "")
	_ = ft.TCP.addRule(f, 100, 100, []string{"good-group"}, "good-host", "", pfix.String(), "", "")

	pfix6 := netip.MustParsePrefix("fd11::11/128")
	_ = ft.TCP.addRule(f, 10, 10, []string{"good-group"}, "good-host", pfix6.String(), "", "", "")
	_ = ft.TCP.addRule(f, 100, 100, []string{"good-group"}, "good-host", "", pfix6.String(), "", "")
	cp := cert.NewCAPool()

	b.Run("fail on proto", func(b *testing.B) {
		// This benchmark is showing us the cost of failing to match the protocol
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{},
		}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoUDP}, true, c, cp))
		}
	})

	b.Run("pass proto, fail on port", func(b *testing.B) {
		// This benchmark is showing us the cost of matching a specific protocol but failing to match the port
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{},
		}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 1}, true, c, cp))
		}
	})

	b.Run("pass proto, port, fail on local CIDR", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{},
		}
		ip := netip.MustParsePrefix("9.254.254.254/32")
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, LocalAddr: ip.Addr()}, true, c, cp))
		}
	})
	b.Run("pass proto, port, fail on local CIDRv6", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{},
		}
		ip := netip.MustParsePrefix("fd99::99/128")
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, LocalAddr: ip.Addr()}, true, c, cp))
		}
	})

	b.Run("pass proto, port, any local CIDR, fail all group, name, and cidr", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{
				name:     "nope",
				networks: []netip.Prefix{netip.MustParsePrefix("9.254.254.245/32")},
			},
			InvertedGroups: map[string]struct{}{"nope": {}},
		}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 10}, true, c, cp))
		}
	})
	b.Run("pass proto, port, any local CIDRv6, fail all group, name, and cidr", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{
				name:     "nope",
				networks: []netip.Prefix{netip.MustParsePrefix("fd99::99/128")},
			},
			InvertedGroups: map[string]struct{}{"nope": {}},
		}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 10}, true, c, cp))
		}
	})

	b.Run("pass proto, port, specific local CIDR, fail all group, name, and cidr", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{
				name:     "nope",
				networks: []netip.Prefix{netip.MustParsePrefix("9.254.254.245/32")},
			},
			InvertedGroups: map[string]struct{}{"nope": {}},
		}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, LocalAddr: pfix.Addr()}, true, c, cp))
		}
	})
	b.Run("pass proto, port, specific local CIDRv6, fail all group, name, and cidr", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{
				name:     "nope",
				networks: []netip.Prefix{netip.MustParsePrefix("fd99::99/128")},
			},
			InvertedGroups: map[string]struct{}{"nope": {}},
		}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, LocalAddr: pfix6.Addr()}, true, c, cp))
		}
	})

	b.Run("pass on group on any local cidr", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{
				name: "nope",
			},
			InvertedGroups: map[string]struct{}{"good-group": {}},
		}
		for n := 0; n < b.N; n++ {
			assert.True(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 10}, true, c, cp))
		}
	})

	b.Run("pass on group on specific local cidr", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{
				name: "nope",
			},
			InvertedGroups: map[string]struct{}{"good-group": {}},
		}
		for n := 0; n < b.N; n++ {
			assert.True(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, LocalAddr: pfix.Addr()}, true, c, cp))
		}
	})
	b.Run("pass on group on specific local cidr6", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{
				name: "nope",
			},
			InvertedGroups: map[string]struct{}{"good-group": {}},
		}
		for n := 0; n < b.N; n++ {
			assert.True(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, LocalAddr: pfix6.Addr()}, true, c, cp))
		}
	})

	b.Run("pass on name", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{
				name: "good-host",
			},
			InvertedGroups: map[string]struct{}{"nope": {}},
		}
		for n := 0; n < b.N; n++ {
			ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 10}, true, c, cp)
		}
	})
}

func TestFirewall_Drop2(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))

	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("1.2.3.4"),
		RemoteAddr: netip.MustParseAddr("1.2.3.4"),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}

	network := netip.MustParsePrefix("1.2.3.4/24")

	c := cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "host1",
			networks: []netip.Prefix{network},
		},
		InvertedGroups: map[string]struct{}{"default-group": {}, "test-group": {}},
	}
	h := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c,
		},
		vpnAddrs: []netip.Addr{network.Addr()},
	}
	h.buildNetworks(myVpnNetworksTable, c.Certificate)

	c1 := cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "host1",
			networks: []netip.Prefix{network},
		},
		InvertedGroups: map[string]struct{}{"default-group": {}, "test-group-not": {}},
	}
	h1 := HostInfo{
		vpnAddrs: []netip.Addr{network.Addr()},
		ConnectionState: &ConnectionState{
			peerCert: &c1,
		},
	}
	h1.buildNetworks(myVpnNetworksTable, c1.Certificate)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group", "test-group"}, "", "", "", "", ""))
	cp := cert.NewCAPool()

	// h1/c1 lacks the proper groups
	require.ErrorIs(t, fw.Drop(p, true, &h1, cp, nil), ErrNoMatchingRule)
	// c has the proper groups
	resetConntrack(fw)
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func TestFirewall_Drop3(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))

	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("1.2.3.4"),
		RemoteAddr: netip.MustParseAddr("1.2.3.4"),
		LocalPort:  1,
		RemotePort: 1,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}

	network := netip.MustParsePrefix("1.2.3.4/24")
	c := cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "host-owner",
			networks: []netip.Prefix{network},
		},
	}

	c1 := cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "host1",
			networks: []netip.Prefix{network},
			issuer:   "signer-sha-bad",
		},
	}
	h1 := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c1,
		},
		vpnAddrs: []netip.Addr{network.Addr()},
	}
	h1.buildNetworks(myVpnNetworksTable, c1.Certificate)

	c2 := cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "host2",
			networks: []netip.Prefix{network},
			issuer:   "signer-sha",
		},
	}
	h2 := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c2,
		},
		vpnAddrs: []netip.Addr{network.Addr()},
	}
	h2.buildNetworks(myVpnNetworksTable, c2.Certificate)

	c3 := cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "host3",
			networks: []netip.Prefix{network},
			issuer:   "signer-sha-bad",
		},
	}
	h3 := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c3,
		},
		vpnAddrs: []netip.Addr{network.Addr()},
	}
	h3.buildNetworks(myVpnNetworksTable, c3.Certificate)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "host1", "", "", "", ""))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", "", "", "", "signer-sha"))
	cp := cert.NewCAPool()

	// c1 should pass because host match
	require.NoError(t, fw.Drop(p, true, &h1, cp, nil))
	// c2 should pass because ca sha match
	resetConntrack(fw)
	require.NoError(t, fw.Drop(p, true, &h2, cp, nil))
	// c3 should fail because no match
	resetConntrack(fw)
	assert.Equal(t, fw.Drop(p, true, &h3, cp, nil), ErrNoMatchingRule)

	// Test a remote address match
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", "1.2.3.4/24", "", "", ""))
	require.NoError(t, fw.Drop(p, true, &h1, cp, nil))
}

func TestFirewall_Drop3V6(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("fd00::/7"))

	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("fd12::34"),
		RemoteAddr: netip.MustParseAddr("fd12::34"),
		LocalPort:  1,
		RemotePort: 1,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}

	network := netip.MustParsePrefix("fd12::34/120")
	c := cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "host-owner",
			networks: []netip.Prefix{network},
		},
	}
	h := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c,
		},
		vpnAddrs: []netip.Addr{network.Addr()},
	}
	h.buildNetworks(myVpnNetworksTable, c.Certificate)

	// Test a remote address match
	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	cp := cert.NewCAPool()
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", "fd12::34/120", "", "", ""))
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func TestFirewall_DropConntrackReload(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))

	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("1.2.3.4"),
		RemoteAddr: netip.MustParseAddr("1.2.3.4"),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}
	network := netip.MustParsePrefix("1.2.3.4/24")

	c := cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "host1",
			networks: []netip.Prefix{network},
			groups:   []string{"default-group"},
			issuer:   "signer-shasum",
		},
		InvertedGroups: map[string]struct{}{"default-group": {}},
	}
	h := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c,
		},
		vpnAddrs: []netip.Addr{network.Addr()},
	}
	h.buildNetworks(myVpnNetworksTable, c.Certificate)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	cp := cert.NewCAPool()

	// Drop outbound
	assert.Equal(t, fw.Drop(p, false, &h, cp, nil), ErrNoMatchingRule)
	// Allow inbound
	resetConntrack(fw)
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
	// Allow outbound because conntrack
	require.NoError(t, fw.Drop(p, false, &h, cp, nil))

	oldFw := fw
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 10, 10, []string{"any"}, "", "", "", "", ""))
	fw.Conntrack = oldFw.Conntrack
	fw.rulesVersion = oldFw.rulesVersion + 1

	// Allow outbound because conntrack and new rules allow port 10
	require.NoError(t, fw.Drop(p, false, &h, cp, nil))

	oldFw = fw
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 11, 11, []string{"any"}, "", "", "", "", ""))
	fw.Conntrack = oldFw.Conntrack
	fw.rulesVersion = oldFw.rulesVersion + 1

	// Drop outbound because conntrack doesn't match new ruleset
	assert.Equal(t, fw.Drop(p, false, &h, cp, nil), ErrNoMatchingRule)
}

func TestFirewall_DropIPSpoofing(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("192.0.2.1/24"))

	c := cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "host-owner",
			networks: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")},
		},
	}

	c1 := cert.CachedCertificate{
		Certificate: &dummyCert{
			name:           "host",
			networks:       []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		},
	}
	h1 := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c1,
		},
		vpnAddrs: []netip.Addr{c1.Certificate.Networks()[0].Addr()},
	}
	h1.buildNetworks(myVpnNetworksTable, c1.Certificate)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)

	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", "", "", "", ""))
	cp := cert.NewCAPool()

	// Packet spoofed by `c1`. Note that the remote addr is not a valid one.
	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("192.0.2.1"),
		RemoteAddr: netip.MustParseAddr("192.0.2.3"),
		LocalPort:  1,
		RemotePort: 1,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}
	assert.Equal(t, fw.Drop(p, true, &h1, cp, nil), ErrInvalidRemoteIP)
}

func BenchmarkLookup(b *testing.B) {
	ml := func(m map[string]struct{}, a [][]string) {
		for n := 0; n < b.N; n++ {
			for _, sg := range a {
				found := false

				for _, g := range sg {
					if _, ok := m[g]; !ok {
						found = false
						break
					}

					found = true
				}

				if found {
					return
				}
			}
		}
	}

	b.Run("array to map best", func(b *testing.B) {
		m := map[string]struct{}{
			"1ne": {},
			"2wo": {},
			"3hr": {},
			"4ou": {},
			"5iv": {},
			"6ix": {},
		}

		a := [][]string{
			{"1ne", "2wo", "3hr", "4ou", "5iv", "6ix"},
			{"one", "2wo", "3hr", "4ou", "5iv", "6ix"},
			{"one", "two", "3hr", "4ou", "5iv", "6ix"},
			{"one", "two", "thr", "4ou", "5iv", "6ix"},
			{"one", "two", "thr", "fou", "5iv", "6ix"},
			{"one", "two", "thr", "fou", "fiv", "6ix"},
			{"one", "two", "thr", "fou", "fiv", "six"},
		}

		for n := 0; n < b.N; n++ {
			ml(m, a)
		}
	})

	b.Run("array to map worst", func(b *testing.B) {
		m := map[string]struct{}{
			"one": {},
			"two": {},
			"thr": {},
			"fou": {},
			"fiv": {},
			"six": {},
		}

		a := [][]string{
			{"1ne", "2wo", "3hr", "4ou", "5iv", "6ix"},
			{"one", "2wo", "3hr", "4ou", "5iv", "6ix"},
			{"one", "two", "3hr", "4ou", "5iv", "6ix"},
			{"one", "two", "thr", "4ou", "5iv", "6ix"},
			{"one", "two", "thr", "fou", "5iv", "6ix"},
			{"one", "two", "thr", "fou", "fiv", "6ix"},
			{"one", "two", "thr", "fou", "fiv", "six"},
		}

		for n := 0; n < b.N; n++ {
			ml(m, a)
		}
	})
}

func Test_parsePort(t *testing.T) {
	_, _, err := parsePort("")
	require.EqualError(t, err, "was not a number; ``")

	_, _, err = parsePort("  ")
	require.EqualError(t, err, "was not a number; `  `")

	_, _, err = parsePort("-")
	require.EqualError(t, err, "appears to be a range but could not be parsed; `-`")

	_, _, err = parsePort(" - ")
	require.EqualError(t, err, "appears to be a range but could not be parsed; ` - `")

	_, _, err = parsePort("a-b")
	require.EqualError(t, err, "beginning range was not a number; `a`")

	_, _, err = parsePort("1-b")
	require.EqualError(t, err, "ending range was not a number; `b`")

	s, e, err := parsePort(" 1 - 2    ")
	assert.Equal(t, int32(1), s)
	assert.Equal(t, int32(2), e)
	require.NoError(t, err)

	s, e, err = parsePort("0-1")
	assert.Equal(t, int32(0), s)
	assert.Equal(t, int32(0), e)
	require.NoError(t, err)

	s, e, err = parsePort("9919")
	assert.Equal(t, int32(9919), s)
	assert.Equal(t, int32(9919), e)
	require.NoError(t, err)

	s, e, err = parsePort("any")
	assert.Equal(t, int32(0), s)
	assert.Equal(t, int32(0), e)
	require.NoError(t, err)
}

func TestNewFirewallFromConfig(t *testing.T) {
	l := test.NewLogger()
	// Test a bad rule definition
	c := &dummyCert{}
	cs, err := newCertState(cert.Version2, nil, c, false, cert.Curve_CURVE25519, nil)
	require.NoError(t, err)

	conf := config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"outbound": "asdf"}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound failed to parse, should be an array of rules")

	// Test both port and code
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "1", "code": "2"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; only one of port or code should be provided")

	// Test missing host, group, cidr, ca_name and ca_sha
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; at least one of host, group, cidr, local_cidr, ca_name, or ca_sha must be provided")

	// Test code/port error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"code": "a", "host": "testh"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; code was not a number; `a`")

	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "a", "host": "testh"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; port was not a number; `a`")

	// Test proto error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"code": "1", "host": "testh"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; proto was not understood; ``")

	// Test cidr parse error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"code": "1", "cidr": "testh", "proto": "any"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; cidr did not parse; netip.ParsePrefix(\"testh\"): no '/'")

	// Test local_cidr parse error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"code": "1", "local_cidr": "testh", "proto": "any"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; local_cidr did not parse; netip.ParsePrefix(\"testh\"): no '/'")

	// Test both group and groups
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "group": "a", "groups": []string{"b", "c"}}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.inbound rule #0; only one of group or groups should be defined, both provided")
}

func TestAddFirewallRulesFromConfig(t *testing.T) {
	l := test.NewLogger()
	// Test adding tcp rule
	conf := config.NewC(l)
	mf := &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "1", "proto": "tcp", "host": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, false, conf, mf))
	assert.Equal(t, addRuleCall{incoming: false, proto: firewall.ProtoTCP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall)

	// Test adding udp rule
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "1", "proto": "udp", "host": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, false, conf, mf))
	assert.Equal(t, addRuleCall{incoming: false, proto: firewall.ProtoUDP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall)

	// Test adding icmp rule
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "1", "proto": "icmp", "host": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, false, conf, mf))
	assert.Equal(t, addRuleCall{incoming: false, proto: firewall.ProtoICMP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall)

	// Test adding any rule
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "host": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall)

	// Test adding rule with cidr
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "cidr": cidr.String()}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: cidr.String(), localIp: ""}, mf.lastCall)

	// Test adding rule with local_cidr
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "local_cidr": cidr.String()}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: "", localIp: cidr.String()}, mf.lastCall)

	// Test adding rule with cidr ipv6
	cidr6 := netip.MustParsePrefix("fd00::/8")
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "cidr": cidr6.String()}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: cidr6.String(), localIp: ""}, mf.lastCall)

	// Test adding rule with any cidr
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "cidr": "any"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: "any", localIp: ""}, mf.lastCall)

	// Test adding rule with junk cidr
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "cidr": "junk/junk"}}}
	require.EqualError(t, AddFirewallRulesFromConfig(l, true, conf, mf), "firewall.inbound rule #0; cidr did not parse; netip.ParsePrefix(\"junk/junk\"): ParseAddr(\"junk\"): unable to parse IP")

	// Test adding rule with local_cidr ipv6
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "local_cidr": cidr6.String()}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: "", localIp: cidr6.String()}, mf.lastCall)

	// Test adding rule with any local_cidr
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "local_cidr": "any"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, localIp: "any"}, mf.lastCall)

	// Test adding rule with junk local_cidr
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "local_cidr": "junk/junk"}}}
	require.EqualError(t, AddFirewallRulesFromConfig(l, true, conf, mf), "firewall.inbound rule #0; local_cidr did not parse; netip.ParsePrefix(\"junk/junk\"): ParseAddr(\"junk\"): unable to parse IP")

	// Test adding rule with ca_sha
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "ca_sha": "12312313123"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: "", localIp: "", caSha: "12312313123"}, mf.lastCall)

	// Test adding rule with ca_name
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "ca_name": "root01"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: "", localIp: "", caName: "root01"}, mf.lastCall)

	// Test single group
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "group": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: []string{"a"}, ip: "", localIp: ""}, mf.lastCall)

	// Test single groups
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "groups": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: []string{"a"}, ip: "", localIp: ""}, mf.lastCall)

	// Test multiple AND groups
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "groups": []string{"a", "b"}}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: []string{"a", "b"}, ip: "", localIp: ""}, mf.lastCall)

	// Test Add error
	conf = config.NewC(l)
	mf = &mockFirewall{}
	mf.nextCallReturn = errors.New("test error")
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "host": "a"}}}
	require.EqualError(t, AddFirewallRulesFromConfig(l, true, conf, mf), "firewall.inbound rule #0; `test error`")
}

func TestFirewall_convertRule(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	// Ensure group array of 1 is converted and a warning is printed
	c := map[string]any{
		"group": []any{"group1"},
	}

	r, err := convertRule(l, c, "test", 1)
	assert.Contains(t, ob.String(), "test rule #1; group was an array with a single value, converting to simple value")
	require.NoError(t, err)
	assert.Equal(t, []string{"group1"}, r.Groups)

	// Ensure group array of > 1 is errord
	ob.Reset()
	c = map[string]any{
		"group": []any{"group1", "group2"},
	}

	r, err = convertRule(l, c, "test", 1)
	assert.Empty(t, ob.String())
	require.Error(t, err, "group should contain a single value, an array with more than one entry was provided")

	// Make sure a well formed group is alright
	ob.Reset()
	c = map[string]any{
		"group": "group1",
	}

	r, err = convertRule(l, c, "test", 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"group1"}, r.Groups)
}

func TestFirewall_convertRuleSanity(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	noWarningPlease := []map[string]any{
		{"group": "group1"},
		{"groups": []any{"group2"}},
		{"host": "bob"},
		{"cidr": "1.1.1.1/1"},
		{"groups": []any{"group2"}, "host": "bob"},
		{"cidr": "1.1.1.1/1", "host": "bob"},
		{"groups": []any{"group2"}, "cidr": "1.1.1.1/1"},
		{"groups": []any{"group2"}, "cidr": "1.1.1.1/1", "host": "bob"},
	}
	for _, c := range noWarningPlease {
		r, err := convertRule(l, c, "test", 1)
		require.NoError(t, err)
		require.NoError(t, r.sanity(), "should not generate a sanity warning, %+v", c)
	}

	yesWarningPlease := []map[string]any{
		{"group": "group1"},
		{"groups": []any{"group2"}},
		{"cidr": "1.1.1.1/1"},
		{"groups": []any{"group2"}, "host": "bob"},
		{"cidr": "1.1.1.1/1", "host": "bob"},
		{"groups": []any{"group2"}, "cidr": "1.1.1.1/1"},
		{"groups": []any{"group2"}, "cidr": "1.1.1.1/1", "host": "bob"},
	}
	for _, c := range yesWarningPlease {
		c["host"] = "any"
		r, err := convertRule(l, c, "test", 1)
		require.NoError(t, err)
		err = r.sanity()
		require.Error(t, err, "I wanted a warning: %+v", c)
	}
	//reset the list
	yesWarningPlease = []map[string]any{
		{"group": "group1"},
		{"groups": []any{"group2"}},
		{"cidr": "1.1.1.1/1"},
		{"groups": []any{"group2"}, "host": "bob"},
		{"cidr": "1.1.1.1/1", "host": "bob"},
		{"groups": []any{"group2"}, "cidr": "1.1.1.1/1"},
		{"groups": []any{"group2"}, "cidr": "1.1.1.1/1", "host": "bob"},
	}
	for _, c := range yesWarningPlease {
		r, err := convertRule(l, c, "test", 1)
		require.NoError(t, err)
		r.Groups = append(r.Groups, "any")
		err = r.sanity()
		require.Error(t, err, "I wanted a warning: %+v", c)
	}
}

type testcase struct {
	h   *HostInfo
	p   firewall.Packet
	c   cert.Certificate
	err error
}

func (c *testcase) Test(t *testing.T, fw *Firewall) {
	t.Helper()
	cp := cert.NewCAPool()
	resetConntrack(fw)
	err := fw.Drop(c.p, true, c.h, cp, nil)
	if c.err == nil {
		require.NoError(t, err, "failed to not drop remote address %s", c.p.RemoteAddr)
	} else {
		require.ErrorIs(t, c.err, err, "failed to drop remote address %s", c.p.RemoteAddr)
	}
}

func buildTestCase(setup testsetup, err error, theirPrefixes ...netip.Prefix) testcase {
	c1 := dummyCert{
		name:     "host1",
		networks: theirPrefixes,
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}
	h := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    &c1,
				InvertedGroups: map[string]struct{}{"default-group": {}},
			},
		},
		vpnAddrs: make([]netip.Addr, len(theirPrefixes)),
	}
	for i := range theirPrefixes {
		h.vpnAddrs[i] = theirPrefixes[i].Addr()
	}
	h.buildNetworks(setup.myVpnNetworksTable, &c1)
	p := firewall.Packet{
		LocalAddr:  setup.c.Networks()[0].Addr(), //todo?
		RemoteAddr: theirPrefixes[0].Addr(),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}
	return testcase{
		h:   &h,
		p:   p,
		c:   &c1,
		err: err,
	}
}

type testsetup struct {
	c                  dummyCert
	myVpnNetworksTable *bart.Lite
	fw                 *Firewall
}

func newSetup(t *testing.T, l *logrus.Logger, myPrefixes ...netip.Prefix) testsetup {
	c := dummyCert{
		name:     "me",
		networks: myPrefixes,
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}

	return newSetupFromCert(t, l, c)
}

func newSetupFromCert(t *testing.T, l *logrus.Logger, c dummyCert) testsetup {
	myVpnNetworksTable := new(bart.Lite)
	for _, prefix := range c.Networks() {
		myVpnNetworksTable.Insert(prefix)
	}
	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))

	return testsetup{
		c:                  c,
		fw:                 fw,
		myVpnNetworksTable: myVpnNetworksTable,
	}
}

func TestFirewall_Drop_EnforceIPMatch(t *testing.T) {
	t.Parallel()
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	myPrefix := netip.MustParsePrefix("1.1.1.1/8")
	// for now, it's okay that these are all "incoming", the logic this test tries to check doesn't care about in/out
	t.Run("allow inbound all matching", func(t *testing.T) {
		t.Parallel()
		setup := newSetup(t, l, myPrefix)
		tc := buildTestCase(setup, nil, netip.MustParsePrefix("1.2.3.4/24"))
		tc.Test(t, setup.fw)
	})
	t.Run("allow inbound local matching", func(t *testing.T) {
		t.Parallel()
		setup := newSetup(t, l, myPrefix)
		tc := buildTestCase(setup, ErrInvalidLocalIP, netip.MustParsePrefix("1.2.3.4/24"))
		tc.p.LocalAddr = netip.MustParseAddr("1.2.3.8")
		tc.Test(t, setup.fw)
	})
	t.Run("block inbound remote mismatched", func(t *testing.T) {
		t.Parallel()
		setup := newSetup(t, l, myPrefix)
		tc := buildTestCase(setup, ErrInvalidRemoteIP, netip.MustParsePrefix("1.2.3.4/24"))
		tc.p.RemoteAddr = netip.MustParseAddr("9.9.9.9")
		tc.Test(t, setup.fw)
	})
	t.Run("Block a vpn peer packet", func(t *testing.T) {
		t.Parallel()
		setup := newSetup(t, l, myPrefix)
		tc := buildTestCase(setup, ErrPeerRejected, netip.MustParsePrefix("2.2.2.2/24"))
		tc.Test(t, setup.fw)
	})
	twoPrefixes := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.4/24"), netip.MustParsePrefix("2.2.2.2/24"),
	}
	t.Run("allow inbound one matching", func(t *testing.T) {
		t.Parallel()
		setup := newSetup(t, l, myPrefix)
		tc := buildTestCase(setup, nil, twoPrefixes...)
		tc.Test(t, setup.fw)
	})
	t.Run("block inbound multimismatch", func(t *testing.T) {
		t.Parallel()
		setup := newSetup(t, l, myPrefix)
		tc := buildTestCase(setup, ErrInvalidRemoteIP, twoPrefixes...)
		tc.p.RemoteAddr = netip.MustParseAddr("9.9.9.9")
		tc.Test(t, setup.fw)
	})
	t.Run("allow inbound 2nd one matching", func(t *testing.T) {
		t.Parallel()
		setup2 := newSetup(t, l, netip.MustParsePrefix("2.2.2.1/24"))
		tc := buildTestCase(setup2, nil, twoPrefixes...)
		tc.p.RemoteAddr = twoPrefixes[1].Addr()
		tc.Test(t, setup2.fw)
	})
	t.Run("allow inbound unsafe route", func(t *testing.T) {
		t.Parallel()
		unsafePrefix := netip.MustParsePrefix("192.168.0.0/24")
		c := dummyCert{
			name:           "me",
			networks:       []netip.Prefix{myPrefix},
			unsafeNetworks: []netip.Prefix{unsafePrefix},
			groups:         []string{"default-group"},
			issuer:         "signer-shasum",
		}
		unsafeSetup := newSetupFromCert(t, l, c)
		tc := buildTestCase(unsafeSetup, nil, twoPrefixes...)
		tc.p.LocalAddr = netip.MustParseAddr("192.168.0.3")
		tc.err = ErrNoMatchingRule
		tc.Test(t, unsafeSetup.fw) //should hit firewall and bounce off
		require.NoError(t, unsafeSetup.fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", unsafePrefix.String(), "", ""))
		tc.err = nil
		tc.Test(t, unsafeSetup.fw) //should pass
	})
}

type addRuleCall struct {
	incoming  bool
	proto     uint8
	startPort int32
	endPort   int32
	groups    []string
	host      string
	ip        string
	localIp   string
	caName    string
	caSha     string
}

type mockFirewall struct {
	lastCall       addRuleCall
	nextCallReturn error
}

func (mf *mockFirewall) AddRule(incoming bool, proto uint8, startPort int32, endPort int32, groups []string, host string, ip, localIp, caName string, caSha string) error {
	mf.lastCall = addRuleCall{
		incoming:  incoming,
		proto:     proto,
		startPort: startPort,
		endPort:   endPort,
		groups:    groups,
		host:      host,
		ip:        ip,
		localIp:   localIp,
		caName:    caName,
		caSha:     caSha,
	}

	err := mf.nextCallReturn
	mf.nextCallReturn = nil
	return err
}

func resetConntrack(fw *Firewall) {
	fw.Conntrack.Lock()
	fw.Conntrack.Conns = map[firewall.Packet]*conn{}
	fw.Conntrack.Unlock()
}
