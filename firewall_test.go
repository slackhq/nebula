package nebula

import (
	"bytes"
	"errors"
	"math"
	"net/netip"
	"testing"
	"time"

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

	require.NoError(t, fw.AddRule(true, firewall.ProtoTCP, 1, 1, []string{}, "", netip.Prefix{}, netip.Prefix{}, "", ""))
	// An empty rule is any
	assert.True(t, fw.InRules.TCP[1].Any.Any.Any)
	assert.Empty(t, fw.InRules.TCP[1].Any.Groups)
	assert.Empty(t, fw.InRules.TCP[1].Any.Hosts)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoUDP, 1, 1, []string{"g1"}, "", netip.Prefix{}, netip.Prefix{}, "", ""))
	assert.Nil(t, fw.InRules.UDP[1].Any.Any)
	assert.Contains(t, fw.InRules.UDP[1].Any.Groups[0].Groups, "g1")
	assert.Empty(t, fw.InRules.UDP[1].Any.Hosts)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoICMP, 1, 1, []string{}, "h1", netip.Prefix{}, netip.Prefix{}, "", ""))
	assert.Nil(t, fw.InRules.ICMP[1].Any.Any)
	assert.Empty(t, fw.InRules.ICMP[1].Any.Groups)
	assert.Contains(t, fw.InRules.ICMP[1].Any.Hosts, "h1")

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 1, 1, []string{}, "", ti, netip.Prefix{}, "", ""))
	assert.Nil(t, fw.OutRules.AnyProto[1].Any.Any)
	_, ok := fw.OutRules.AnyProto[1].Any.CIDR.Get(ti)
	assert.True(t, ok)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 1, 1, []string{}, "", netip.Prefix{}, ti, "", ""))
	assert.NotNil(t, fw.OutRules.AnyProto[1].Any.Any)
	_, ok = fw.OutRules.AnyProto[1].Any.Any.LocalCIDR.Get(ti)
	assert.True(t, ok)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoUDP, 1, 1, []string{"g1"}, "", netip.Prefix{}, netip.Prefix{}, "ca-name", ""))
	assert.Contains(t, fw.InRules.UDP[1].CANames, "ca-name")

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoUDP, 1, 1, []string{"g1"}, "", netip.Prefix{}, netip.Prefix{}, "", "ca-sha"))
	assert.Contains(t, fw.InRules.UDP[1].CAShas, "ca-sha")

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "any", netip.Prefix{}, netip.Prefix{}, "", ""))
	assert.True(t, fw.OutRules.AnyProto[0].Any.Any.Any)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	anyIp, err := netip.ParsePrefix("0.0.0.0/0")
	require.NoError(t, err)

	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "", anyIp, netip.Prefix{}, "", ""))
	assert.True(t, fw.OutRules.AnyProto[0].Any.Any.Any)

	// Test error conditions
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	require.Error(t, fw.AddRule(true, math.MaxUint8, 0, 0, []string{}, "", netip.Prefix{}, netip.Prefix{}, "", ""))
	require.Error(t, fw.AddRule(true, firewall.ProtoAny, 10, 0, []string{}, "", netip.Prefix{}, netip.Prefix{}, "", ""))
}

func TestFirewall_Drop(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

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
	h.buildNetworks(c.networks, c.unsafeNetworks)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", netip.Prefix{}, netip.Prefix{}, "", ""))
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
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", netip.Prefix{}, netip.Prefix{}, "", "signer-shasum"))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", netip.Prefix{}, netip.Prefix{}, "", "signer-shasum-bad"))
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caSha doesn't drop on match
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", netip.Prefix{}, netip.Prefix{}, "", "signer-shasum-bad"))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", netip.Prefix{}, netip.Prefix{}, "", "signer-shasum"))
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))

	// ensure ca name doesn't get in the way of group checks
	cp.CAs["signer-shasum"] = &cert.CachedCertificate{Certificate: &dummyCert{name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", netip.Prefix{}, netip.Prefix{}, "ca-good", ""))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", netip.Prefix{}, netip.Prefix{}, "ca-good-bad", ""))
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caName doesn't drop on match
	cp.CAs["signer-shasum"] = &cert.CachedCertificate{Certificate: &dummyCert{name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", netip.Prefix{}, netip.Prefix{}, "ca-good-bad", ""))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", netip.Prefix{}, netip.Prefix{}, "ca-good", ""))
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func BenchmarkFirewallTable_match(b *testing.B) {
	f := &Firewall{}
	ft := FirewallTable{
		TCP: firewallPort{},
	}

	pfix := netip.MustParsePrefix("172.1.1.1/32")
	_ = ft.TCP.addRule(f, 10, 10, []string{"good-group"}, "good-host", pfix, netip.Prefix{}, "", "")
	_ = ft.TCP.addRule(f, 100, 100, []string{"good-group"}, "good-host", netip.Prefix{}, pfix, "", "")
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
	h.buildNetworks(c.Certificate.Networks(), c.Certificate.UnsafeNetworks())

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
	h1.buildNetworks(c1.Certificate.Networks(), c1.Certificate.UnsafeNetworks())

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group", "test-group"}, "", netip.Prefix{}, netip.Prefix{}, "", ""))
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
	h1.buildNetworks(c1.Certificate.Networks(), c1.Certificate.UnsafeNetworks())

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
	h2.buildNetworks(c2.Certificate.Networks(), c2.Certificate.UnsafeNetworks())

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
	h3.buildNetworks(c3.Certificate.Networks(), c3.Certificate.UnsafeNetworks())

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "host1", netip.Prefix{}, netip.Prefix{}, "", ""))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", netip.Prefix{}, netip.Prefix{}, "", "signer-sha"))
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
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", netip.MustParsePrefix("1.2.3.4/24"), netip.Prefix{}, "", ""))
	require.NoError(t, fw.Drop(p, true, &h1, cp, nil))
}

func TestFirewall_DropConntrackReload(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

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
	h.buildNetworks(c.Certificate.Networks(), c.Certificate.UnsafeNetworks())

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", netip.Prefix{}, netip.Prefix{}, "", ""))
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
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 10, 10, []string{"any"}, "", netip.Prefix{}, netip.Prefix{}, "", ""))
	fw.Conntrack = oldFw.Conntrack
	fw.rulesVersion = oldFw.rulesVersion + 1

	// Allow outbound because conntrack and new rules allow port 10
	require.NoError(t, fw.Drop(p, false, &h, cp, nil))

	oldFw = fw
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 11, 11, []string{"any"}, "", netip.Prefix{}, netip.Prefix{}, "", ""))
	fw.Conntrack = oldFw.Conntrack
	fw.rulesVersion = oldFw.rulesVersion + 1

	// Drop outbound because conntrack doesn't match new ruleset
	assert.Equal(t, fw.Drop(p, false, &h, cp, nil), ErrNoMatchingRule)
}

func TestHandshakeFilter_AddRuleToHandshakeFilter(t *testing.T) {
	hf := NewHandshakeFilter()
	assert.Empty(t, hf.AllowedHosts)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Empty(t, hf.AllowedCidrs)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)

	assert.True(t, hf.IsEmtpy.Load())
	assert.False(t, hf.IsModifiedSinceLastMashalling.Load())
	hf.AddRule([]string{}, "", netip.Prefix{}, "", "")
	assert.Empty(t, hf.AllowedCidrs)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Empty(t, hf.AllowedHosts)
	assert.True(t, hf.IsEmtpy.Load())
	assert.False(t, hf.IsModifiedSinceLastMashalling.Load())
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)

	hf = NewHandshakeFilter()
	g := "g1"
	hf.AddRule([]string{g}, "", netip.Prefix{}, "", "")
	assert.Empty(t, hf.AllowedCidrs)
	assert.Contains(t, hf.AllowedGroups, g)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Empty(t, hf.AllowedHosts)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)
	assert.False(t, hf.IsEmtpy.Load())
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())

	hf = NewHandshakeFilter()
	h := "h1"
	hf.AddRule([]string{}, h, netip.Prefix{}, "", "")
	assert.Empty(t, hf.AllowedCidrs)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Contains(t, hf.AllowedHosts, h)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)
	assert.False(t, hf.IsEmtpy.Load())
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())

	hf = NewHandshakeFilter()
	ti := netip.MustParsePrefix("1.2.3.4/32")
	hf.AddRule([]string{}, "", ti, "", "")
	assert.Contains(t, hf.AllowedCidrs, ti)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Empty(t, hf.AllowedHosts)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)
	assert.False(t, hf.IsEmtpy.Load())
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())

	hf = NewHandshakeFilter()
	groups := []string{"g1", "g2"}
	hf.AddRule(groups, "", netip.Prefix{}, "", "")
	assert.Empty(t, hf.AllowedCidrs)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)

	gs := make(map[string]struct{})
	for i := range groups {
		gs[groups[i]] = struct{}{}
	}
	assert.Len(t, gs, len(groups))
	assert.Equal(t, hf.AllowedGroupsCombos[0], gs)
	assert.Empty(t, hf.AllowedHosts)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)

	hf = NewHandshakeFilter()
	i := "TestCA"
	hf.AddRule([]string{}, "", netip.Prefix{}, i, "")
	assert.Empty(t, hf.AllowedCidrs)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Empty(t, hf.AllowedHosts)
	assert.Contains(t, hf.AllowedCANames, i)
	assert.Empty(t, hf.AllowedCAShas)

	hf = NewHandshakeFilter()
	s := "3fc204e4d45e8b22ed0879bcd7cb5bf93cdc1c7a309c5dcedddc03aed33a47c6"
	hf.AddRule([]string{}, "", netip.Prefix{}, "", s)
	assert.Empty(t, hf.AllowedCidrs)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Empty(t, hf.AllowedHosts)
	assert.Empty(t, hf.AllowedCANames)
	assert.Contains(t, hf.AllowedCAShas, s)
	assert.False(t, hf.IsEmtpy.Load())
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())
}

func TestHandshakeFilter_IsHandshakeAllowed(t *testing.T) {
	hf := NewHandshakeFilter()
	assert.NotNil(t, hf.AllowedHosts)
	assert.NotNil(t, hf.AllowedGroups)
	assert.NotNil(t, hf.AllowedGroupsCombos)
	assert.NotNil(t, hf.AllowedCidrs)

	ti := netip.MustParsePrefix("1.2.3.0/24")
	ais := []netip.Addr{
		netip.MustParseAddr("1.2.3.5"),
		netip.MustParseAddr("1.1.1.2"),
	}

	aos := []netip.Addr{
		netip.MustParseAddr("1.2.0.1"),
		netip.MustParseAddr("1.10.0.1"),
	}

	hf.AddRule([]string{"g1"}, "", netip.Prefix{}, "", "")
	hf.AddRule([]string{}, "h1", netip.Prefix{}, "", "")
	hf.AddRule([]string{}, "", ti, "", "")
	hf.AddRule([]string{"g1", "g2"}, "", netip.Prefix{}, "", "")
	hf.AddRule([]string{"g1", "g2"}, "", netip.Prefix{}, "", "")
	hf.AddRule([]string{}, "", netip.Prefix{}, "TestCA", "")
	hf.AddRule([]string{}, "", netip.Prefix{}, "", "3fc204e4d45e8b22ed0879bcd7cb5bf93cdc1c7a309c5dcedddc03aed33a47c6")

	g := []string{"g2", "g3"}
	g2 := []string{"g1", "g2"}
	assert.True(t, hf.IsHandshakeAllowed([]string{"g1"}, "", []netip.Addr{netip.Addr{}}, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{"g2"}, "", []netip.Addr{netip.Addr{}}, "", ""))
	assert.False(t, hf.IsHandshakeAllowed(g, "", []netip.Addr{netip.Addr{}}, "", ""))
	assert.True(t, hf.IsHandshakeAllowed(g2, "", []netip.Addr{netip.Addr{}}, "", ""))
	assert.Len(t, hf.AllowedGroupsCombos[0], 2)

	assert.True(t, hf.IsHandshakeAllowed([]string{"g2", "g1"}, "", []netip.Addr{netip.Addr{}}, "", ""))
	assert.True(t, hf.IsHandshakeAllowed([]string{"g3", "g2", "g1"}, "", []netip.Addr{netip.Addr{}}, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{}, "h2", aos, "", ""))

	assert.True(t, hf.IsHandshakeAllowed([]string{}, "h1", []netip.Addr{netip.Addr{}}, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{}, "h2", []netip.Addr{netip.Addr{}}, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{}, "", []netip.Addr{netip.Addr{}}, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{}, "any", []netip.Addr{netip.Addr{}}, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{"h1"}, "", aos, "", ""))

	assert.True(t, hf.IsHandshakeAllowed([]string{}, "", ais, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{}, "", aos, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{"g3"}, "h2", aos, "", ""))

	assert.True(t, hf.IsHandshakeAllowed([]string{}, "", []netip.Addr{netip.Addr{}}, "TestCA", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{}, "", []netip.Addr{netip.Addr{}}, "WrongCA", ""))

	assert.True(t, hf.IsHandshakeAllowed([]string{}, "", []netip.Addr{netip.Addr{}}, "", "3fc204e4d45e8b22ed0879bcd7cb5bf93cdc1c7a309c5dcedddc03aed33a47c6"))
	assert.False(t, hf.IsHandshakeAllowed([]string{}, "", []netip.Addr{netip.Addr{}}, "", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))

	pAny := netip.MustParsePrefix("0.0.0.0/0")

	hf = NewHandshakeFilter()
	hf.AddRule([]string{"any"}, "", netip.Prefix{}, "", "")
	hf.AddRule([]string{}, "any", netip.Prefix{}, "", "")
	hf.AddRule([]string{}, "", pAny, "", "")

	assert.True(t, hf.IsHandshakeAllowed([]string{}, "", ais, "", ""))
	assert.True(t, hf.IsHandshakeAllowed([]string{}, "h3", []netip.Addr{netip.Addr{}}, "", ""))
	assert.True(t, hf.IsHandshakeAllowed([]string{"g4"}, "", []netip.Addr{netip.Addr{}}, "", ""))
	assert.True(t, hf.IsHandshakeAllowed([]string{"g4", "g5"}, "", []netip.Addr{netip.Addr{}}, "", ""))

	hf = NewHandshakeFilter()
	hf.AddRule([]string{}, "any", netip.Prefix{}, "", "")
	assert.True(t, hf.IsHandshakeAllowed([]string{}, "", ais, "", ""))
	assert.True(t, hf.IsHandshakeAllowed([]string{}, "h3", []netip.Addr{netip.Addr{}}, "", ""))
	assert.True(t, hf.IsHandshakeAllowed([]string{"g4"}, "", []netip.Addr{netip.Addr{}}, "", ""))
	assert.True(t, hf.IsHandshakeAllowed([]string{"g4", "g5"}, "", []netip.Addr{netip.Addr{}}, "", ""))

	hf = NewHandshakeFilter()
	hf.AddRule([]string{}, "", pAny, "", "")
	assert.True(t, hf.IsHandshakeAllowed([]string{}, "", ais, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{}, "h3", []netip.Addr{netip.Addr{}}, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{"g4"}, "", []netip.Addr{netip.Addr{}}, "", ""))
	assert.False(t, hf.IsHandshakeAllowed([]string{"g4", "g5"}, "", []netip.Addr{netip.Addr{}}, "", ""))
}

func TestHandshakeFilter_Marshalling(t *testing.T) {
	hf := NewHandshakeFilter()
	assert.NotNil(t, hf.AllowedHosts)
	assert.NotNil(t, hf.AllowedGroups)
	assert.NotNil(t, hf.AllowedGroupsCombos)
	assert.NotNil(t, hf.AllowedCidrs)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)
	assert.False(t, hf.IsModifiedSinceLastMashalling.Load())
	assert.True(t, hf.IsEmtpy.Load())
	hfw := hf.MarshalToHfw()
	assert.False(t, hf.IsModifiedSinceLastMashalling.Load())
	assert.Empty(t, hfw.AllowedGroups)
	assert.Empty(t, hfw.AllowedGroupsCombos)
	assert.Empty(t, hfw.AllowedHosts)
	assert.Empty(t, hfw.AllowedCidrs)
	assert.Empty(t, hfw.AllowedCANames)
	assert.Empty(t, hfw.AllowedCAShas)
	assert.True(t, hfw.SetEmpty)

	hf = NewHandshakeFilter()
	g := "g1"
	hf.AddRule([]string{g}, "", netip.Prefix{}, "", "")
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())
	hfw = hf.MarshalToHfw()
	assert.Contains(t, hfw.AllowedGroups, g)
	assert.Empty(t, hfw.AllowedGroupsCombos)
	assert.Empty(t, hfw.AllowedHosts)
	assert.Empty(t, hfw.AllowedCidrs)
	assert.Empty(t, hfw.AllowedCANames)
	assert.Empty(t, hfw.AllowedCAShas)
	assert.False(t, hfw.SetEmpty)
	assert.False(t, hf.IsModifiedSinceLastMashalling.Load())
	hf = NewHandshakeFilter()
	hf.UnmarshalFromHfw(hfw)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Empty(t, hf.AllowedHosts)
	assert.Empty(t, hf.AllowedCidrs)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)
	assert.Contains(t, hf.AllowedGroups, g)
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())

	hf = NewHandshakeFilter()
	gc := []string{"g1", "g2"}
	hf.AddRule(gc, "", netip.Prefix{}, "", "")
	assert.Len(t, hf.AllowedGroupsCombos, 1)
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())
	hfw = hf.MarshalToHfw()
	assert.Empty(t, hfw.AllowedGroups)
	assert.Len(t, hfw.AllowedGroupsCombos, 1)
	for _, g := range gc {
		assert.Contains(t, hfw.AllowedGroupsCombos[0].Group, g)
	}
	assert.Empty(t, hfw.AllowedHosts)
	assert.Empty(t, hfw.AllowedCidrs)
	assert.Empty(t, hfw.AllowedCANames)
	assert.Empty(t, hfw.AllowedCAShas)
	assert.False(t, hfw.SetEmpty)
	assert.False(t, hf.IsModifiedSinceLastMashalling.Load())
	hf = NewHandshakeFilter()
	hf.UnmarshalFromHfw(hfw)
	assert.Empty(t, hf.AllowedGroups)
	gs := make(map[string]struct{})
	for _, g := range hfw.AllowedGroupsCombos[0].Group {
		gs[g] = struct{}{}
	}
	for _, g := range gc {
		assert.Contains(t, hf.AllowedGroupsCombos[0], g)
	}
	assert.Empty(t, hf.AllowedHosts)
	assert.Empty(t, hf.AllowedCidrs)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())

	hf = NewHandshakeFilter()
	h := "h1"
	hf.AddRule(nil, h, netip.Prefix{}, "", "")
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())
	hfw = hf.MarshalToHfw()
	assert.Empty(t, hfw.AllowedGroups)
	assert.Empty(t, hfw.AllowedGroupsCombos)
	assert.Contains(t, hfw.AllowedHosts, h)
	assert.Empty(t, hfw.AllowedCidrs)
	assert.Empty(t, hfw.AllowedCANames)
	assert.Empty(t, hfw.AllowedCAShas)
	assert.False(t, hfw.SetEmpty)
	assert.False(t, hf.IsModifiedSinceLastMashalling.Load())
	hf = NewHandshakeFilter()
	hf.UnmarshalFromHfw(hfw)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Contains(t, hf.AllowedHosts, h)
	assert.Empty(t, hf.AllowedCidrs)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())

	hf = NewHandshakeFilter()
	p, _ := netip.ParsePrefix("10.1.1.1/32")
	hf.AddRule(nil, "", p, "", "")
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())
	hfw = hf.MarshalToHfw()
	assert.Empty(t, hfw.AllowedGroups)
	assert.Empty(t, hfw.AllowedGroupsCombos)
	assert.Empty(t, hfw.AllowedHosts)
	assert.Equal(t, hfw.AllowedCidrs[0], p.String())
	assert.Empty(t, hfw.AllowedCANames)
	assert.Empty(t, hfw.AllowedCAShas)
	assert.False(t, hfw.SetEmpty)
	assert.False(t, hf.IsModifiedSinceLastMashalling.Load())
	hf = NewHandshakeFilter()
	hf.UnmarshalFromHfw(hfw)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Empty(t, hf.AllowedHosts)
	assert.Contains(t, hf.AllowedCidrs, p)
	assert.Empty(t, hf.AllowedCANames)
	assert.Empty(t, hf.AllowedCAShas)
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())

	hf = NewHandshakeFilter()
	ca := "TestCA"
	hf.AddRule(nil, "", netip.Prefix{}, ca, "")
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())
	hfw = hf.MarshalToHfw()
	assert.Empty(t, hfw.AllowedGroups)
	assert.Empty(t, hfw.AllowedGroupsCombos)
	assert.Empty(t, hfw.AllowedHosts)
	assert.Empty(t, hfw.AllowedCidrs)
	assert.Contains(t, hfw.AllowedCANames, ca)
	assert.Empty(t, hfw.AllowedCAShas)
	assert.False(t, hfw.SetEmpty)
	assert.False(t, hf.IsModifiedSinceLastMashalling.Load())
	hf = NewHandshakeFilter()
	hf.UnmarshalFromHfw(hfw)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Empty(t, hf.AllowedHosts)
	assert.Empty(t, hf.AllowedCidrs)
	assert.Contains(t, hf.AllowedCANames, ca)
	assert.Empty(t, hf.AllowedCAShas)
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())

	hf = NewHandshakeFilter()
	fp := "3fc204e4d45e8b22ed0879bcd7cb5bf93cdc1c7a309c5dcedddc03aed33a47c6"
	hf.AddRule(nil, "", netip.Prefix{}, "", fp)
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())
	hfw = hf.MarshalToHfw()
	assert.Empty(t, hfw.AllowedGroups)
	assert.Empty(t, hfw.AllowedGroupsCombos)
	assert.Empty(t, hfw.AllowedHosts)
	assert.Empty(t, hfw.AllowedCidrs)
	assert.Empty(t, hfw.AllowedCANames)
	assert.Contains(t, hfw.AllowedCAShas, fp)
	assert.False(t, hfw.SetEmpty)
	assert.False(t, hf.IsModifiedSinceLastMashalling.Load())
	hf = NewHandshakeFilter()
	hf.UnmarshalFromHfw(hfw)
	assert.Empty(t, hf.AllowedGroups)
	assert.Empty(t, hf.AllowedGroupsCombos)
	assert.Empty(t, hf.AllowedHosts, h)
	assert.Empty(t, hf.AllowedCidrs)
	assert.Empty(t, hfw.AllowedCANames)
	assert.Contains(t, hf.AllowedCAShas, fp)
	assert.True(t, hf.IsModifiedSinceLastMashalling.Load())
}

func Test_isSubset(t *testing.T) {
	subset := make(map[string]struct{}, 2)
	subset["g1"] = struct{}{}
	subset["g2"] = struct{}{}
	assert.Len(t, subset, 2)

	superset := []string{"g0", "g1", "g", "g2", "g3", "g1", "g2", "g4"}
	assert.True(t, isSubset(subset, superset))
	superset = []string{"g0", "g1", "g3"}
	assert.False(t, isSubset(subset, superset))
	superset = []string{"g0", "g1", "g1", "g3"}
	assert.False(t, isSubset(subset, superset))
}

func Test_containsMap(t *testing.T) {
	slice := make([]map[string]struct{}, 2)

	m1 := make(map[string]struct{}, 2)
	m1["g1"] = struct{}{}
	m1["g2"] = struct{}{}
	assert.Len(t, m1, 2)

	m2 := make(map[string]struct{}, 2)
	m2["g2"] = struct{}{}
	m2["g3"] = struct{}{}
	assert.Len(t, m1, 2)

	slice[0] = m1
	slice[1] = m2
	assert.Len(t, slice, 2)

	assert.True(t, containsMap(slice, m1))
	assert.True(t, containsMap(slice, m2))

	c1 := make(map[string]struct{}, 2)
	c1["g1"] = struct{}{}
	c1["g3"] = struct{}{}
	assert.Len(t, c1, 2)
	assert.False(t, containsMap(slice, c1))
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
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": "asdf"}
	_, _, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound failed to parse, should be an array of rules")

	// Test both port and code
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"port": "1", "code": "2"}}}
	_, _, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; only one of port or code should be provided")

	// Test missing host, group, cidr, ca_name and ca_sha
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{}}}
	_, _, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; at least one of host, group, cidr, local_cidr, ca_name, or ca_sha must be provided")

	// Test code/port error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"code": "a", "host": "testh"}}}
	_, _, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; code was not a number; `a`")

	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"port": "a", "host": "testh"}}}
	_, _, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; port was not a number; `a`")

	// Test proto error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"code": "1", "host": "testh"}}}
	_, _, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; proto was not understood; ``")

	// Test cidr parse error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"code": "1", "cidr": "testh", "proto": "any"}}}
	_, _, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; cidr did not parse; netip.ParsePrefix(\"testh\"): no '/'")

	// Test local_cidr parse error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"code": "1", "local_cidr": "testh", "proto": "any"}}}
	_, _, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; local_cidr did not parse; netip.ParsePrefix(\"testh\"): no '/'")

	// Test both group and groups
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "group": "a", "groups": []string{"b", "c"}}}}
	_, _, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.inbound rule #0; only one of group or groups should be defined, both provided")
}

func TestAddFirewallRulesFromConfig(t *testing.T) {
	l := test.NewLogger()
	// Test adding tcp rule
	conf := config.NewC(l)
	mf := &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "tcp", "host": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, false, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: false, proto: firewall.ProtoTCP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: netip.Prefix{}, localIp: netip.Prefix{}}, mf.lastCall)

	// Test adding udp rule
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "udp", "host": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, false, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: false, proto: firewall.ProtoUDP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: netip.Prefix{}, localIp: netip.Prefix{}}, mf.lastCall)

	// Test adding icmp rule
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "icmp", "host": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, false, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: false, proto: firewall.ProtoICMP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: netip.Prefix{}, localIp: netip.Prefix{}}, mf.lastCall)

	// Test adding any rule
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "host": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, host: "a", ip: netip.Prefix{}, localIp: netip.Prefix{}}, mf.lastCall)

	// Test adding rule with cidr
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "cidr": cidr.String()}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: cidr, localIp: netip.Prefix{}}, mf.lastCall)

	// Test adding rule with local_cidr
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "local_cidr": cidr.String()}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: netip.Prefix{}, localIp: cidr}, mf.lastCall)

	// Test adding rule with ca_sha
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "ca_sha": "12312313123"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: netip.Prefix{}, localIp: netip.Prefix{}, caSha: "12312313123"}, mf.lastCall)

	// Test adding rule with ca_name
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "ca_name": "root01"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: netip.Prefix{}, localIp: netip.Prefix{}, caName: "root01"}, mf.lastCall)

	// Test single group
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "group": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: []string{"a"}, ip: netip.Prefix{}, localIp: netip.Prefix{}}, mf.lastCall)

	// Test single groups
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "groups": "a"}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: []string{"a"}, ip: netip.Prefix{}, localIp: netip.Prefix{}}, mf.lastCall)

	// Test multiple AND groups
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "groups": []string{"a", "b"}}}}
	require.NoError(t, AddFirewallRulesFromConfig(l, true, conf, mf, nil))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: []string{"a", "b"}, ip: netip.Prefix{}, localIp: netip.Prefix{}}, mf.lastCall)

	// Test Add error
	conf = config.NewC(l)
	mf = &mockFirewall{}
	mf.nextCallReturn = errors.New("test error")
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "host": "a"}}}
	require.EqualError(t, AddFirewallRulesFromConfig(l, true, conf, mf, nil), "firewall.inbound rule #0; `test error`")
}

func TestFirewall_convertRule(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	// Ensure group array of 1 is converted and a warning is printed
	c := map[interface{}]interface{}{
		"group": []interface{}{"group1"},
	}

	r, err := convertRule(l, c, "test", 1)
	assert.Contains(t, ob.String(), "test rule #1; group was an array with a single value, converting to simple value")
	require.NoError(t, err)
	assert.Equal(t, "group1", r.Group)

	// Ensure group array of > 1 is errord
	ob.Reset()
	c = map[interface{}]interface{}{
		"group": []interface{}{"group1", "group2"},
	}

	r, err = convertRule(l, c, "test", 1)
	assert.Equal(t, "", ob.String())
	require.Error(t, err, "group should contain a single value, an array with more than one entry was provided")

	// Make sure a well formed group is alright
	ob.Reset()
	c = map[interface{}]interface{}{
		"group": "group1",
	}

	r, err = convertRule(l, c, "test", 1)
	require.NoError(t, err)
	assert.Equal(t, "group1", r.Group)
}

type addRuleCall struct {
	incoming  bool
	proto     uint8
	startPort int32
	endPort   int32
	groups    []string
	host      string
	ip        netip.Prefix
	localIp   netip.Prefix
	caName    string
	caSha     string
}

type mockFirewall struct {
	lastCall       addRuleCall
	nextCallReturn error
}

func (mf *mockFirewall) AddRule(incoming bool, proto uint8, startPort int32, endPort int32, groups []string, host string, ip netip.Prefix, localIp netip.Prefix, caName string, caSha string) error {
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
