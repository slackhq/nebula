package nebula

import (
	"bytes"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/iputil"
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
	assert.NotNil(t, fw.rules.In)
	assert.NotNil(t, fw.rules.Out)
	// Nothing is allowed until there are rules
	assert.False(t, fw.rules.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP}, true, nil, nil))
	assert.False(t, fw.rules.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP}, false, nil, nil))
	assert.Equal(t, time.Second, fw.TCPTimeout)
	assert.Equal(t, time.Minute, fw.UDPTimeout)
	assert.Equal(t, time.Hour, fw.DefaultTimeout)

	assert.Equal(t, time.Second, fw.conntrackTimeout(iputil.IPProtocolTCP))
	assert.Equal(t, time.Second, fw.conntrackTimeout(iputil.IPProtocolSCTP))
	assert.Equal(t, time.Second, fw.conntrackTimeout(iputil.IPProtocolDCCP))
	assert.Equal(t, time.Minute, fw.conntrackTimeout(iputil.IPProtocolUDP))
	assert.Equal(t, time.Minute, fw.conntrackTimeout(iputil.IPProtocolUDPLite))
	assert.Equal(t, time.Hour, fw.conntrackTimeout(iputil.IPProtocolICMP))
	assert.Equal(t, time.Hour, fw.conntrackTimeout(47)) // GRE

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

func TestFirewall_Drop(t *testing.T) {
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))
	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("1.2.3.4"),
		RemoteAddr: netip.MustParseAddr("1.2.3.4"),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   iputil.IPProtocolUDP,
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
	rb := firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	fw.setRules(rb)
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
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "", "signer-shasum"))
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "", "signer-shasum-bad"))
	fw.setRules(rb)
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caSha doesn't drop on match
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "", "signer-shasum-bad"))
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "", "signer-shasum"))
	fw.setRules(rb)
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))

	// ensure ca name doesn't get in the way of group checks
	cp.CAs["signer-shasum"] = &cert.CachedCertificate{Certificate: &dummyCert{name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "ca-good", ""))
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "ca-good-bad", ""))
	fw.setRules(rb)
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caName doesn't drop on match
	cp.CAs["signer-shasum"] = &cert.CachedCertificate{Certificate: &dummyCert{name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "ca-good-bad", ""))
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "ca-good", ""))
	fw.setRules(rb)
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func TestFirewall_DropV6(t *testing.T) {
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)

	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("fd00::/7"))

	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("fd12::34"),
		RemoteAddr: netip.MustParseAddr("fd12::34"),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   iputil.IPProtocolUDP,
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
	rb := firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	fw.setRules(rb)
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
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "", "signer-shasum"))
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "", "signer-shasum-bad"))
	fw.setRules(rb)
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caSha doesn't drop on match
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "", "signer-shasum-bad"))
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "", "signer-shasum"))
	fw.setRules(rb)
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))

	// ensure ca name doesn't get in the way of group checks
	cp.CAs["signer-shasum"] = &cert.CachedCertificate{Certificate: &dummyCert{name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "ca-good", ""))
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "ca-good-bad", ""))
	fw.setRules(rb)
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caName doesn't drop on match
	cp.CAs["signer-shasum"] = &cert.CachedCertificate{Certificate: &dummyCert{name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "ca-good-bad", ""))
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", "", "", "ca-good", ""))
	fw.setRules(rb)
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func BenchmarkFirewallTable_match(b *testing.B) {
	rb := firewall.NewRulesBuilder(test.NewLogger())

	pfix := netip.MustParsePrefix("172.1.1.1/32")
	require.NoError(b, rb.AddRule(true, iputil.IPProtocolTCP, 10, 10, []string{"good-group"}, "good-host", pfix.String(), "", "", ""))
	require.NoError(b, rb.AddRule(true, iputil.IPProtocolTCP, 100, 100, []string{"good-group"}, "good-host", "", pfix.String(), "", ""))

	pfix6 := netip.MustParsePrefix("fd11::11/128")
	require.NoError(b, rb.AddRule(true, iputil.IPProtocolTCP, 10, 10, []string{"good-group"}, "good-host", pfix6.String(), "", "", ""))
	require.NoError(b, rb.AddRule(true, iputil.IPProtocolTCP, 100, 100, []string{"good-group"}, "good-host", "", pfix6.String(), "", ""))
	ft := rb.Build(nil, nil).In
	cp := cert.NewCAPool()

	b.Run("fail on proto", func(b *testing.B) {
		// This benchmark is showing us the cost of failing to match the protocol
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{},
		}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolUDP}, true, c, cp))
		}
	})

	b.Run("pass proto, fail on port", func(b *testing.B) {
		// This benchmark is showing us the cost of matching a specific protocol but failing to match the port
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{},
		}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 1}, true, c, cp))
		}
	})

	b.Run("pass proto, port, fail on local CIDR", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{},
		}
		ip := netip.MustParsePrefix("9.254.254.254/32")
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 100, LocalAddr: ip.Addr()}, true, c, cp))
		}
	})
	b.Run("pass proto, port, fail on local CIDRv6", func(b *testing.B) {
		c := &cert.CachedCertificate{
			Certificate: &dummyCert{},
		}
		ip := netip.MustParsePrefix("fd99::99/128")
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 100, LocalAddr: ip.Addr()}, true, c, cp))
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
			assert.False(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 10}, true, c, cp))
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
			assert.False(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 10}, true, c, cp))
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
			assert.False(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 100, LocalAddr: pfix.Addr()}, true, c, cp))
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
			assert.False(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 100, LocalAddr: pfix6.Addr()}, true, c, cp))
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
			assert.True(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 10}, true, c, cp))
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
			assert.True(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 100, LocalAddr: pfix.Addr()}, true, c, cp))
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
			assert.True(b, ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 100, LocalAddr: pfix6.Addr()}, true, c, cp))
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
			ft.Match(&firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 10}, true, c, cp)
		}
	})

	// The port 10 rules have a cidr, this cert fails their group and host so only the cidr can pass them
	cidrCert := &cert.CachedCertificate{
		Certificate:    &dummyCert{name: "nope"},
		InvertedGroups: map[string]struct{}{"nope": {}},
	}
	for _, tc := range []struct {
		name string
		addr netip.Addr
		want bool
	}{
		{"pass on cidr", pfix.Addr(), true},
		{"pass on cidr6", pfix6.Addr(), true},
		{"pass proto, port, fail group and name, fail on cidr", netip.MustParseAddr("9.254.254.245"), false},
		{"pass proto, port, fail group and name, fail on cidr6", netip.MustParseAddr("fd99::99"), false},
	} {
		p := &firewall.Packet{Protocol: iputil.IPProtocolTCP, LocalPort: 10, RemoteAddr: tc.addr}
		b.Run(tc.name, func(b *testing.B) {
			if ft.Match(p, true, cidrCert, cp) != tc.want {
				b.Fatal("wrong verdict")
			}
			for b.Loop() {
				benchMatchSink = ft.Match(p, true, cidrCert, cp)
			}
		})
	}
}

var benchMatchSink bool

func TestFirewall_Drop2(t *testing.T) {
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))

	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("1.2.3.4"),
		RemoteAddr: netip.MustParseAddr("1.2.3.4"),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   iputil.IPProtocolUDP,
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
	rb := firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group", "test-group"}, "", "", "", "", ""))
	fw.setRules(rb)
	cp := cert.NewCAPool()

	// h1/c1 lacks the proper groups
	require.ErrorIs(t, fw.Drop(p, true, &h1, cp, nil), ErrNoMatchingRule)
	// c has the proper groups
	resetConntrack(fw)
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func TestFirewall_Drop3(t *testing.T) {
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))

	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("1.2.3.4"),
		RemoteAddr: netip.MustParseAddr("1.2.3.4"),
		LocalPort:  1,
		RemotePort: 1,
		Protocol:   iputil.IPProtocolUDP,
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
	rb := firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "host1", "", "", "", ""))
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", "", "", "", "signer-sha"))
	fw.setRules(rb)
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
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", "1.2.3.4/24", "", "", ""))
	fw.setRules(rb)
	require.NoError(t, fw.Drop(p, true, &h1, cp, nil))
}

func TestFirewall_Drop3V6(t *testing.T) {
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("fd00::/7"))

	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("fd12::34"),
		RemoteAddr: netip.MustParseAddr("fd12::34"),
		LocalPort:  1,
		RemotePort: 1,
		Protocol:   iputil.IPProtocolUDP,
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
	rb := firewall.NewRulesBuilder(l)
	cp := cert.NewCAPool()
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", "fd12::34/120", "", "", ""))
	fw.setRules(rb)
	require.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func TestFirewall_DropConntrackReload(t *testing.T) {
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))

	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("1.2.3.4"),
		RemoteAddr: netip.MustParseAddr("1.2.3.4"),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   iputil.IPProtocolUDP,
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
	rb := firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	fw.setRules(rb)
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
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 10, 10, []string{"any"}, "", "", "", "", ""))
	fw.setRules(rb)
	fw.Conntrack = oldFw.Conntrack
	fw.rulesVersion = oldFw.rulesVersion + 1

	// Allow outbound because conntrack and new rules allow port 10
	require.NoError(t, fw.Drop(p, false, &h, cp, nil))

	oldFw = fw
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 11, 11, []string{"any"}, "", "", "", "", ""))
	fw.setRules(rb)
	fw.Conntrack = oldFw.Conntrack
	fw.rulesVersion = oldFw.rulesVersion + 1

	// Drop outbound because conntrack doesn't match new ruleset
	assert.Equal(t, fw.Drop(p, false, &h, cp, nil), ErrNoMatchingRule)
}

func TestFirewall_ICMPPortBehavior(t *testing.T) {
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))

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

	cp := cert.NewCAPool()

	templ := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("1.2.3.4"),
		RemoteAddr: netip.MustParseAddr("1.2.3.4"),
		Protocol:   iputil.IPProtocolICMP,
		Fragment:   false,
	}

	t.Run("ICMP allowed", func(t *testing.T) {
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
		rb := firewall.NewRulesBuilder(l)
		require.NoError(t, rb.AddRule(true, iputil.IPProtocolICMP, 0, 0, []string{"any"}, "", "", "", "", ""))
		fw.setRules(rb)
		t.Run("zero ports", func(t *testing.T) {
			p := templ.Copy()
			p.LocalPort = 0
			p.RemotePort = 0
			// Drop outbound
			assert.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
			// Allow inbound
			resetConntrack(fw)
			require.NoError(t, fw.Drop(*p, true, &h, cp, nil))
			//now also allow outbound
			require.NoError(t, fw.Drop(*p, false, &h, cp, nil))
		})

		t.Run("nonzero ports", func(t *testing.T) {
			p := templ.Copy()
			p.LocalPort = 0xabcd
			p.RemotePort = 0x1234
			// Drop outbound
			assert.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
			// Allow inbound
			resetConntrack(fw)
			require.NoError(t, fw.Drop(*p, true, &h, cp, nil))
			//now also allow outbound
			require.NoError(t, fw.Drop(*p, false, &h, cp, nil))
		})
	})

	t.Run("Any proto, some ports allowed", func(t *testing.T) {
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
		rb := firewall.NewRulesBuilder(l)
		require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 80, 444, []string{"any"}, "", "", "", "", ""))
		fw.setRules(rb)
		t.Run("zero ports, still blocked", func(t *testing.T) {
			p := templ.Copy()
			p.LocalPort = 0
			p.RemotePort = 0
			// Drop outbound
			assert.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
			// Allow inbound
			resetConntrack(fw)
			assert.Equal(t, fw.Drop(*p, true, &h, cp, nil), ErrNoMatchingRule)
			//now also allow outbound
			assert.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
		})

		t.Run("nonzero ports, still blocked", func(t *testing.T) {
			p := templ.Copy()
			p.LocalPort = 0xabcd
			p.RemotePort = 0x1234
			// Drop outbound
			assert.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
			// Allow inbound
			resetConntrack(fw)
			assert.Equal(t, fw.Drop(*p, true, &h, cp, nil), ErrNoMatchingRule)
			//now also allow outbound
			assert.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
		})

		t.Run("nonzero, matching ports, still blocked", func(t *testing.T) {
			p := templ.Copy()
			p.LocalPort = 80
			p.RemotePort = 80
			// Drop outbound
			assert.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
			// Allow inbound
			resetConntrack(fw)
			assert.Equal(t, fw.Drop(*p, true, &h, cp, nil), ErrNoMatchingRule)
			//now also allow outbound
			assert.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
		})
	})
	t.Run("Any proto, any port", func(t *testing.T) {
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
		rb := firewall.NewRulesBuilder(l)
		require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
		fw.setRules(rb)
		t.Run("zero ports, allowed", func(t *testing.T) {
			resetConntrack(fw)
			p := templ.Copy()
			p.LocalPort = 0
			p.RemotePort = 0
			// Drop outbound
			assert.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
			// Allow inbound
			resetConntrack(fw)
			require.NoError(t, fw.Drop(*p, true, &h, cp, nil))
			//now also allow outbound
			require.NoError(t, fw.Drop(*p, false, &h, cp, nil))
		})

		t.Run("nonzero ports, allowed", func(t *testing.T) {
			resetConntrack(fw)
			p := templ.Copy()
			p.LocalPort = 0xabcd
			p.RemotePort = 0x1234
			// Drop outbound
			assert.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
			// Allow inbound
			resetConntrack(fw)
			require.NoError(t, fw.Drop(*p, true, &h, cp, nil))
			//now also allow outbound
			require.NoError(t, fw.Drop(*p, false, &h, cp, nil))
			//different ID is blocked
			p.RemotePort++
			require.Equal(t, fw.Drop(*p, false, &h, cp, nil), ErrNoMatchingRule)
		})
	})

}

func TestFirewall_ProtocolRules(t *testing.T) {
	l := test.NewLogger()
	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("1.1.1.1/8"))

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

	cp := cert.NewCAPool()

	protos := []uint8{iputil.IPProtocolTCP, iputil.IPProtocolUDP, iputil.IPProtocolUDPLite, iputil.IPProtocolDCCP, iputil.IPProtocolSCTP}
	for _, ruleProto := range protos {
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
		rb := firewall.NewRulesBuilder(l)
		require.NoError(t, rb.AddRule(true, ruleProto, 80, 80, []string{"any"}, "", "", "", "", ""))
		fw.setRules(rb)

		for _, pktProto := range protos {
			p := firewall.Packet{
				LocalAddr:  netip.MustParseAddr("1.2.3.4"),
				RemoteAddr: netip.MustParseAddr("1.2.3.4"),
				LocalPort:  80,
				RemotePort: 5000,
				Protocol:   pktProto,
			}
			if pktProto == ruleProto {
				require.NoError(t, fw.Drop(p, true, &h, cp, nil), "rule %d, packet %d", ruleProto, pktProto)
				p.LocalPort = 81
				assert.Equal(t, ErrNoMatchingRule, fw.Drop(p, true, &h, cp, nil), "rule %d, packet %d, wrong port", ruleProto, pktProto)
			} else {
				assert.Equal(t, ErrNoMatchingRule, fw.Drop(p, true, &h, cp, nil), "rule %d, packet %d", ruleProto, pktProto)
			}
		}
	}

	pkt := func(proto uint8) firewall.Packet {
		return firewall.Packet{
			LocalAddr:  netip.MustParseAddr("1.2.3.4"),
			RemoteAddr: netip.MustParseAddr("1.2.3.4"),
			Protocol:   proto,
		}
	}

	// A rule on any other protocol number only matches that protocol
	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	rb := firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, 47, firewall.PortAny, firewall.PortAny, []string{"any"}, "", "", "", "", "")) // GRE
	fw.setRules(rb)
	require.NoError(t, fw.Drop(pkt(47), true, &h, cp, nil))
	assert.Equal(t, ErrNoMatchingRule, fw.Drop(pkt(50), true, &h, cp, nil)) // ESP
	assert.Equal(t, ErrNoMatchingRule, fw.Drop(pkt(iputil.IPProtocolTCP), true, &h, cp, nil))

	// A rule on either ICMP or ICMPv6 matches both
	for _, ruleProto := range []uint8{iputil.IPProtocolICMP, iputil.IPProtocolICMPv6} {
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
		rb := firewall.NewRulesBuilder(l)
		require.NoError(t, rb.AddRule(true, ruleProto, firewall.PortAny, firewall.PortAny, []string{"any"}, "", "", "", "", ""))
		fw.setRules(rb)
		require.NoError(t, fw.Drop(pkt(iputil.IPProtocolICMP), true, &h, cp, nil), "rule %d", ruleProto)
		require.NoError(t, fw.Drop(pkt(iputil.IPProtocolICMPv6), true, &h, cp, nil), "rule %d", ruleProto)
		assert.Equal(t, ErrNoMatchingRule, fw.Drop(pkt(47), true, &h, cp, nil), "rule %d", ruleProto)
	}

	// proto `any` rules apply to protocols with rules of their own, whichever rule was added first
	for _, anyFirst := range []bool{true, false} {
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
		rb := firewall.NewRulesBuilder(l)
		addAny := func() {
			require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 80, 80, []string{"any"}, "", "", "", "", ""))
		}
		if anyFirst {
			addAny()
		}
		require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 22, 22, []string{"any"}, "", "", "", "", ""))
		if !anyFirst {
			addAny()
		}
		fw.setRules(rb)

		for _, tc := range []struct {
			proto uint8
			port  uint16
			want  error
		}{
			{iputil.IPProtocolTCP, 22, nil},
			{iputil.IPProtocolTCP, 80, nil},
			{iputil.IPProtocolTCP, 23, ErrNoMatchingRule},
			{iputil.IPProtocolUDP, 80, nil},
			{iputil.IPProtocolUDP, 22, ErrNoMatchingRule},
		} {
			p := pkt(tc.proto)
			p.LocalPort = tc.port
			assert.Equal(t, tc.want, fw.Drop(p, true, &h, cp, nil), "anyFirst %v, proto %d, port %d", anyFirst, tc.proto, tc.port)
		}
	}

	// ICMP and ICMPv6 share one copy of each proto `any` rule, whichever rule was added first
	for _, anyFirst := range []bool{true, false} {
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
		rb := firewall.NewRulesBuilder(l)
		addAny := func() {
			require.NoError(t, rb.AddRule(true, firewall.ProtoAny, firewall.PortAny, firewall.PortAny, []string{"default-group"}, "", "", "", "", ""))
		}
		if anyFirst {
			addAny()
		}
		require.NoError(t, rb.AddRule(true, iputil.IPProtocolICMPv6, firewall.PortAny, firewall.PortAny, []string{"nope"}, "", "", "", "", ""))
		if !anyFirst {
			addAny()
		}
		fw.setRules(rb)

		require.NoError(t, fw.Drop(pkt(iputil.IPProtocolICMP), true, &h, cp, nil), "anyFirst %v", anyFirst)
		require.NoError(t, fw.Drop(pkt(iputil.IPProtocolICMPv6), true, &h, cp, nil), "anyFirst %v", anyFirst)
	}

	// Protocols without rules of their own have no rules to check until there is a proto `any` rule to share
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 22, 22, []string{"any"}, "", "", "", "", ""))
	fw.setRules(rb)
	assert.Equal(t, ErrNoMatchingRule, fw.Drop(pkt(47), true, &h, cp, nil))

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c.Certificate)
	rb = firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 22, 22, []string{"any"}, "", "", "", "", ""))
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, firewall.PortAny, firewall.PortAny, []string{"any"}, "", "", "", "", ""))
	fw.setRules(rb)
	require.NoError(t, fw.Drop(pkt(47), true, &h, cp, nil))
}

func TestFirewall_DropIPSpoofing(t *testing.T) {
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)
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
	rb := firewall.NewRulesBuilder(l)

	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", "", "", "", ""))
	fw.setRules(rb)
	cp := cert.NewCAPool()

	// Packet spoofed by `c1`. Note that the remote addr is not a valid one.
	p := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("192.0.2.1"),
		RemoteAddr: netip.MustParseAddr("192.0.2.3"),
		LocalPort:  1,
		RemotePort: 1,
		Protocol:   iputil.IPProtocolUDP,
		Fragment:   false,
	}
	assert.Equal(t, fw.Drop(p, true, &h1, cp, nil), ErrInvalidRemoteIP)
}

func TestFirewall_ConntrackSourceSpoofingAcrossPeers(t *testing.T) {
	l := test.NewLoggerWithOutput(&bytes.Buffer{})

	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("192.0.2.1/24"))

	owner := &dummyCert{
		name:     "owner",
		networks: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")},
	}

	victim := &cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "victim",
			networks: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
		},
	}
	victimHI := HostInfo{
		ConnectionState: &ConnectionState{peerCert: victim},
		vpnAddrs:        []netip.Addr{netip.MustParseAddr("192.0.2.2")},
	}
	victimHI.buildNetworks(myVpnNetworksTable, victim.Certificate)

	attacker := &cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "attacker",
			networks: []netip.Prefix{netip.MustParsePrefix("192.0.2.3/24")},
		},
	}
	attackerHI := HostInfo{
		ConnectionState: &ConnectionState{peerCert: attacker},
		vpnAddrs:        []netip.Addr{netip.MustParseAddr("192.0.2.3")},
	}
	attackerHI.buildNetworks(myVpnNetworksTable, attacker.Certificate)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, owner)
	rb := firewall.NewRulesBuilder(l)
	// Allow any inbound traffic that passes the cert / source-IP checks.
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	fw.setRules(rb)
	cp := cert.NewCAPool()

	flow := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("192.0.2.1"),
		RemoteAddr: netip.MustParseAddr("192.0.2.2"),
		LocalPort:  443,
		RemotePort: 55000,
		Protocol:   iputil.IPProtocolUDP,
	}

	require.NoError(t, fw.Drop(flow, true, &victimHI, cp, nil),
		"victim's own traffic from its own overlay IP must be allowed")

	unseen := flow
	unseen.RemotePort = 55001
	assert.Equal(t, ErrInvalidRemoteIP, fw.Drop(unseen, true, &attackerHI, cp, nil),
		"sanity: attacker forging victim's source IP must be rejected when no conntrack entry exists")

	got := fw.Drop(flow, true, &attackerHI, cp, nil)
	t.Logf("attacker replaying victim's 4-tuple: Drop returned %v (nil == packet ALLOWED == spoof succeeded)", got)
	assert.Equal(t, ErrInvalidRemoteIP, got,
		"SECURITY: attacker spoofed victim's overlay source IP (192.0.2.2) by reusing an existing conntrack 4-tuple; Drop returned %v instead of rejecting", got)
}

// BenchmarkFirewallDropConntrackHit measures Drop on an already-established flow
// (a conntrack hit). This is the fast path that the source-IP<->cert binding
// reordering adds work to, so it quantifies the cost of moving the address checks
// ahead of the conntrack lookup. Cases:
//   - simple:  peer cert has one address, no unsafe networks (h.networks == nil),
//     so the remote-address check is a single netip.Addr compare.
//   - complex: peer cert has unsafe networks (h.networks populated), so the
//     remote-address check is a BART lookup.
//   - noCache/localCache: whether a per-batch ConntrackCache is supplied, which in
//     the original code let the fast path skip straight past the address checks.
func BenchmarkFirewallDropConntrackHit(b *testing.B) {
	l := test.NewLoggerWithOutput(&bytes.Buffer{})

	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("192.0.2.1/24"))

	owner := &dummyCert{
		name:     "owner",
		networks: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")},
	}

	simpleCert := &cert.CachedCertificate{
		Certificate: &dummyCert{
			name:     "simple",
			networks: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
		},
	}
	simpleHost := &HostInfo{
		ConnectionState: &ConnectionState{peerCert: simpleCert},
		vpnAddrs:        []netip.Addr{netip.MustParseAddr("192.0.2.2")},
	}
	simpleHost.buildNetworks(myVpnNetworksTable, simpleCert.Certificate)

	complexCert := &cert.CachedCertificate{
		Certificate: &dummyCert{
			name:           "complex",
			networks:       []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		},
	}
	complexHost := &HostInfo{
		ConnectionState: &ConnectionState{peerCert: complexCert},
		vpnAddrs:        []netip.Addr{netip.MustParseAddr("192.0.2.2")},
	}
	complexHost.buildNetworks(myVpnNetworksTable, complexCert.Certificate)

	cp := cert.NewCAPool()

	flow := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("192.0.2.1"),
		RemoteAddr: netip.MustParseAddr("192.0.2.2"),
		LocalPort:  443,
		RemotePort: 55000,
		Protocol:   iputil.IPProtocolUDP,
	}

	cases := []struct {
		name     string
		host     *HostInfo
		useCache bool
	}{
		{"simple/noCache", simpleHost, false},
		{"simple/localCache", simpleHost, true},
		{"complex/noCache", complexHost, false},
		{"complex/localCache", complexHost, true},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			fw := NewFirewall(l, time.Second, time.Minute, time.Hour, owner)
			rb := firewall.NewRulesBuilder(l)
			require.NoError(b, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
			fw.setRules(rb)

			// Establish the conntrack entry so every benchmarked Drop is a hit.
			require.NoError(b, fw.Drop(flow, true, tc.host, cp, nil))

			var cache firewall.ConntrackCache
			if tc.useCache {
				cache = firewall.ConntrackCache{}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := fw.Drop(flow, true, tc.host, cp, cache); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
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

func TestNewFirewallFromConfig(t *testing.T) {
	l := test.NewLogger()
	// Test a bad rule definition
	c := &dummyCert{}
	cs, err := newCertState(cert.Version2, nil, c, false, cert.Curve_CURVE25519, nil, "aes")
	require.NoError(t, err)

	conf := config.NewC(test.NewLogger())
	conf.Settings["firewall"] = map[string]any{"outbound": "asdf"}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound failed to parse, should be an array of rules")

	// Test both port and code
	conf = config.NewC(test.NewLogger())
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "1", "code": "2"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; only one of port or code should be provided")

	// Test missing host, group, cidr, ca_name and ca_sha
	conf = config.NewC(test.NewLogger())
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; at least one of host, group, cidr, local_cidr, ca_name, or ca_sha must be provided")

	// Test code/port error
	conf = config.NewC(test.NewLogger())
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"code": "a", "host": "testh", "proto": "any"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; code was not a number; `a`")

	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "a", "host": "testh", "proto": "any"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; port was not a number; `a`")

	// Test proto error
	conf = config.NewC(test.NewLogger())
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"code": "1", "host": "testh"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; proto was not understood; ``")

	// Test cidr parse error
	conf = config.NewC(test.NewLogger())
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"code": "1", "cidr": "testh", "proto": "any"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; cidr did not parse; netip.ParsePrefix(\"testh\"): no '/'")

	// Test local_cidr parse error
	conf = config.NewC(test.NewLogger())
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"code": "1", "local_cidr": "testh", "proto": "any"}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.outbound rule #0; local_cidr did not parse; netip.ParsePrefix(\"testh\"): no '/'")

	// Test both group and groups
	conf = config.NewC(test.NewLogger())
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "group": "a", "groups": []string{"b", "c"}}}}
	_, err = NewFirewallFromConfig(l, cs, conf)
	require.EqualError(t, err, "firewall.inbound rule #0; only one of group or groups should be defined, both provided")
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
		Protocol:   iputil.IPProtocolUDP,
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

func newSetup(t *testing.T, l *slog.Logger, myPrefixes ...netip.Prefix) testsetup {
	c := dummyCert{
		name:     "me",
		networks: myPrefixes,
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}

	return newSetupFromCert(t, l, c)
}

func newSetupFromCert(t *testing.T, l *slog.Logger, c dummyCert) testsetup {
	myVpnNetworksTable := new(bart.Lite)
	for _, prefix := range c.Networks() {
		myVpnNetworksTable.Insert(prefix)
	}
	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	rb := firewall.NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	fw.setRules(rb)

	return testsetup{
		c:                  c,
		fw:                 fw,
		myVpnNetworksTable: myVpnNetworksTable,
	}
}

func TestFirewall_Drop_EnforceIPMatch(t *testing.T) {
	t.Parallel()
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)

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

		// The same rules plus one for the unsafe route
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
		rb := firewall.NewRulesBuilder(l)
		require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
		require.NoError(t, rb.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", unsafePrefix.String(), "", ""))
		fw.setRules(rb)
		tc.err = nil
		tc.Test(t, fw) //should pass
	})
}

// setRules builds rb for fw's networks and makes them its rules
func (f *Firewall) setRules(rb *firewall.RulesBuilder) {
	f.rules = rb.Build(f.assignedNetworks, f.unsafeNetworks)
}

func resetConntrack(fw *Firewall) {
	fw.Conntrack.Lock()
	fw.Conntrack.Conns = map[firewall.Packet]*conn{}
	fw.Conntrack.Unlock()
}
