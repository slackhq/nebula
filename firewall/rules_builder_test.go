package firewall

import (
	"math"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRulesBuilder_AddRule(t *testing.T) {
	l := test.NewLogger()

	ti, err := netip.ParsePrefix("1.2.3.4/32")
	require.NoError(t, err)

	ti6, err := netip.ParsePrefix("fd12::34/128")
	require.NoError(t, err)

	rb := NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 1, 1, []string{}, "", "", "", "", ""))
	rules := rb.Build(nil, nil)
	// An empty rule is any
	assert.True(t, rules.In.protos[iputil.IPProtocolTCP][1].Any.Any.Any)
	assert.Empty(t, rules.In.protos[iputil.IPProtocolTCP][1].Any.Groups)
	assert.Empty(t, rules.In.protos[iputil.IPProtocolTCP][1].Any.Hosts)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolUDP, 1, 1, []string{"g1"}, "", "", "", "", ""))
	rules = rb.Build(nil, nil)
	assert.Nil(t, rules.In.protos[iputil.IPProtocolUDP][1].Any.Any)
	assert.Contains(t, rules.In.protos[iputil.IPProtocolUDP][1].Any.Groups[0].Groups, "g1")
	assert.Empty(t, rules.In.protos[iputil.IPProtocolUDP][1].Any.Hosts)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolICMP, 1, 1, []string{}, "h1", "", "", "", ""))
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolICMPv6, 1, 1, []string{}, "h2", "", "", "", ""))
	rules = rb.Build(nil, nil)
	//no matter what port is given for icmp, it should end up as "any"
	assert.Nil(t, rules.In.protos[iputil.IPProtocolICMP][PortAny].Any.Any)
	assert.Empty(t, rules.In.protos[iputil.IPProtocolICMP][PortAny].Any.Groups)
	assert.Contains(t, rules.In.protos[iputil.IPProtocolICMP][PortAny].Any.Hosts, "h1")

	// ICMP and ICMPv6 share one set of rules
	assert.Contains(t, rules.In.protos[iputil.IPProtocolICMP][PortAny].Any.Hosts, "h2")
	assert.Contains(t, rules.In.protos[iputil.IPProtocolICMPv6][PortAny].Any.Hosts, "h1")

	// Any other protocol number gets its own rules
	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, 47, 0, 0, []string{"g1"}, "", "", "", "", "")) // GRE
	rules = rb.Build(nil, nil)
	assert.Contains(t, rules.In.protos[47][PortAny].Any.Groups[0].Groups, "g1")
	assert.Nil(t, rules.In.protos[iputil.IPProtocolTCP])

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 1, 1, []string{}, "", ti.String(), "", "", ""))
	rules = rb.Build(nil, nil)
	assert.Nil(t, rules.Out.protos[ProtoAny][1].Any.Any)
	_, ok := rules.Out.protos[ProtoAny][1].Any.CIDR.Get(ti)
	assert.True(t, ok)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 1, 1, []string{}, "", ti6.String(), "", "", ""))
	rules = rb.Build(nil, nil)
	assert.Nil(t, rules.Out.protos[ProtoAny][1].Any.Any)
	_, ok = rules.Out.protos[ProtoAny][1].Any.CIDR.Get(ti6)
	assert.True(t, ok)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 1, 1, []string{}, "", "", ti.String(), "", ""))
	rules = rb.Build(nil, nil)
	assert.NotNil(t, rules.Out.protos[ProtoAny][1].Any.Any)
	ok = rules.Out.protos[ProtoAny][1].Any.Any.LocalCIDR.Get(ti)
	assert.True(t, ok)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 1, 1, []string{}, "", "", ti6.String(), "", ""))
	rules = rb.Build(nil, nil)
	assert.NotNil(t, rules.Out.protos[ProtoAny][1].Any.Any)
	ok = rules.Out.protos[ProtoAny][1].Any.Any.LocalCIDR.Get(ti6)
	assert.True(t, ok)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolUDP, 1, 1, []string{"g1"}, "", "", "", "ca-name", ""))
	rules = rb.Build(nil, nil)
	assert.Contains(t, rules.In.protos[iputil.IPProtocolUDP][1].CANames, "ca-name")

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolUDP, 1, 1, []string{"g1"}, "", "", "", "", "ca-sha"))
	rules = rb.Build(nil, nil)
	assert.Contains(t, rules.In.protos[iputil.IPProtocolUDP][1].CAShas, "ca-sha")

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "any", "", "", "", ""))
	rules = rb.Build(nil, nil)
	assert.True(t, rules.Out.protos[ProtoAny][0].Any.Any.Any)

	rb = NewRulesBuilder(l)
	anyIp, err := netip.ParsePrefix("0.0.0.0/0")
	require.NoError(t, err)

	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", anyIp.String(), "", "", ""))
	rules = rb.Build(nil, nil)
	assert.Nil(t, rules.Out.protos[ProtoAny][0].Any.Any)
	table, ok := rules.Out.protos[ProtoAny][0].Any.CIDR.Lookup(netip.MustParseAddr("1.1.1.1"))
	assert.True(t, table.Any)
	table, ok = rules.Out.protos[ProtoAny][0].Any.CIDR.Lookup(netip.MustParseAddr("9::9"))
	assert.False(t, ok)

	rb = NewRulesBuilder(l)
	anyIp6, err := netip.ParsePrefix("::/0")
	require.NoError(t, err)

	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", anyIp6.String(), "", "", ""))
	rules = rb.Build(nil, nil)
	assert.Nil(t, rules.Out.protos[ProtoAny][0].Any.Any)
	table, ok = rules.Out.protos[ProtoAny][0].Any.CIDR.Lookup(netip.MustParseAddr("9::9"))
	assert.True(t, table.Any)
	table, ok = rules.Out.protos[ProtoAny][0].Any.CIDR.Lookup(netip.MustParseAddr("1.1.1.1"))
	assert.False(t, ok)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", "any", "", "", ""))
	rules = rb.Build(nil, nil)
	assert.True(t, rules.Out.protos[ProtoAny][0].Any.Any.Any)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", "", anyIp.String(), "", ""))
	rules = rb.Build(nil, nil)
	assert.False(t, rules.Out.protos[ProtoAny][0].Any.Any.Any)
	assert.True(t, rules.Out.protos[ProtoAny][0].Any.Any.LocalCIDR.Lookup(netip.MustParseAddr("1.1.1.1")))
	assert.False(t, rules.Out.protos[ProtoAny][0].Any.Any.LocalCIDR.Lookup(netip.MustParseAddr("9::9")))

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", "", anyIp6.String(), "", ""))
	rules = rb.Build(nil, nil)
	assert.False(t, rules.Out.protos[ProtoAny][0].Any.Any.Any)
	assert.True(t, rules.Out.protos[ProtoAny][0].Any.Any.LocalCIDR.Lookup(netip.MustParseAddr("9::9")))
	assert.False(t, rules.Out.protos[ProtoAny][0].Any.Any.LocalCIDR.Lookup(netip.MustParseAddr("1.1.1.1")))

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", "", "any", "", ""))
	rules = rb.Build(nil, nil)
	assert.True(t, rules.Out.protos[ProtoAny][0].Any.Any.Any)

	// Every protocol number is accepted
	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, math.MaxUint8, 0, 0, []string{}, "", "", "", "", ""))
	rules = rb.Build(nil, nil)
	assert.True(t, rules.In.protos[math.MaxUint8][PortAny].Any.Any.Any)

	// Test error conditions, a bad rule is reported when it's added
	rb = NewRulesBuilder(l)
	require.Error(t, rb.AddRule(true, ProtoAny, 10, 0, []string{}, "", "", "", "", ""))
	require.Error(t, rb.AddRule(true, ProtoAny, 0, 0, []string{}, "", "junk", "", "", ""))
	require.Error(t, rb.AddRule(true, ProtoAny, 0, 0, []string{}, "", "", "junk", "", ""))

	// ICMP and ICMPv6 share one copy of each proto `any` rule
	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, ProtoAny, PortAny, PortAny, []string{"default-group"}, "", "", "", "", ""))
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolICMPv6, PortAny, PortAny, []string{"nope"}, "", "", "", "", ""))
	rules = rb.Build(nil, nil)
	assert.Len(t, rules.In.protos[iputil.IPProtocolICMP][PortAny].Any.Groups, 2)
	assert.Len(t, rules.In.protos[iputil.IPProtocolICMPv6][PortAny].Any.Groups, 2)

	// No rules allow nothing
	rules = NewRulesBuilder(l).Build(nil, nil)
	for proto := range rules.In.protos {
		assert.Nil(t, rules.In.protos[proto], "proto %d", proto)
		assert.Nil(t, rules.Out.protos[proto], "proto %d", proto)
	}
}

// TestRulesBuilder_sharedLocalCIDR ensures local cidrs shared between rules and ports are copied, not changed,
// when another rule's local cidrs are added to them. The prefixes share their first octet so the copy has to reach
// past the root of the shared table.
func TestRulesBuilder_sharedLocalCIDR(t *testing.T) {
	vpnNetworks := []netip.Prefix{
		netip.MustParsePrefix("10.1.0.5/16"),
		netip.MustParsePrefix("10.2.0.5/16"),
		netip.MustParsePrefix("fd00:1::5/64"),
	}
	unsafeNetworks := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}
	vpn1 := netip.MustParseAddr("10.1.9.9")
	vpn2 := netip.MustParseAddr("10.2.9.9")
	vpn6 := netip.MustParseAddr("fd00:1::9")
	h1Extra := netip.MustParseAddr("10.3.0.1")
	h1Extra6 := netip.MustParseAddr("fd00:2::1")
	h2Own := netip.MustParseAddr("10.4.0.1")

	rb := NewRulesBuilder(test.NewLogger())
	// h1 allows the vpn networks by default on ports 1 and 2, and 10.3.0.0/16 and fd00:2::/64 as well on port 1
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 1, 2, nil, "h1", "", "", "", ""))
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 1, 1, nil, "h1", "", "10.3.0.0/16", "", ""))
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 1, 1, nil, "h1", "", "fd00:2::/64", "", ""))
	// h2 allows 10.4.0.0/16 on ports 1 and 2, and the vpn networks by default as well on port 1
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 1, 2, nil, "h2", "", "10.4.0.0/16", "", ""))
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 1, 1, nil, "h2", "", "", "", ""))
	// h3 only has the default
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 3, 3, nil, "h3", "", "", "", ""))
	rules := rb.Build(vpnNetworks, unsafeNetworks)

	for _, tc := range []struct {
		port int32
		host string
		addr netip.Addr
		want bool
	}{
		{1, "h1", vpn1, true},
		{1, "h1", vpn2, true},
		{1, "h1", vpn6, true},
		{1, "h1", h1Extra, true},
		{1, "h1", h1Extra6, true},
		{1, "h1", h2Own, false},
		{2, "h1", vpn1, true},
		{2, "h1", h1Extra, false},
		{2, "h1", h1Extra6, false},
		{1, "h2", h2Own, true},
		{1, "h2", vpn1, true},
		{1, "h2", vpn2, true},
		{1, "h2", vpn6, true},
		{1, "h2", h1Extra, false},
		{2, "h2", h2Own, true},
		{2, "h2", vpn1, false},
		{2, "h2", vpn6, false},
		{3, "h3", vpn1, true},
		{3, "h3", vpn2, true},
		{3, "h3", vpn6, true},
		{3, "h3", h1Extra, false},
		{3, "h3", h1Extra6, false},
		{3, "h3", h2Own, false},
	} {
		lr := rules.In.protos[iputil.IPProtocolTCP][tc.port].Any.Hosts[tc.host]
		assert.Equal(t, tc.want, lr.match(&Packet{LocalAddr: tc.addr}, nil), "port %d, %s, %s", tc.port, tc.host, tc.addr)
	}
}
