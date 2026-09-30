package firewall

import (
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rulesAt returns the rules that a packet on proto with the given port is checked against, in id order.
// port may also be PortAny or PortFragment.
func (t *Table) rulesAt(proto uint8, port int32) []*rule {
	pi := t.protos[proto]
	if pi == nil {
		return nil
	}

	p := &Packet{Protocol: proto, Fragment: port == PortFragment}
	if port > 0 {
		p.LocalPort = uint16(port)
	}

	var rules []*rule
	for id := range pi.whichMatch(p, true).all() {
		rules = append(rules, &t.rules[id])
	}
	return rules
}

// oneRuleAt returns the single rule that rulesAt finds, and fails the test when there is not exactly one.
func oneRuleAt(t *testing.T, table *Table, proto uint8, key int32) *rule {
	t.Helper()
	rules := table.rulesAt(proto, key)
	require.Len(t, rules, 1)
	return rules[0]
}

func TestRulesBuilder_AddRule(t *testing.T) {
	l := test.NewLogger()

	ti := netip.MustParsePrefix("1.2.3.4/32")
	ti6 := netip.MustParsePrefix("fd12::34/128")

	rb := NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 1, 1, []string{}, "", "", "", "", ""))
	rules := rb.Build(nil, nil)
	// An empty rule is any
	r := oneRuleAt(t, rules.In, iputil.IPProtocolTCP, 1)
	assert.True(t, r.remoteAny)
	assert.Empty(t, r.groups)
	assert.Empty(t, r.host)
	// It applies only to its own port.
	assert.Empty(t, rules.In.rulesAt(iputil.IPProtocolTCP, 2))
	assert.Empty(t, rules.In.rulesAt(iputil.IPProtocolTCP, PortAny))

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolUDP, 1, 1, []string{"g1"}, "", "", "", "", ""))
	rules = rb.Build(nil, nil)
	r = oneRuleAt(t, rules.In, iputil.IPProtocolUDP, 1)
	assert.False(t, r.remoteAny)
	assert.Equal(t, []string{"g1"}, r.groups)
	assert.Empty(t, r.host)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolICMP, 1, 1, []string{}, "h1", "", "", "", ""))
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolICMPv6, 1, 1, []string{}, "h2", "", "", "", ""))
	rules = rb.Build(nil, nil)
	// An ICMP rule is port `any` regardless of the port given, and ICMP and ICMPv6 share one set of rules.
	for _, proto := range []uint8{iputil.IPProtocolICMP, iputil.IPProtocolICMPv6} {
		rs := rules.In.rulesAt(proto, PortAny)
		require.Len(t, rs, 2, "proto %d", proto)
		assert.False(t, rs[0].remoteAny)
		assert.Equal(t, "h1", rs[0].host)
		assert.Equal(t, "h2", rs[1].host)
	}
	assert.Same(t, rules.In.protos[iputil.IPProtocolICMP], rules.In.protos[iputil.IPProtocolICMPv6])

	// Any other protocol number gets its own rules
	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, 47, 0, 0, []string{"g1"}, "", "", "", "", "")) // GRE
	rules = rb.Build(nil, nil)
	assert.Equal(t, []string{"g1"}, oneRuleAt(t, rules.In, 47, PortAny).groups)
	assert.Nil(t, rules.In.protos[iputil.IPProtocolTCP])

	// A proto `any` rule with a port applies to every protocol with ports, and ProtoAny itself has none.
	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 1, 1, []string{}, "", ti.String(), "", "", ""))
	rules = rb.Build(nil, nil)
	assert.Empty(t, rules.Out.rulesAt(ProtoAny, 1))
	r = oneRuleAt(t, rules.Out, iputil.IPProtocolTCP, 1)
	assert.False(t, r.remoteAny)
	assert.Equal(t, ti, r.cidr)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 1, 1, []string{}, "", ti6.String(), "", "", ""))
	rules = rb.Build(nil, nil)
	r = oneRuleAt(t, rules.Out, iputil.IPProtocolTCP, 1)
	assert.False(t, r.remoteAny)
	assert.Equal(t, ti6, r.cidr)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 1, 1, []string{}, "", "", ti.String(), "", ""))
	rules = rb.Build(nil, nil)
	r = oneRuleAt(t, rules.Out, iputil.IPProtocolTCP, 1)
	assert.True(t, r.remoteAny)
	assert.False(t, r.localAny)
	assert.Equal(t, []netip.Prefix{ti}, r.local)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 1, 1, []string{}, "", "", ti6.String(), "", ""))
	rules = rb.Build(nil, nil)
	r = oneRuleAt(t, rules.Out, iputil.IPProtocolTCP, 1)
	assert.True(t, r.remoteAny)
	assert.False(t, r.localAny)
	assert.Equal(t, []netip.Prefix{ti6}, r.local)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolUDP, 1, 1, []string{"g1"}, "", "", "", "ca-name", ""))
	rules = rb.Build(nil, nil)
	assert.Equal(t, "ca-name", oneRuleAt(t, rules.In, iputil.IPProtocolUDP, 1).caName)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolUDP, 1, 1, []string{"g1"}, "", "", "", "", "ca-sha"))
	rules = rb.Build(nil, nil)
	assert.Equal(t, "ca-sha", oneRuleAt(t, rules.In, iputil.IPProtocolUDP, 1).caSha)

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "any", "", "", "", ""))
	rules = rb.Build(nil, nil)
	assert.True(t, oneRuleAt(t, rules.Out, ProtoAny, 0).remoteAny)

	// 0.0.0.0/0 allows any IPv4 address, but no IPv6 address.
	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", "0.0.0.0/0", "", "", ""))
	rules = rb.Build(nil, nil)
	r = oneRuleAt(t, rules.Out, ProtoAny, 0)
	assert.False(t, r.remoteAny)
	assert.True(t, r.matchRemote(netip.MustParseAddr("1.1.1.1"), nil))
	assert.False(t, r.matchRemote(netip.MustParseAddr("9::9"), nil))

	// ::/0 allows any IPv6 address, but no IPv4 address.
	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", "::/0", "", "", ""))
	rules = rb.Build(nil, nil)
	r = oneRuleAt(t, rules.Out, ProtoAny, 0)
	assert.False(t, r.remoteAny)
	assert.True(t, r.matchRemote(netip.MustParseAddr("9::9"), nil))
	assert.False(t, r.matchRemote(netip.MustParseAddr("1.1.1.1"), nil))

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", "any", "", "", ""))
	rules = rb.Build(nil, nil)
	assert.True(t, oneRuleAt(t, rules.Out, ProtoAny, 0).remoteAny)

	// A local cidr is likewise limited to its own address family.
	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", "", "0.0.0.0/0", "", ""))
	rules = rb.Build(nil, nil)
	r = oneRuleAt(t, rules.Out, ProtoAny, 0)
	assert.False(t, r.localAny)
	assert.True(t, r.matchLocal(netip.MustParseAddr("1.1.1.1")))
	assert.False(t, r.matchLocal(netip.MustParseAddr("9::9")))

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", "", "::/0", "", ""))
	rules = rb.Build(nil, nil)
	r = oneRuleAt(t, rules.Out, ProtoAny, 0)
	assert.False(t, r.localAny)
	assert.True(t, r.matchLocal(netip.MustParseAddr("9::9")))
	assert.False(t, r.matchLocal(netip.MustParseAddr("1.1.1.1")))

	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(false, ProtoAny, 0, 0, []string{}, "", "", "any", "", ""))
	rules = rb.Build(nil, nil)
	assert.True(t, oneRuleAt(t, rules.Out, ProtoAny, 0).localAny)

	// Every protocol number is accepted
	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, math.MaxUint8, 0, 0, []string{}, "", "", "", "", ""))
	rules = rb.Build(nil, nil)
	assert.True(t, oneRuleAt(t, rules.In, math.MaxUint8, PortAny).remoteAny)

	// Test error conditions, a bad rule is reported when it's added
	rb = NewRulesBuilder(l)
	require.Error(t, rb.AddRule(true, ProtoAny, 10, 0, []string{}, "", "", "", "", ""))
	require.Error(t, rb.AddRule(true, ProtoAny, PortFragment-1, 0, []string{}, "", "", "", "", ""))
	require.Error(t, rb.AddRule(true, ProtoAny, 1, math.MaxUint16+1, []string{}, "", "", "", "", ""))
	require.Error(t, rb.AddRule(true, ProtoAny, 0, 0, []string{}, "", "junk", "", "", ""))
	require.Error(t, rb.AddRule(true, ProtoAny, 0, 0, []string{}, "", "", "junk", "", ""))

	// ICMP and ICMPv6 share one copy of each proto `any` rule
	rb = NewRulesBuilder(l)
	require.NoError(t, rb.AddRule(true, ProtoAny, PortAny, PortAny, []string{"default-group"}, "", "", "", "", ""))
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolICMPv6, PortAny, PortAny, []string{"nope"}, "", "", "", "", ""))
	rules = rb.Build(nil, nil)
	assert.Len(t, rules.In.rules, 2)
	assert.Len(t, rules.In.rulesAt(iputil.IPProtocolICMP, PortAny), 2)
	assert.Len(t, rules.In.rulesAt(iputil.IPProtocolICMPv6, PortAny), 2)

	// No rules allow nothing
	rules = NewRulesBuilder(l).Build(nil, nil)
	for proto := range rules.In.protos {
		assert.Nil(t, rules.In.protos[proto], "proto %d", proto)
		assert.Nil(t, rules.Out.protos[proto], "proto %d", proto)
	}
}

// TestRulesBuilder_protoIndex checks which packets each kind of port clause covers, and which protocols
// share an index.
func TestRulesBuilder_protoIndex(t *testing.T) {
	rb := NewRulesBuilder(test.NewLogger())
	require.NoError(t, rb.AddRule(true, ProtoAny, PortAny, PortAny, nil, "any", "", "", "", ""))
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 22, 22, nil, "port", "", "", "", ""))
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, 1024, math.MaxUint16, nil, "range", "", "", "", ""))
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, PortFragment, PortFragment, nil, "fragment", "", "", "", ""))
	// A range that includes port 0 is port `any`.
	require.NoError(t, rb.AddRule(true, iputil.IPProtocolUDP, 0, 100, nil, "zero", "", "", "", ""))
	// GRE has no ports, so a port rule on it never applies.
	require.NoError(t, rb.AddRule(true, 47, 22, 22, nil, "gre", "", "", "", ""))
	rules := rb.Build(nil, nil)

	hosts := func(proto uint8, key int32) []string {
		var hosts []string
		for _, r := range rules.In.rulesAt(proto, key) {
			hosts = append(hosts, r.host)
		}
		return hosts
	}

	assert.Equal(t, []string{"any", "fragment"}, hosts(iputil.IPProtocolTCP, PortFragment))
	assert.Equal(t, []string{"any"}, hosts(iputil.IPProtocolTCP, PortAny))
	assert.Equal(t, []string{"any"}, hosts(iputil.IPProtocolTCP, 21))
	assert.Equal(t, []string{"any", "port"}, hosts(iputil.IPProtocolTCP, 22))
	assert.Equal(t, []string{"any"}, hosts(iputil.IPProtocolTCP, 23))
	assert.Equal(t, []string{"any"}, hosts(iputil.IPProtocolTCP, 1023))
	assert.Equal(t, []string{"any", "range"}, hosts(iputil.IPProtocolTCP, 1024))
	assert.Equal(t, []string{"any", "range"}, hosts(iputil.IPProtocolTCP, math.MaxUint16))

	assert.Equal(t, []string{"any", "zero"}, hosts(iputil.IPProtocolUDP, PortFragment))
	assert.Equal(t, []string{"any", "zero"}, hosts(iputil.IPProtocolUDP, PortAny))
	assert.Equal(t, []string{"any", "zero"}, hosts(iputil.IPProtocolUDP, math.MaxUint16))

	// A protocol without ports sees only the port `any` rules, and the port `fragment` rules for a fragment.
	assert.False(t, rules.In.protos[47].hasPorts)
	assert.Equal(t, []string{"any"}, hosts(47, PortAny))
	assert.Equal(t, []string{"any"}, hosts(47, 22))
	assert.Equal(t, []string{"any"}, hosts(47, PortFragment))
	assert.Equal(t, []string{"any"}, hosts(iputil.IPProtocolICMP, PortFragment))

	// Protocols without rules of their own share an index of the proto `any` rules: one for protocols with
	// ports and one for protocols without.
	assert.True(t, rules.In.protos[iputil.IPProtocolSCTP].hasPorts)
	assert.Equal(t, []string{"any"}, hosts(iputil.IPProtocolSCTP, 5000))
	assert.Same(t, rules.In.protos[iputil.IPProtocolSCTP], rules.In.protos[iputil.IPProtocolDCCP])
	assert.NotSame(t, rules.In.protos[iputil.IPProtocolSCTP], rules.In.protos[iputil.IPProtocolTCP])
	assert.Equal(t, []string{"any"}, hosts(50, PortAny))
	assert.Same(t, rules.In.protos[ProtoAny], rules.In.protos[50])
	assert.Same(t, rules.In.protos[ProtoAny], rules.In.protos[iputil.IPProtocolICMP])
	assert.NotSame(t, rules.In.protos[ProtoAny], rules.In.protos[iputil.IPProtocolSCTP])
	assert.Nil(t, rules.Out.protos[iputil.IPProtocolTCP])
}

// TestRulesBuilder_manyRules checks that rule ids beyond the first byte of a rule set are indexed correctly.
func TestRulesBuilder_manyRules(t *testing.T) {
	rb := NewRulesBuilder(test.NewLogger())
	const n = 130
	for i := range n {
		require.NoError(t, rb.AddRule(true, iputil.IPProtocolTCP, int32(i+1), int32(i+1), nil, fmt.Sprintf("h%d", i), "", "", "", ""))
	}
	require.NoError(t, rb.AddRule(true, ProtoAny, PortAny, PortAny, nil, "any", "", "", "", ""))
	rules := rb.Build(nil, nil)

	assert.Equal(t, ruleSetLen(n+1), rules.In.protos[iputil.IPProtocolTCP].byPort.setLen)
	for i := range n {
		rs := rules.In.rulesAt(iputil.IPProtocolTCP, int32(i+1))
		require.Len(t, rs, 2, "port %d", i+1)
		assert.Equal(t, "any", rs[0].host)
		assert.Equal(t, fmt.Sprintf("h%d", i), rs[1].host)
	}
	assert.Len(t, rules.In.rulesAt(iputil.IPProtocolTCP, n+1), 1)
}

// TestRulesBuilder_defaultLocalCIDR checks which local addresses rules allow when there are unsafe networks.
// A rule without a local cidr allows only the vpn networks, and a rule with one allows only that cidr.
func TestRulesBuilder_defaultLocalCIDR(t *testing.T) {
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

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	caPool := cert.NewCAPool()
	require.NoError(t, caPool.AddCA(ca))
	certs := map[string]*cert.CachedCertificate{}
	for _, name := range []string{"h1", "h2", "h3"} {
		crt, _, _, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, name, time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.9/16")}, nil, nil)
		c, err := caPool.VerifyCertificate(time.Now(), crt)
		require.NoError(t, err)
		certs[name] = c
	}

	for _, tc := range []struct {
		port uint16
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
		// Only h3 is allowed on port 3.
		{3, "h1", vpn1, false},
	} {
		p := &Packet{Protocol: iputil.IPProtocolTCP, LocalPort: tc.port, LocalAddr: tc.addr, RemoteAddr: netip.MustParseAddr("10.1.0.9")}
		assert.Equal(t, tc.want, rules.In.Match(p, true, certs[tc.host], caPool), "port %d, %s, %s", tc.port, tc.host, tc.addr)
	}
}
