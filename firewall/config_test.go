package firewall

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// Test_parsePort_invalid covers inputs that must error. The named bug is
// that int32(strconv.Atoi("4294967296")) truncates to 0 == PortAny,
// silently turning a typo into a match-all-ports rule; the rest are
// representative syntax/range probes.
func Test_parsePort_invalid(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantErrContains string
	}{
		// Numeric overflow (the named bug + boundary).
		{"named bug: 2^32 truncates to PortAny", "4294967296", "out of range"},
		{"just above max real port", "65536", "out of range"},

		// Negatives route through the range branch and hit the empty-half
		// guard; included as defense in depth so a future refactor cannot
		// accidentally reach the int32 cast.
		{"negative", "-1", "could not be parsed"},

		// Syntax probes.
		{"NUL between digits", "4\x002", "was not a number"},
		{"hex notation", "0x10", "was not a number"},
		{"scientific notation", "1e3", "was not a number"},
		{"leading whitespace", " 42", "was not a number"},
		{"fullwidth digits", "４２", "was not a number"},

		// Range branch.
		{"range upper out of range", "1-65536", "ending range out of range"},
		{"range lower out of range", "65536-65537", "beginning range out of range"},
		{"range with negative upper", "1--1", "ending range was not a number"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parsePort(tc.input)
			require.Error(t, err, "input %q must error", tc.input)
			require.ErrorContains(t, err, tc.wantErrContains)
		})
	}
}

// Test_parsePort_valid_boundaries locks in success cases at 0, 1, and 65535
// so a future refactor cannot regress the boundaries.
func Test_parsePort_valid_boundaries(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantStart int32
		wantEnd   int32
	}{
		{"zero is PortAny", "0", 0, 0},
		{"min real port", "1", 1, 1},
		{"max real port", "65535", 65535, 65535},
		{"range zero to max forces end to zero", "0-65535", 0, 0},
		{"range max to max", "65535-65535", 65535, 65535},
		{"range one to max", "1-65535", 1, 65535},
		{"range with whitespace inside", " 1 - 2    ", 1, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, e, err := parsePort(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.wantStart, s, "start port")
			assert.Equal(t, tc.wantEnd, e, "end port")
		})
	}
}

func TestAddRulesFromConfig(t *testing.T) {
	l := test.NewLogger()
	// Test adding tcp rule
	conf := config.NewC(test.NewLogger())
	mf := &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "1", "proto": "tcp", "host": "a"}}}
	require.NoError(t, addRulesFromConfig(l, false, conf, mf))
	assert.Equal(t, addRuleCall{incoming: false, proto: iputil.IPProtocolTCP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall)

	// Test adding udp rule
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "1", "proto": "udp", "host": "a"}}}
	require.NoError(t, addRulesFromConfig(l, false, conf, mf))
	assert.Equal(t, addRuleCall{incoming: false, proto: iputil.IPProtocolUDP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall)

	// Test adding udplite, dccp, and sctp rules
	for name, proto := range map[string]uint8{"udplite": iputil.IPProtocolUDPLite, "dccp": iputil.IPProtocolDCCP, "sctp": iputil.IPProtocolSCTP} {
		conf = config.NewC(test.NewLogger())
		mf = &mockFirewall{}
		conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "1-2", "proto": name, "host": "a"}}}
		require.NoError(t, addRulesFromConfig(l, false, conf, mf), name)
		assert.Equal(t, addRuleCall{incoming: false, proto: proto, startPort: 1, endPort: 2, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall, name)
	}

	// Test adding icmp rule
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "1", "proto": "icmp", "host": "a"}}}
	require.NoError(t, addRulesFromConfig(l, false, conf, mf))
	assert.Equal(t, addRuleCall{incoming: false, proto: iputil.IPProtocolICMP, startPort: PortAny, endPort: PortAny, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall)

	// Test adding icmp rule no port
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"proto": "icmp", "host": "a"}}}
	require.NoError(t, addRulesFromConfig(l, false, conf, mf))
	assert.Equal(t, addRuleCall{incoming: false, proto: iputil.IPProtocolICMP, startPort: PortAny, endPort: PortAny, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall)

	// Test adding rules by protocol number, as yaml would give a string or an int
	for _, proto := range []any{"47", 47} {
		conf = config.NewC(test.NewLogger())
		mf = &mockFirewall{}
		conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "any", "proto": proto, "host": "a"}}}
		require.NoError(t, addRulesFromConfig(l, false, conf, mf), proto)
		assert.Equal(t, addRuleCall{incoming: false, proto: 47, startPort: PortAny, endPort: PortAny, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall, proto)
	}

	// Test ICMP and ICMPv6, by name and by number, still ignore ports
	for _, tc := range []struct {
		given any
		want  uint8
	}{
		{"icmp", iputil.IPProtocolICMP},
		{"icmpv6", iputil.IPProtocolICMPv6},
		{iputil.IPProtocolICMP, iputil.IPProtocolICMP},
		{iputil.IPProtocolICMPv6, iputil.IPProtocolICMPv6},
	} {
		conf = config.NewC(test.NewLogger())
		mf = &mockFirewall{}
		conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "1", "proto": tc.given, "host": "a"}}}
		require.NoError(t, addRulesFromConfig(l, false, conf, mf), tc.given)
		assert.Equal(t, addRuleCall{incoming: false, proto: tc.want, startPort: PortAny, endPort: PortAny, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall, tc.given)
	}

	// Test protocols that aren't a known name or a number from 1 to 255
	for _, proto := range []string{"0", "256", "-1", "gre"} {
		conf = config.NewC(test.NewLogger())
		mf = &mockFirewall{}
		conf.Settings["firewall"] = map[string]any{"outbound": []any{map[string]any{"port": "any", "proto": proto, "host": "a"}}}
		require.EqualError(t, addRulesFromConfig(l, false, conf, mf), "firewall.outbound rule #0; proto was not understood; `"+proto+"`")
	}

	// Test adding any rule
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "host": "a"}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: nil, host: "a", ip: "", localIp: ""}, mf.lastCall)

	// Test adding rule with cidr
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "cidr": cidr.String()}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: cidr.String(), localIp: ""}, mf.lastCall)

	// Test adding rule with local_cidr
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "local_cidr": cidr.String()}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: "", localIp: cidr.String()}, mf.lastCall)

	// Test adding rule with cidr ipv6
	cidr6 := netip.MustParsePrefix("fd00::/8")
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "cidr": cidr6.String()}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: cidr6.String(), localIp: ""}, mf.lastCall)

	// Test adding rule with any cidr
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "cidr": "any"}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: "any", localIp: ""}, mf.lastCall)

	// Test adding rule with junk cidr, which RulesBuilder rejects
	conf = config.NewC(test.NewLogger())
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "cidr": "junk/junk"}}}
	require.EqualError(t, addRulesFromConfig(l, true, conf, NewRulesBuilder(l)), "firewall.inbound rule #0; cidr did not parse; netip.ParsePrefix(\"junk/junk\"): ParseAddr(\"junk\"): unable to parse IP")

	// Test adding rule with local_cidr ipv6
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "local_cidr": cidr6.String()}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: "", localIp: cidr6.String()}, mf.lastCall)

	// Test adding rule with any local_cidr
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "local_cidr": "any"}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: nil, localIp: "any"}, mf.lastCall)

	// Test adding rule with junk local_cidr, which RulesBuilder rejects
	conf = config.NewC(test.NewLogger())
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "local_cidr": "junk/junk"}}}
	require.EqualError(t, addRulesFromConfig(l, true, conf, NewRulesBuilder(l)), "firewall.inbound rule #0; local_cidr did not parse; netip.ParsePrefix(\"junk/junk\"): ParseAddr(\"junk\"): unable to parse IP")

	// Test adding rule with ca_sha
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "ca_sha": "12312313123"}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: "", localIp: "", caSha: "12312313123"}, mf.lastCall)

	// Test adding rule with ca_name
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "ca_name": "root01"}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: "", localIp: "", caName: "root01"}, mf.lastCall)

	// Test single group
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "group": "a"}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: []string{"a"}, ip: "", localIp: ""}, mf.lastCall)

	// Test single groups
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "groups": "a"}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: []string{"a"}, ip: "", localIp: ""}, mf.lastCall)

	// Test multiple AND groups
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "groups": []string{"a", "b"}}}}
	require.NoError(t, addRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: ProtoAny, startPort: 1, endPort: 1, groups: []string{"a", "b"}, ip: "", localIp: ""}, mf.lastCall)

	// Test Add error
	conf = config.NewC(test.NewLogger())
	mf = &mockFirewall{}
	mf.nextCallReturn = errors.New("test error")
	conf.Settings["firewall"] = map[string]any{"inbound": []any{map[string]any{"port": "1", "proto": "any", "host": "a"}}}
	require.EqualError(t, addRulesFromConfig(l, true, conf, mf), "firewall.inbound rule #0; test error")
}

// TestRulesFromConfig_defaultLocalCIDR ensures rules without a local_cidr allow only the vpn networks when there are
// unsafe networks, unless default_local_cidr_any is set, and that a rule's own local_cidr is kept either way
func TestRulesFromConfig_defaultLocalCIDR(t *testing.T) {
	vpnNetworks := []netip.Prefix{netip.MustParsePrefix("10.1.0.5/16")}
	unsafeNetworks := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}
	vpnAddr := netip.MustParseAddr("10.1.9.9")
	unsafeAddr := netip.MustParseAddr("192.168.0.3")

	// ruleOnPort returns the rule on proto whose port clause is exactly port, chosen from the rules that a packet
	// on port is checked against.
	ruleOnPort := func(t *testing.T, table *Table, proto uint8, port int32) *rule {
		t.Helper()
		for _, r := range table.rulesAt(proto, port) {
			if r.startPort == port {
				return r
			}
		}
		require.Failf(t, "no rule found", "proto %d port %d", proto, port)
		return nil
	}

	for _, tc := range []struct {
		name                string
		unsafeNetworks      []netip.Prefix
		defaultLocalCIDRAny bool
		wantUnsafe          bool
	}{
		{"no unsafe networks", nil, false, true},
		{"unsafe networks", unsafeNetworks, false, false},
		{"unsafe networks and default_local_cidr_any", unsafeNetworks, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := config.NewC(test.NewLogger())
			conf.Settings["firewall"] = map[string]any{
				"default_local_cidr_any": tc.defaultLocalCIDRAny,
				"inbound": []any{
					map[string]any{"port": "any", "proto": "any", "host": "any"},
					map[string]any{"port": "22", "proto": "tcp", "host": "any"},
					map[string]any{"port": "80", "proto": "tcp", "host": "any", "local_cidr": "192.168.0.0/24"},
					map[string]any{"port": "443", "proto": "tcp", "host": "any", "local_cidr": "any"},
				},
			}
			rules, err := RulesFromConfig(test.NewLogger(), conf, vpnNetworks, tc.unsafeNetworks)
			require.NoError(t, err)

			// The proto `any` rule, as indexed by a protocol with rules of its own and as shared by one without.
			for _, proto := range []uint8{iputil.IPProtocolTCP, 47} {
				r := ruleOnPort(t, rules.In, proto, PortAny)
				assert.True(t, r.matchLocal(vpnAddr), "proto %d", proto)
				assert.Equal(t, tc.wantUnsafe, r.matchLocal(unsafeAddr), "proto %d", proto)
			}

			r := ruleOnPort(t, rules.In, iputil.IPProtocolTCP, 22)
			assert.True(t, r.matchLocal(vpnAddr))
			assert.Equal(t, tc.wantUnsafe, r.matchLocal(unsafeAddr))

			r = ruleOnPort(t, rules.In, iputil.IPProtocolTCP, 80)
			assert.False(t, r.matchLocal(vpnAddr))
			assert.True(t, r.matchLocal(unsafeAddr))

			r = ruleOnPort(t, rules.In, iputil.IPProtocolTCP, 443)
			assert.True(t, r.matchLocal(vpnAddr))
			assert.True(t, r.matchLocal(unsafeAddr))
		})
	}
}

func Test_convertRule(t *testing.T) {
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)

	// Ensure group array of 1 is converted and a warning is printed
	c := map[string]any{
		"group": []any{"group1"},
	}

	r, err := yamlToConfigRule(l, c, "test", 1)
	assert.Contains(t, ob.String(), "group was an array with a single value, converting to simple value")
	assert.Contains(t, ob.String(), "table=test")
	assert.Contains(t, ob.String(), "rule=1")
	require.NoError(t, err)
	assert.Equal(t, []string{"group1"}, r.Groups)

	// Ensure group array of > 1 is errord
	ob.Reset()
	c = map[string]any{
		"group": []any{"group1", "group2"},
	}

	r, err = yamlToConfigRule(l, c, "test", 1)
	assert.Empty(t, ob.String())
	require.Error(t, err, "group should contain a single value, an array with more than one entry was provided")

	// Make sure a well formed group is alright
	ob.Reset()
	c = map[string]any{
		"group": "group1",
	}

	r, err = yamlToConfigRule(l, c, "test", 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"group1"}, r.Groups)
}

func Test_convertRuleSanity(t *testing.T) {
	ob := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(ob)

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
		r, err := yamlToConfigRule(l, c, "test", 1)
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
		r, err := yamlToConfigRule(l, c, "test", 1)
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
		r, err := yamlToConfigRule(l, c, "test", 1)
		require.NoError(t, err)
		r.Groups = append(r.Groups, "any")
		err = r.sanity()
		require.Error(t, err, "I wanted a warning: %+v", c)
	}
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
