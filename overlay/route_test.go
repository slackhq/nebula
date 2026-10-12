package overlay

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseRoutes(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	n, err := netip.ParsePrefix("10.0.0.0/24")
	require.NoError(t, err)

	// test no routes config
	routes, err := parseRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Empty(t, routes)

	// not an array
	c.Settings["tun"] = map[string]any{"routes": "hi"}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "tun.routes is not an array")

	// no routes
	c.Settings["tun"] = map[string]any{"routes": []any{}}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Empty(t, routes)

	// weird route
	c.Settings["tun"] = map[string]any{"routes": []any{"asdf"}}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1 in tun.routes is invalid")

	// no mtu
	c.Settings["tun"] = map[string]any{"routes": []any{map[string]any{}}}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.mtu in tun.routes is not present")

	// bad mtu
	c.Settings["tun"] = map[string]any{"routes": []any{map[string]any{"mtu": "nope"}}}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.mtu in tun.routes is not an integer: strconv.Atoi: parsing \"nope\": invalid syntax")

	// low mtu
	c.Settings["tun"] = map[string]any{"routes": []any{map[string]any{"mtu": "499"}}}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.mtu in tun.routes is below 500: 499")

	// missing route
	c.Settings["tun"] = map[string]any{"routes": []any{map[string]any{"mtu": "500"}}}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.route in tun.routes is not present")

	// unparsable route
	c.Settings["tun"] = map[string]any{"routes": []any{map[string]any{"mtu": "500", "route": "nope"}}}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.route in tun.routes failed to parse: netip.ParsePrefix(\"nope\"): no '/'")

	// below network range
	c.Settings["tun"] = map[string]any{"routes": []any{map[string]any{"mtu": "500", "route": "1.0.0.0/8"}}}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.route in tun.routes is not contained within the configured vpn networks; route: 1.0.0.0/8, networks: [10.0.0.0/24]")

	// above network range
	c.Settings["tun"] = map[string]any{"routes": []any{map[string]any{"mtu": "500", "route": "10.0.1.0/24"}}}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.route in tun.routes is not contained within the configured vpn networks; route: 10.0.1.0/24, networks: [10.0.0.0/24]")

	// Not in multiple ranges
	c.Settings["tun"] = map[string]any{"routes": []any{map[string]any{"mtu": "500", "route": "192.0.0.0/24"}}}
	routes, err = parseRoutes(c, []netip.Prefix{n, netip.MustParsePrefix("192.1.0.0/24")})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.route in tun.routes is not contained within the configured vpn networks; route: 192.0.0.0/24, networks: [10.0.0.0/24 192.1.0.0/24]")

	// happy case
	c.Settings["tun"] = map[string]any{"routes": []any{
		map[string]any{"mtu": "9000", "route": "10.0.0.0/29"},
		map[string]any{"mtu": "8000", "route": "10.0.0.1/32"},
	}}
	routes, err = parseRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Len(t, routes, 2)

	tested := 0
	for _, r := range routes {
		assert.True(t, r.Install)

		if r.MTU == 8000 {
			assert.Equal(t, "10.0.0.1/32", r.Cidr.String())
			tested++
		} else {
			assert.Equal(t, 9000, r.MTU)
			assert.Equal(t, "10.0.0.0/29", r.Cidr.String())
			tested++
		}
	}

	if tested != 2 {
		t.Fatal("Did not see both routes")
	}
}

func Test_parseUnsafeRoutes(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	n, err := netip.ParsePrefix("10.0.0.0/24")
	require.NoError(t, err)

	// test no routes config
	routes, err := parseUnsafeRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Empty(t, routes)

	// not an array
	c.Settings["tun"] = map[string]any{"unsafe_routes": "hi"}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "tun.unsafe_routes is not an array")

	// no routes
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Empty(t, routes)

	// weird route
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{"asdf"}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1 in tun.unsafe_routes is invalid")

	// no via
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.via in tun.unsafe_routes is not present")

	// invalid via
	for _, invalidValue := range []any{
		127, false, nil, 1.0, []string{"1", "2"},
	} {
		c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": invalidValue}}}
		routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
		assert.Nil(t, routes)
		require.EqualError(t, err, fmt.Sprintf("entry 1.via in tun.unsafe_routes is not a string or list of gateways: found %T", invalidValue))
	}

	// Unparsable list of via
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": []string{"1", "2"}}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.via in tun.unsafe_routes is not a string or list of gateways: found []string")

	// unparsable via
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"mtu": "500", "via": "nope"}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.via in tun.unsafe_routes failed to parse address: ParseAddr(\"nope\"): unable to parse IP")

	// unparsable gateway
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"mtu": "500", "via": []any{map[string]any{"gateway": "1"}}}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry .gateway in tun.unsafe_routes[1].via[1] failed to parse address: ParseAddr(\"1\"): unable to parse IP")

	// missing gateway element
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"mtu": "500", "via": []any{map[string]any{"weight": "1"}}}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry .gateway in tun.unsafe_routes[1].via[1] is not present")

	// unparsable weight element
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"mtu": "500", "via": []any{map[string]any{"gateway": "10.0.0.1", "weight": "a"}}}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry .weight in tun.unsafe_routes[1].via[1] is not an integer")

	// missing route
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": "127.0.0.1", "mtu": "500"}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.route in tun.unsafe_routes is not present")

	// unparsable route
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": "127.0.0.1", "mtu": "500", "route": "nope"}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.route in tun.unsafe_routes failed to parse: netip.ParsePrefix(\"nope\"): no '/'")

	// within network range
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": "127.0.0.1", "route": "10.0.0.0/24"}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.route in tun.unsafe_routes is contained within the configured vpn networks; route: 10.0.0.0/24, network: 10.0.0.0/24")

	// below network range
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": "127.0.0.1", "route": "1.0.0.0/8"}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Len(t, routes, 1)
	require.NoError(t, err)

	// above network range
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": "127.0.0.1", "route": "10.0.1.0/24"}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Len(t, routes, 1)
	require.NoError(t, err)

	// no mtu
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": "127.0.0.1", "route": "1.0.0.0/8"}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Len(t, routes, 1)
	assert.Equal(t, 0, routes[0].MTU)

	// bad mtu
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": "127.0.0.1", "mtu": "nope"}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.mtu in tun.unsafe_routes is not an integer: strconv.Atoi: parsing \"nope\": invalid syntax")

	// low mtu
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": "127.0.0.1", "mtu": "499"}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.mtu in tun.unsafe_routes is below 500: 499")

	// bad install
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"via": "127.0.0.1", "mtu": "9000", "route": "1.0.0.0/29", "install": "nope"}}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.install in tun.unsafe_routes is not a boolean: strconv.ParseBool: parsing \"nope\": invalid syntax")

	// happy case
	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{
		map[string]any{"via": "127.0.0.1", "mtu": "9000", "route": "1.0.0.0/29", "install": "t"},
		map[string]any{"via": "127.0.0.1", "mtu": "8000", "route": "1.0.0.1/32", "install": 0},
		map[string]any{"via": "127.0.0.1", "mtu": "1500", "metric": 1234, "route": "1.0.0.2/32", "install": 1},
		map[string]any{"via": "127.0.0.1", "mtu": "1500", "metric": 1234, "route": "1.0.0.2/32"},
	}}
	routes, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Len(t, routes, 4)

	tested := 0
	for _, r := range routes {
		if r.MTU == 8000 {
			assert.Equal(t, "1.0.0.1/32", r.Cidr.String())
			assert.False(t, r.Install)
			tested++
		} else if r.MTU == 9000 {
			assert.Equal(t, 9000, r.MTU)
			assert.Equal(t, "1.0.0.0/29", r.Cidr.String())
			assert.True(t, r.Install)
			tested++
		} else {
			assert.Equal(t, 1500, r.MTU)
			assert.Equal(t, 1234, r.Metric)
			assert.Equal(t, "1.0.0.2/32", r.Cidr.String())
			assert.True(t, r.Install)
			tested++
		}
	}

	if tested != 4 {
		t.Fatal("Did not see all unsafe_routes")
	}
}

func Test_makeRouteTree(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	n, err := netip.ParsePrefix("10.0.0.0/24")
	require.NoError(t, err)

	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{
		map[string]any{"via": "192.168.0.1", "route": "1.0.0.0/28"},
		map[string]any{"via": "192.168.0.2", "route": "1.0.0.1/32"},
	}}
	routes, err := parseUnsafeRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Len(t, routes, 2)
	routeTree, err := makeRouteTree(test.NewLogger(), routes, true)
	require.NoError(t, err)

	ip, err := netip.ParseAddr("1.0.0.2")
	require.NoError(t, err)
	r, ok := routeTree.Lookup(ip)
	assert.True(t, ok)

	nip, err := netip.ParseAddr("192.168.0.1")
	require.NoError(t, err)
	assert.Equal(t, nip, r[0].Addr())

	ip, err = netip.ParseAddr("1.0.0.1")
	require.NoError(t, err)
	r, ok = routeTree.Lookup(ip)
	assert.True(t, ok)

	nip, err = netip.ParseAddr("192.168.0.2")
	require.NoError(t, err)
	assert.Equal(t, nip, r[0].Addr())

	ip, err = netip.ParseAddr("1.1.0.1")
	require.NoError(t, err)
	r, ok = routeTree.Lookup(ip)
	assert.False(t, ok)
}

func Test_makeMultipathUnsafeRouteTree(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	n, err := netip.ParsePrefix("10.0.0.0/24")
	require.NoError(t, err)

	c.Settings["tun"] = map[string]any{
		"unsafe_routes": []any{
			map[string]any{
				"route": "192.168.86.0/24",
				"via":   "192.168.100.10",
			},
			map[string]any{
				"route": "192.168.87.0/24",
				"via": []any{
					map[string]any{
						"gateway": "10.0.0.1",
					},
					map[string]any{
						"gateway": "10.0.0.2",
					},
					map[string]any{
						"gateway": "10.0.0.3",
					},
				},
			},
			map[string]any{
				"route": "192.168.89.0/24",
				"via": []any{
					map[string]any{
						"gateway": "10.0.0.1",
						"weight":  10,
					},
					map[string]any{
						"gateway": "10.0.0.2",
						"weight":  5,
					},
				},
			},
		},
	}

	routes, err := parseUnsafeRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Len(t, routes, 3)
	routeTree, err := makeRouteTree(test.NewLogger(), routes, true)
	require.NoError(t, err)

	ip, err := netip.ParseAddr("192.168.86.1")
	require.NoError(t, err)
	r, ok := routeTree.Lookup(ip)
	assert.True(t, ok)

	nip, err := netip.ParseAddr("192.168.100.10")
	require.NoError(t, err)
	assert.Equal(t, nip, r[0].Addr())

	ip, err = netip.ParseAddr("192.168.87.1")
	require.NoError(t, err)
	r, ok = routeTree.Lookup(ip)
	assert.True(t, ok)

	expectedGateways := routing.Gateways{routing.NewGateway(netip.MustParseAddr("10.0.0.1"), 1),
		routing.NewGateway(netip.MustParseAddr("10.0.0.2"), 1),
		routing.NewGateway(netip.MustParseAddr("10.0.0.3"), 1)}

	routing.CalculateBucketsForGateways(expectedGateways)
	assert.ElementsMatch(t, expectedGateways, r)

	ip, err = netip.ParseAddr("192.168.89.1")
	require.NoError(t, err)
	r, ok = routeTree.Lookup(ip)
	assert.True(t, ok)

	expectedGateways = routing.Gateways{routing.NewGateway(netip.MustParseAddr("10.0.0.1"), 10),
		routing.NewGateway(netip.MustParseAddr("10.0.0.2"), 5)}

	routing.CalculateBucketsForGateways(expectedGateways)
	assert.ElementsMatch(t, expectedGateways, r)
}

func Test_getMTU(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)

	// unset
	assert.Equal(t, DefaultMTU, getMTU(l, c))

	// the largest a relayed packet can carry in one underlay buffer
	require.Equal(t, udp.MTU, MaxMTU+header.MaxOverhead)
	c.Settings["tun"] = map[string]any{"mtu": MaxMTU}
	assert.Equal(t, MaxMTU, getMTU(l, c))

	// too big is capped
	c.Settings["tun"] = map[string]any{"mtu": 9000}
	assert.Equal(t, MaxMTU, getMTU(l, c))
}

func Test_getAllRoutesFromConfigCapsMTU(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	c.Settings["tun"] = map[string]any{
		"routes": []any{
			map[string]any{"mtu": "9000", "route": "10.0.0.0/29"},
			map[string]any{"mtu": "1300", "route": "10.0.0.8/29"},
		},
		"unsafe_routes": []any{
			map[string]any{"via": "127.0.0.1", "mtu": "9000", "route": "1.0.0.0/29"},
		},
	}

	changed, routes, err := getAllRoutesFromConfig(l, c, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, true)
	require.NoError(t, err)
	assert.True(t, changed)

	mtus := map[string]int{}
	for _, r := range routes {
		mtus[r.Cidr.String()] = r.MTU
	}
	assert.Equal(t, map[string]int{"10.0.0.0/29": MaxMTU, "10.0.0.8/29": 1300, "1.0.0.0/29": MaxMTU}, mtus)
}

// The route tree keeps one entry per CIDR, so a CIDR listed twice only routes by the last one. Say so instead of
// letting the earlier via, or on Windows the earlier metric, quietly lose
func Test_makeRouteTree_WarnsOnDuplicate(t *testing.T) {
	buf := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(buf)
	via := func(s string) routing.Gateways {
		return routing.Gateways{routing.NewGateway(netip.MustParseAddr(s), 1)}
	}
	cidr := netip.MustParsePrefix("10.251.1.0/24")

	_, err := makeRouteTree(l, []Route{
		{Cidr: cidr, Via: via("10.250.0.2"), Install: true, Metric: 100},
		{Cidr: netip.MustParsePrefix("10.251.2.0/24"), Via: via("10.250.0.2"), Install: true},
	}, false)
	require.NoError(t, err)
	assert.Empty(t, buf.String())

	tree, err := makeRouteTree(l, []Route{
		{Cidr: cidr, Via: via("10.250.0.2"), Install: true, Metric: 100},
		{Cidr: cidr, Via: via("10.250.0.3"), Install: true, Metric: 200},
	}, false)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(buf.String(), "route is listed more than once, only the last entry's via is used"))
	gw, ok := tree.Lookup(netip.MustParseAddr("10.251.1.1"))
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("10.250.0.3"), gw[0].Addr(), "the last entry wins")
}

// A quoted metric or weight is a number written as a string, it means that number. Anything else is an error, not a
// panic
func Test_parseUnsafeRoutes_QuotedNumbers(t *testing.T) {
	c := config.NewC(test.NewLogger())
	n := netip.MustParsePrefix("10.0.0.1/24")
	route := func(metric, weight any) {
		c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{
			"route":  "1.0.0.0/8",
			"metric": metric,
			"via":    []any{map[string]any{"gateway": "10.0.0.2", "weight": weight}},
		}}}
	}

	route("100", "5")
	routes, err := parseUnsafeRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	require.Len(t, routes, 1)
	assert.Equal(t, 100, routes[0].Metric)
	assert.Equal(t, "{addr: 10.0.0.2, weight: 5}", routes[0].Via[0].String())

	route(1.5, 1)
	_, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	require.EqualError(t, err, "entry 1.metric in tun.unsafe_routes is not an integer: 1.5")

	route(1, true)
	_, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	require.EqualError(t, err, "entry .weight in tun.unsafe_routes[1].via[1] is not an integer")
}

// An mtu that is neither a number nor a quoted one is an error, not a panic
func Test_parseRoutes_MTUNotANumber(t *testing.T) {
	c := config.NewC(test.NewLogger())
	n := netip.MustParsePrefix("10.0.0.1/24")

	c.Settings["tun"] = map[string]any{"routes": []any{map[string]any{"route": "1.0.0.0/8", "mtu": 1500.5}}}
	_, err := parseRoutes(c, []netip.Prefix{n})
	require.EqualError(t, err, "entry 1.mtu in tun.routes is not an integer: 1500.5")

	c.Settings["tun"] = map[string]any{"unsafe_routes": []any{map[string]any{"route": "1.0.0.0/8", "via": "10.0.0.2", "mtu": 1500.5}}}
	_, err = parseUnsafeRoutes(c, []netip.Prefix{n})
	require.EqualError(t, err, "entry 1.mtu in tun.unsafe_routes is not an integer: 1500.5")
}
