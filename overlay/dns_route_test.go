package overlay

import (
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseUnsafeDnsRoutes(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	n, err := netip.ParsePrefix("10.0.0.0/24")
	require.NoError(t, err)

	// test no routes config
	routes, err := parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Empty(t, routes)

	// not an array
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": "hi"}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "tun.unsafe_dns_routes is not an array")

	// no routes
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Empty(t, routes)

	// weird route
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{"asdf"}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1 in tun.unsafe_dns_routes is invalid")

	// no via
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{map[string]any{"host": "example.com"}}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.via in tun.unsafe_dns_routes is not present")

	// no host
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{map[string]any{"via": "127.0.0.1"}}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.host in tun.unsafe_dns_routes is not present")

	// empty host
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{map[string]any{"via": "127.0.0.1", "host": ""}}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.host in tun.unsafe_dns_routes is empty")

	// host not a string
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{map[string]any{"via": "127.0.0.1", "host": 123}}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.host in tun.unsafe_dns_routes is not a string")

	// unparsable via
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{map[string]any{"host": "example.com", "mtu": "500", "via": "nope"}}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.via in tun.unsafe_dns_routes failed to parse address: ParseAddr(\"nope\"): unable to parse IP")

	// bad mtu
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{map[string]any{"host": "example.com", "via": "127.0.0.1", "mtu": "nope"}}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.mtu in tun.unsafe_dns_routes is not an integer: strconv.Atoi: parsing \"nope\": invalid syntax")

	// low mtu
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{map[string]any{"host": "example.com", "via": "127.0.0.1", "mtu": "499"}}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	assert.Nil(t, routes)
	require.EqualError(t, err, "entry 1.mtu in tun.unsafe_dns_routes is below 500: 499")

	// happy case - single gateway
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{
		map[string]any{"host": "example.com", "via": "127.0.0.1", "mtu": "9000"},
		map[string]any{"host": "test.org", "via": "127.0.0.2", "mtu": "8000", "metric": 100},
	}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Len(t, routes, 2)

	tested := 0
	for _, r := range routes {
		if r.Host == "example.com" {
			assert.Equal(t, 9000, r.MTU)
			assert.Equal(t, 0, r.Metric)
			assert.Len(t, r.Via, 1)
			tested++
		} else if r.Host == "test.org" {
			assert.Equal(t, 8000, r.MTU)
			assert.Equal(t, 100, r.Metric)
			assert.Len(t, r.Via, 1)
			tested++
		}
	}

	if tested != 2 {
		t.Fatal("Did not see all dns routes")
	}

	// happy case - multiple gateways
	c.Settings["tun"] = map[string]any{"unsafe_dns_routes": []any{
		map[string]any{
			"host": "example.com",
			"mtu":  "1500",
			"via": []any{
				map[string]any{"gateway": "10.0.0.1", "weight": 10},
				map[string]any{"gateway": "10.0.0.2", "weight": 5},
			},
		},
	}}
	routes, err = parseUnsafeDnsRoutes(c, []netip.Prefix{n})
	require.NoError(t, err)
	assert.Len(t, routes, 1)
	assert.Equal(t, "example.com", routes[0].Host)
	assert.Equal(t, 1500, routes[0].MTU)
	assert.Len(t, routes[0].Via, 2)
}
