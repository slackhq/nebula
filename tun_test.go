package nebula

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func Test_parseRoutes(t *testing.T) {
	c := NewConfig()
	_, n, _ := net.ParseCIDR("10.0.0.0/24")

	// test no routes config
	routes, err := parseRoutes(c, n)
	assert.Nil(t, err)
	assert.Len(t, routes, 0)

	// not an array
	c.Settings["tun"] = map[interface{}]interface{}{"routes": "hi"}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, routes)
	assert.EqualError(t, err, "tun.routes is not an array")

	// no routes
	c.Settings["tun"] = map[interface{}]interface{}{"routes": []interface{}{}}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, err)
	assert.Len(t, routes, 0)

	// weird route
	c.Settings["tun"] = map[interface{}]interface{}{"routes": []interface{}{"asdf"}}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, routes)
	assert.EqualError(t, err, "entry 1 in tun.routes is invalid")

	// no mtu
	c.Settings["tun"] = map[interface{}]interface{}{"routes": []interface{}{map[interface{}]interface{}{}}}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, routes)
	assert.EqualError(t, err, "entry 1.mtu in tun.routes is not present")

	// bad mtu
	c.Settings["tun"] = map[interface{}]interface{}{"routes": []interface{}{map[interface{}]interface{}{"mtu": "nope"}}}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, routes)
	assert.EqualError(t, err, "entry 1.mtu in tun.routes is not an integer: strconv.Atoi: parsing \"nope\": invalid syntax")

	// low mtu
	c.Settings["tun"] = map[interface{}]interface{}{"routes": []interface{}{map[interface{}]interface{}{"mtu": "499"}}}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, routes)
	assert.EqualError(t, err, "entry 1.mtu in tun.routes is below 500: 499")

	// missing route
	c.Settings["tun"] = map[interface{}]interface{}{"routes": []interface{}{map[interface{}]interface{}{"mtu": "500"}}}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, routes)
	assert.EqualError(t, err, "entry 1.route in tun.routes is not present")

	// unparsable route
	c.Settings["tun"] = map[interface{}]interface{}{"routes": []interface{}{map[interface{}]interface{}{"mtu": "500", "route": "nope"}}}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, routes)
	assert.EqualError(t, err, "entry 1.route in tun.routes failed to parse: invalid CIDR address: nope")

	// below network range
	c.Settings["tun"] = map[interface{}]interface{}{"routes": []interface{}{map[interface{}]interface{}{"mtu": "500", "route": "1.0.0.0/8"}}}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, routes)
	assert.EqualError(t, err, "entry 1.route in tun.routes is not contained within the network attached to the certificate; route: 1.0.0.0/8, network: 10.0.0.0/24")

	// above network range
	c.Settings["tun"] = map[interface{}]interface{}{"routes": []interface{}{map[interface{}]interface{}{"mtu": "500", "route": "10.0.1.0/24"}}}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, routes)
	assert.EqualError(t, err, "entry 1.route in tun.routes is not contained within the network attached to the certificate; route: 10.0.1.0/24, network: 10.0.0.0/24")

	// happy case
	c.Settings["tun"] = map[interface{}]interface{}{"routes": []interface{}{
		map[interface{}]interface{}{"mtu": "9000", "route": "10.0.0.0/29"},
		map[interface{}]interface{}{"mtu": "8000", "route": "10.0.0.1/32"},
	}}
	routes, err = parseRoutes(c, n)
	assert.Nil(t, err)
	assert.Len(t, routes, 2)

	tested := 0
	for _, r := range routes {
		if r.mtu == 8000 {
			assert.Equal(t, "10.0.0.1/32", r.route.String())
			tested++
		} else {
			assert.Equal(t, 9000, r.mtu)
			assert.Equal(t, "10.0.0.0/29", r.route.String())
			tested++
		}
	}

	if tested != 2 {
		t.Fatal("Did not see both routes")
	}
}
