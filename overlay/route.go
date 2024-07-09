package overlay

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"runtime"
	"strconv"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

type Route struct {
	MTU     int
	Metric  int
	Cidr    netip.Prefix
	Via     netip.Addr
	Install bool
}

// Equal determines if a route that could be installed in the system route table is equal to another
// Via is ignored since that is only consumed within nebula itself
func (r Route) Equal(t Route) bool {
	if r.Cidr != t.Cidr {
		return false
	}
	if r.Metric != t.Metric {
		return false
	}
	if r.MTU != t.MTU {
		return false
	}
	if r.Install != t.Install {
		return false
	}
	return true
}

func (r Route) String() string {
	s := r.Cidr.String()
	if r.Metric != 0 {
		s += fmt.Sprintf(" metric: %v", r.Metric)
	}
	return s
}

func makeRouteTree(l *logrus.Logger, routes []Route, allowMTU bool) (*bart.Table[netip.Addr], error) {
	routeTree := new(bart.Table[netip.Addr])
	for _, r := range routes {
		if !allowMTU && r.MTU > 0 {
			l.WithField("route", r).Warnf("route MTU is not supported in %s", runtime.GOOS)
		}

		if r.Via.IsValid() {
			routeTree.Insert(r.Cidr, r.Via)
		}
	}
	return routeTree, nil
}

func parseRoutes(c *config.C, network netip.Prefix) ([]Route, error) {
	var err error

	r := c.Get("tun.routes")
	if r == nil {
		return []Route{}, nil
	}

	rawRoutes, ok := r.([]interface{})
	if !ok {
		return nil, fmt.Errorf("tun.routes is not an array")
	}

	if len(rawRoutes) < 1 {
		return []Route{}, nil
	}

	routes := make([]Route, len(rawRoutes))
	for i, r := range rawRoutes {
		m, ok := r.(map[interface{}]interface{})
		if !ok {
			return nil, fmt.Errorf("entry %v in tun.routes is invalid", i+1)
		}

		rMtu, ok := m["mtu"]
		if !ok {
			return nil, fmt.Errorf("entry %v.mtu in tun.routes is not present", i+1)
		}

		mtu, ok := rMtu.(int)
		if !ok {
			mtu, err = strconv.Atoi(rMtu.(string))
			if err != nil {
				return nil, fmt.Errorf("entry %v.mtu in tun.routes is not an integer: %v", i+1, err)
			}
		}

		if mtu < 500 {
			return nil, fmt.Errorf("entry %v.mtu in tun.routes is below 500: %v", i+1, mtu)
		}

		rRoute, ok := m["route"]
		if !ok {
			return nil, fmt.Errorf("entry %v.route in tun.routes is not present", i+1)
		}

		r := Route{
			Install: true,
			MTU:     mtu,
		}

		r.Cidr, err = netip.ParsePrefix(fmt.Sprintf("%v", rRoute))
		if err != nil {
			return nil, fmt.Errorf("entry %v.route in tun.routes failed to parse: %v", i+1, err)
		}

		if !network.Contains(r.Cidr.Addr()) || r.Cidr.Bits() < network.Bits() {
			return nil, fmt.Errorf(
				"entry %v.route in tun.routes is not contained within the network attached to the certificate; route: %v, network: %v",
				i+1,
				r.Cidr.String(),
				network.String(),
			)
		}

		routes[i] = r
	}

	return routes, nil
}

func parseUnsafeRoutes(c *config.C, network netip.Prefix) ([]Route, error) {
	var err error

	r := c.Get("tun.unsafe_routes")
	if r == nil {
		return []Route{}, nil
	}

	rawRoutes, ok := r.([]interface{})
	if !ok {
		return nil, fmt.Errorf("tun.unsafe_routes is not an array")
	}

	if len(rawRoutes) < 1 {
		return []Route{}, nil
	}

	routes := make([]Route, len(rawRoutes))
	for i, r := range rawRoutes {
		m, ok := r.(map[interface{}]interface{})
		if !ok {
			return nil, fmt.Errorf("entry %v in tun.unsafe_routes is invalid", i+1)
		}

		var mtu int
		if rMtu, ok := m["mtu"]; ok {
			mtu, ok = rMtu.(int)
			if !ok {
				mtu, err = strconv.Atoi(rMtu.(string))
				if err != nil {
					return nil, fmt.Errorf("entry %v.mtu in tun.unsafe_routes is not an integer: %v", i+1, err)
				}
			}

			if mtu != 0 && mtu < 500 {
				return nil, fmt.Errorf("entry %v.mtu in tun.unsafe_routes is below 500: %v", i+1, mtu)
			}
		}

		rMetric, ok := m["metric"]
		if !ok {
			rMetric = 0
		}

		metric, ok := rMetric.(int)
		if !ok {
			_, err = strconv.ParseInt(rMetric.(string), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("entry %v.metric in tun.unsafe_routes is not an integer: %v", i+1, err)
			}
		}

		if metric < 0 || metric > math.MaxInt32 {
			return nil, fmt.Errorf("entry %v.metric in tun.unsafe_routes is not in range (0-%d) : %v", i+1, math.MaxInt32, metric)
		}

		rVia, ok := m["via"]
		if !ok {
			return nil, fmt.Errorf("entry %v.via in tun.unsafe_routes is not present", i+1)
		}

		via, ok := rVia.(string)
		if !ok {
			return nil, fmt.Errorf("entry %v.via in tun.unsafe_routes is not a string: found %T", i+1, rVia)
		}

		viaVpnIp, err := netip.ParseAddr(via)
		if err != nil {
			return nil, fmt.Errorf("entry %v.via in tun.unsafe_routes failed to parse address: %v", i+1, err)
		}

		rRoute, ok := m["route"]
		if !ok {
			return nil, fmt.Errorf("entry %v.route in tun.unsafe_routes is not present", i+1)
		}

		install := true
		rInstall, ok := m["install"]
		if ok {
			install, err = strconv.ParseBool(fmt.Sprintf("%v", rInstall))
			if err != nil {
				return nil, fmt.Errorf("entry %v.install in tun.unsafe_routes is not a boolean: %v", i+1, err)
			}
		}

		r := Route{
			Via:     viaVpnIp,
			MTU:     mtu,
			Metric:  metric,
			Install: install,
		}

		r.Cidr, err = netip.ParsePrefix(fmt.Sprintf("%v", rRoute))
		if err != nil {
			return nil, fmt.Errorf("entry %v.route in tun.unsafe_routes failed to parse: %v", i+1, err)
		}

		if network.Contains(r.Cidr.Addr()) {
			return nil, fmt.Errorf(
				"entry %v.route in tun.unsafe_routes is contained within the network attached to the certificate; route: %v, network: %v",
				i+1,
				r.Cidr.String(),
				network.String(),
			)
		}

		routes[i] = r
	}

	return routes, nil
}

func ipWithin(o *net.IPNet, i *net.IPNet) bool {
	// Make sure o contains the lowest form of i
	if !o.Contains(i.IP.Mask(i.Mask)) {
		return false
	}

	// Find the max ip in i
	ip4 := i.IP.To4()
	if ip4 == nil {
		return false
	}

	last := make(net.IP, len(ip4))
	copy(last, ip4)
	for x := range ip4 {
		last[x] |= ^i.Mask[x]
	}

	// Make sure o contains the max
	if !o.Contains(last) {
		return false
	}

	return true
}
