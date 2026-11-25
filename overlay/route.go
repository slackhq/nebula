package overlay

import (
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
)

const mainRouteTable = 254

type Route struct {
	MTU      int
	Metric   int
	Cidr     netip.Prefix
	Source   *netip.Prefix
	Table    int
	Priority int
	Via      routing.Gateways
	Install  bool
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
	if r.Source == nil != (t.Source == nil) || (r.Source != nil && *r.Source != *t.Source) {
		return false
	}
	if r.Table != t.Table || r.Priority != t.Priority {
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

func makeRouteTree(l *slog.Logger, routes []Route, allowMTU bool) (*bart.Table[routing.Gateways], error) {
	routeTree := new(bart.Table[routing.Gateways])
	seen := make(map[netip.Prefix]bool, len(routes))
	for _, r := range routes {
		if seen[r.Cidr] {
			l.Warn("route is listed more than once, only the last entry's via is used", "route", r)
		}
		seen[r.Cidr] = true

		if !allowMTU && r.MTU > 0 {
			l.Warn("route MTU is not supported on this platform",
				"goos", runtime.GOOS,
				"route", r,
			)
		}

		gateways := r.Via
		if len(gateways) > 0 {
			routing.CalculateBucketsForGateways(gateways)
			routeTree.Insert(r.Cidr, gateways)
		}
	}
	return routeTree, nil
}

func parseRoutes(c *config.C, networks []netip.Prefix) ([]Route, error) {
	var err error

	r := c.Get("tun.routes")
	if r == nil {
		return []Route{}, nil
	}

	rawRoutes, ok := r.([]any)
	if !ok {
		return nil, fmt.Errorf("tun.routes is not an array")
	}

	if len(rawRoutes) < 1 {
		return []Route{}, nil
	}

	routes := make([]Route, len(rawRoutes))
	for i, r := range rawRoutes {
		m, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("entry %v in tun.routes is invalid", i+1)
		}

		rMtu, ok := m["mtu"]
		if !ok {
			return nil, fmt.Errorf("entry %v.mtu in tun.routes is not present", i+1)
		}

		mtu, ok := rMtu.(int)
		if !ok {
			s, ok := rMtu.(string)
			if !ok {
				return nil, fmt.Errorf("entry %v.mtu in tun.routes is not an integer: %v", i+1, rMtu)
			}
			mtu, err = strconv.Atoi(s)
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
			Table:   mainRouteTable,
		}

		r.Cidr, err = netip.ParsePrefix(fmt.Sprintf("%v", rRoute))
		if err != nil {
			return nil, fmt.Errorf("entry %v.route in tun.routes failed to parse: %v", i+1, err)
		}

		found := false
		for _, network := range networks {
			if network.Contains(r.Cidr.Addr()) && r.Cidr.Bits() >= network.Bits() {
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf(
				"entry %v.route in tun.routes is not contained within the configured vpn networks; route: %v, networks: %v",
				i+1,
				r.Cidr.String(),
				networks,
			)
		}

		routes[i] = r
	}

	return routes, nil
}

func parseUnsafeRoutes(c *config.C, networks []netip.Prefix) ([]Route, error) {
	var err error

	r := c.Get("tun.unsafe_routes")
	if r == nil {
		return []Route{}, nil
	}

	rawRoutes, ok := r.([]any)
	if !ok {
		return nil, fmt.Errorf("tun.unsafe_routes is not an array")
	}

	if len(rawRoutes) < 1 {
		return []Route{}, nil
	}

	routes := make([]Route, len(rawRoutes))
	for i, r := range rawRoutes {
		m, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("entry %v in tun.unsafe_routes is invalid", i+1)
		}
		if runtime.GOOS != "linux" {
			for _, field := range []string{"table", "source", "priority"} {
				if _, ok := m[field]; ok {
					return nil, fmt.Errorf("entry %v.%s in tun.unsafe_routes is only supported on Linux", i+1, field)
				}
			}
		}

		var mtu int
		if rMtu, ok := m["mtu"]; ok {
			mtu, ok = rMtu.(int)
			if !ok {
				s, ok := rMtu.(string)
				if !ok {
					return nil, fmt.Errorf("entry %v.mtu in tun.unsafe_routes is not an integer: %v", i+1, rMtu)
				}
				mtu, err = strconv.Atoi(s)
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

		metric, err := parseRouteInt(rMetric, "metric", i+1)
		if err != nil {
			return nil, err
		}

		if metric < 0 || metric > math.MaxInt32 {
			return nil, fmt.Errorf("entry %v.metric in tun.unsafe_routes is not in range (0-%d) : %v", i+1, math.MaxInt32, metric)
		}

		rVia, ok := m["via"]
		if !ok {
			return nil, fmt.Errorf("entry %v.via in tun.unsafe_routes is not present", i+1)
		}

		var gateways routing.Gateways

		switch via := rVia.(type) {
		case string:
			viaIp, err := netip.ParseAddr(via)
			if err != nil {
				return nil, fmt.Errorf("entry %v.via in tun.unsafe_routes failed to parse address: %v", i+1, err)
			}

			gateways = routing.Gateways{routing.NewGateway(viaIp, 1)}

		case []any:
			gateways = make(routing.Gateways, len(via))
			for ig, v := range via {
				gatewayMap, ok := v.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("entry %v in tun.unsafe_routes[%v].via is invalid", i+1, ig+1)
				}

				rGateway, ok := gatewayMap["gateway"]
				if !ok {
					return nil, fmt.Errorf("entry .gateway in tun.unsafe_routes[%v].via[%v] is not present", i+1, ig+1)
				}

				parsedGateway, ok := rGateway.(string)
				if !ok {
					return nil, fmt.Errorf("entry .gateway in tun.unsafe_routes[%v].via[%v] is not a string", i+1, ig+1)
				}

				gatewayIp, err := netip.ParseAddr(parsedGateway)
				if err != nil {
					return nil, fmt.Errorf("entry .gateway in tun.unsafe_routes[%v].via[%v] failed to parse address: %v", i+1, ig+1, err)
				}

				rGatewayWeight, ok := gatewayMap["weight"]
				if !ok {
					rGatewayWeight = 1
				}

				gatewayWeight, ok := rGatewayWeight.(int)
				if !ok {
					s, ok := rGatewayWeight.(string)
					if !ok {
						return nil, fmt.Errorf("entry .weight in tun.unsafe_routes[%v].via[%v] is not an integer", i+1, ig+1)
					}
					w, err := strconv.ParseInt(s, 10, 32)
					if err != nil {
						return nil, fmt.Errorf("entry .weight in tun.unsafe_routes[%v].via[%v] is not an integer", i+1, ig+1)
					}
					gatewayWeight = int(w)
				}

				if gatewayWeight < 1 || gatewayWeight > math.MaxInt32 {
					return nil, fmt.Errorf("entry .weight in tun.unsafe_routes[%v].via[%v] is not in range (1-%d) : %v", i+1, ig+1, math.MaxInt32, gatewayWeight)
				}

				gateways[ig] = routing.NewGateway(gatewayIp, gatewayWeight)

			}

		default:
			return nil, fmt.Errorf("entry %v.via in tun.unsafe_routes is not a string or list of gateways: found %T", i+1, rVia)
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
			Via:     gateways,
			MTU:     mtu,
			Metric:  metric,
			Install: install,
			Table:   mainRouteTable,
		}

		if rTable, ok := m["table"]; ok {
			r.Table, err = parseRouteInt(rTable, "table", i+1)
			if err != nil {
				return nil, err
			}
			if r.Table < 1 || r.Table > math.MaxInt32 {
				return nil, fmt.Errorf("entry %v.table in tun.unsafe_routes is not in range (1-%d): %v", i+1, math.MaxInt32, r.Table)
			}
			if r.Table == 253 || r.Table == 255 {
				return nil, fmt.Errorf("entry %v.table in tun.unsafe_routes uses a reserved routing table: %v", i+1, r.Table)
			}
		}

		if rSource, ok := m["source"]; ok {
			source, parseErr := netip.ParsePrefix(fmt.Sprintf("%v", rSource))
			if parseErr != nil {
				return nil, fmt.Errorf("entry %v.source in tun.unsafe_routes failed to parse: %v", i+1, parseErr)
			}
			r.Source = &source
		}

		if rPriority, ok := m["priority"]; ok {
			r.Priority, err = parseRouteInt(rPriority, "priority", i+1)
			if err != nil {
				return nil, err
			}
			if r.Priority < 1 || r.Priority > math.MaxInt32 {
				return nil, fmt.Errorf("entry %v.priority in tun.unsafe_routes is not in range (1-%d): %v", i+1, math.MaxInt32, r.Priority)
			}
		} else if r.Source != nil {
			r.Priority = 10000
		}
		if r.Source == nil && r.Table != mainRouteTable {
			return nil, fmt.Errorf("entry %v.table requires entry %v.source in tun.unsafe_routes", i+1, i+1)
		}
		if r.Source != nil && r.Table == mainRouteTable {
			return nil, fmt.Errorf("entry %v.source requires a non-main table in tun.unsafe_routes", i+1)
		}

		r.Cidr, err = netip.ParsePrefix(fmt.Sprintf("%v", rRoute))
		if err != nil {
			return nil, fmt.Errorf("entry %v.route in tun.unsafe_routes failed to parse: %v", i+1, err)
		}
		if r.Source != nil && r.Source.Addr().Is4() != r.Cidr.Addr().Is4() {
			return nil, fmt.Errorf("entry %v.source and entry %v.route in tun.unsafe_routes must use the same IP family", i+1, i+1)
		}

		for _, network := range networks {
			if network.Contains(r.Cidr.Addr()) {
				return nil, fmt.Errorf(
					"entry %v.route in tun.unsafe_routes is contained within the configured vpn networks; route: %v, network: %v",
					i+1,
					r.Cidr.String(),
					network.String(),
				)
			}
		}

		// Nebula selects gateways by destination only, not by source or table.
		for j, previous := range routes[:i] {
			if previous.Cidr.Overlaps(r.Cidr) && (previous.Source != nil || r.Source != nil) && !slices.Equal(previous.Via, r.Via) {
				return nil, fmt.Errorf("entries %v and %v in tun.unsafe_routes have conflicting gateways for policy route %v", j+1, i+1, r.Cidr.Masked())
			}
		}
		routes[i] = r
	}

	return routes, nil
}

func parseRouteInt(value any, field string, entry int) (int, error) {
	if n, ok := value.(int); ok {
		return n, nil
	}
	s, ok := value.(string)
	if !ok {
		return 0, fmt.Errorf("entry %v.%s in tun.unsafe_routes is not an integer: %v", entry, field, value)
	}
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("entry %v.%s in tun.unsafe_routes is not an integer: %v", entry, field, err)
	}
	return int(n), nil
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
