package overlay

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/slackhq/nebula/util"
)

const DefaultMTU = 1300

// MaxMTU is the largest tun.mtu, or route mtu, the underlay can carry.
// Every underlay buffer is udp.MTU bytes, and a relayed packet adds header.MaxOverhead to its plaintext.
const MaxMTU = udp.MTU - header.MaxOverhead

// getMTU reads tun.mtu, capping a value too big for the underlay to carry.
func getMTU(c *config.C) int {
	mtu := c.GetInt("tun.mtu", DefaultMTU)
	if mtu > MaxMTU {
		c.Logger().Warn("tun.mtu is too big for the underlay to carry, capping it", "mtu", mtu, "maxMTU", MaxMTU)
		return MaxMTU
	}
	return mtu
}

type NameError struct {
	Name       string
	Underlying error
}

func (e *NameError) Error() string {
	return fmt.Sprintf("could not set tun device name: %s because %s", e.Name, e.Underlying)
}

// TODO: We may be able to remove routines
type DeviceFactory func(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, routines int) (Device, error)

func NewDeviceFromConfig(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, routines int) (Device, error) {
	switch {
	case c.GetBool("tun.disabled", false):
		tun := newDisabledTun(vpnNetworks, c.GetInt("tun.tx_queue", 500), c.GetBool("stats.message_metrics", false), l)
		return tun, nil

	default:
		return newTun(c, l, vpnNetworks, routines > 1)
	}
}

func NewFdDeviceFromConfig(fd *int) DeviceFactory {
	return func(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, routines int) (Device, error) {
		return newTunFromFd(c, l, *fd, vpnNetworks)
	}
}

func getAllRoutesFromConfig(c *config.C, vpnNetworks []netip.Prefix, initial bool) (bool, []Route, error) {
	if !initial && !c.HasChanged("tun.routes") && !c.HasChanged("tun.unsafe_routes") {
		return false, nil, nil
	}

	routes, err := parseRoutes(c, vpnNetworks)
	if err != nil {
		return true, nil, util.NewContextualError("Could not parse tun.routes", nil, err)
	}

	unsafeRoutes, err := parseUnsafeRoutes(c, vpnNetworks)
	if err != nil {
		return true, nil, util.NewContextualError("Could not parse tun.unsafe_routes", nil, err)
	}

	routes = append(routes, unsafeRoutes...)
	for i, r := range routes {
		if r.MTU > MaxMTU {
			c.Logger().Warn("route mtu is too big for the underlay to carry, capping it", "route", r.Cidr, "mtu", r.MTU, "maxMTU", MaxMTU)
			routes[i].MTU = MaxMTU
		}
	}
	return true, routes, nil
}

// findRemovedRoutes will return all routes that are not present in the newRoutes list and would affect the system route table.
// Via is not used to evaluate since it does not affect the system route table.
func findRemovedRoutes(newRoutes, oldRoutes []Route) []Route {
	var removed []Route
	has := func(entry Route) bool {
		for _, check := range newRoutes {
			if check.Equal(entry) {
				return true
			}
		}
		return false
	}

	for _, oldEntry := range oldRoutes {
		if !has(oldEntry) {
			removed = append(removed, oldEntry)
		}
	}

	return removed
}

func prefixToMask(prefix netip.Prefix) netip.Addr {
	pLen := 128
	if prefix.Addr().Is4() {
		pLen = 32
	}

	addr, _ := netip.AddrFromSlice(net.CIDRMask(prefix.Bits(), pLen))
	return addr
}

func flipBytes(b []byte) []byte {
	for i := range b {
		b[i] ^= 0xFF
	}
	return b
}
func orBytes(a []byte, b []byte) []byte {
	ret := make([]byte, len(a))
	for i := range a {
		ret[i] = a[i] | b[i]
	}
	return ret
}

func getBroadcast(cidr netip.Prefix) netip.Addr {
	broadcast, _ := netip.AddrFromSlice(
		orBytes(
			cidr.Addr().AsSlice(),
			flipBytes(prefixToMask(cidr).AsSlice()),
		),
	)
	return broadcast
}

func selectGateway(dest netip.Prefix, gateways []netip.Prefix) (netip.Prefix, error) {
	for _, gateway := range gateways {
		if dest.Addr().Is4() && gateway.Addr().Is4() {
			return gateway, nil
		}

		if dest.Addr().Is6() && gateway.Addr().Is6() {
			return gateway, nil
		}
	}

	return netip.Prefix{}, fmt.Errorf("no gateway found for %v in the list of vpn networks", dest)
}
