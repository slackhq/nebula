package overlay

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
)

const DefaultMTU = 1300

// TODO: We may be able to remove routines
type DeviceFactory func(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, routines int) (Device, error)

func NewDeviceFromConfig(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, routines int) (Device, error) {
	switch {
	case c.GetBool("tun.disabled", false):
		tun := newDisabledTun(vpnNetworks, c.GetInt("tun.tx_queue", 500), c.GetBool("stats.message_metrics", false), l)
		return tun, nil

	default:
		return newTun(c, l, vpnNetworks, routines > 1)
	}
}

func NewFdDeviceFromConfig(fd *int) DeviceFactory {
	return func(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, routines int) (Device, error) {
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
	for i := 0; i < len(b); i++ {
		b[i] ^= 0xFF
	}
	return b
}
func orBytes(a []byte, b []byte) []byte {
	ret := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
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
