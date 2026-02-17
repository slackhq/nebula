package overlay

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
)

const DefaultMTU = 1300

type NameError struct {
	Name       string
	Underlying error
}

func (e *NameError) Error() string {
	return fmt.Sprintf("could not set tun device name: %s because %s", e.Name, e.Underlying)
}

// TODO: We may be able to remove routines
type DeviceFactory func(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, unsafeNetworks []netip.Prefix, routines int) (Device, error)

func NewDeviceFromConfig(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, unsafeNetworks []netip.Prefix, routines int) (Device, error) {
	switch {
	case c.GetBool("tun.disabled", false):
		tun := newDisabledTun(vpnNetworks, c.GetInt("tun.tx_queue", 500), c.GetBool("stats.message_metrics", false), l)
		return tun, nil

	default:
		return newTun(c, l, vpnNetworks, unsafeNetworks, routines > 1)
	}
}

func NewFdDeviceFromConfig(fd *int) DeviceFactory {
	return func(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, unsafeNetworks []netip.Prefix, routines int) (Device, error) {
		return newTunFromFd(c, l, *fd, vpnNetworks, unsafeNetworks)
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

func prepareSnatAddr(d Device, l *logrus.Logger, c *config.C, routes []Route) netip.Prefix {
	if !d.Networks()[0].Addr().Is6() {
		return netip.Prefix{} //if we have an IPv4 assignment within the overlay, we don't need a snat address
	}

	addSnatAddr := false
	for _, un := range d.UnsafeNetworks() { //if we are an unsafe router for an IPv4 range
		if un.Addr().Is4() {
			addSnatAddr = true
			break
		}
	}
	for _, route := range routes { //or if we have a route defined into an IPv4 range
		if route.Cidr.Addr().Is4() {
			addSnatAddr = true //todo should this only apply to unsafe routes?
			break
		}
	}
	if !addSnatAddr {
		return netip.Prefix{}
	}

	var err error
	out := netip.Addr{}
	if a := c.GetString("tun.snat_address_for_4over6", ""); a != "" {
		out, err = netip.ParseAddr(a)
		if err != nil {
			l.WithField("value", a).WithError(err).Warn("failed to parse tun.snat_address_for_4over6, will use a random value")
		} else if !out.Is4() || !out.IsLinkLocalUnicast() {
			l.WithField("value", out).Warn("tun.snat_address_for_4over6 must be an IPv4 address")
		}
	}
	if !out.IsValid() {
		octets := []byte{169, 254, 0, 0}
		_, _ = rand.Read(octets[2:4])
		if octets[3] == 0 {
			octets[3] = 1 //please no .0 addresses
		} else if octets[2] == 255 && octets[3] == 255 {
			octets[3] = 254 //please no broadcast addresses
		}
		ok := false
		out, ok = netip.AddrFromSlice(octets)
		if !ok {
			l.Error("failed to produce a valid IPv4 address for tun.snat_address_for_4over6")
			return netip.Prefix{}
		}
	}
	return netip.PrefixFrom(out, 32)
}
