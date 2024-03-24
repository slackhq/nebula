package overlay

import (
	"net"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
)

const DefaultMTU = 1300

type DeviceFactory func(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, routines int) (Device, error)

func NewDeviceFromConfig(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, routines int) (Device, error) {
	routes, err := parseRoutes(c, tunCidr)
	if err != nil {
		return nil, util.NewContextualError("Could not parse tun.routes", nil, err)
	}

	unsafeRoutes, err := parseUnsafeRoutes(c, tunCidr)
	if err != nil {
		return nil, util.NewContextualError("Could not parse tun.unsafe_routes", nil, err)
	}
	routes = append(routes, unsafeRoutes...)

	switch {
	case c.GetBool("tun.disabled").UnwrapOr(false):
		tun := newDisabledTun(tunCidr, c.GetInt("tun.tx_queue").UnwrapOr(500), c.GetBool("stats.message_metrics").UnwrapOr(false), l)
		return tun, nil

	default:
		return newTun(
			l,
			c.GetString("tun.dev").UnwrapOrDefault(),
			tunCidr,
			c.GetInt("tun.mtu").UnwrapOr(DefaultMTU),
			routes,
			c.GetInt("tun.tx_queue").UnwrapOr(500),
			routines > 1,
			c.GetBool("tun.use_system_route_table").UnwrapOr(false),
		)
	}
}

func NewFdDeviceFromConfig(fd *int) DeviceFactory {
	return func(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, routines int) (Device, error) {
		routes, err := parseRoutes(c, tunCidr)
		if err != nil {
			return nil, util.NewContextualError("Could not parse tun.routes", nil, err)
		}

		unsafeRoutes, err := parseUnsafeRoutes(c, tunCidr)
		if err != nil {
			return nil, util.NewContextualError("Could not parse tun.unsafe_routes", nil, err)
		}
		routes = append(routes, unsafeRoutes...)
		return newTunFromFd(
			l,
			*fd,
			tunCidr,
			c.GetInt("tun.mtu").UnwrapOr(DefaultMTU),
			routes,
			c.GetInt("tun.tx_queue").UnwrapOr(500),
			c.GetBool("tun.use_system_route_table").UnwrapOr(false),
		)

	}
}
