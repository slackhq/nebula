package overlay

import (
	"net"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

const DefaultMTU = 1300

func NewDeviceFromConfig(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, routes, unsafeRoutes []Route, fd *int, routines int) (Device, error) {
	switch {
	case c.GetBool("tun.disabled", false):
		tun := newDisabledTun(tunCidr, c.GetInt("tun.tx_queue", 500), c.GetBool("stats.message_metrics", false), l)
		return tun, nil

	case fd != nil:
		return newTunFromFd(
			l,
			*fd,
			tunCidr,
			c.GetInt("tun.mtu", DefaultMTU),
			routes,
			unsafeRoutes,
			c.GetInt("tun.tx_queue", 500),
		)

	default:
		return newTun(
			l,
			c.GetString("tun.dev", ""),
			tunCidr,
			c.GetInt("tun.mtu", DefaultMTU),
			routes,
			unsafeRoutes,
			c.GetInt("tun.tx_queue", 500),
			routines > 1,
		)
	}
}
