package overlay

import (
	"net"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

const DefaultMTU = 1300

// TODO: We may be able to remove routines
type DeviceFactory func(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, routines int) (Device, error)

func NewDeviceFromConfig(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, routines int) (Device, error) {
	switch {
	case c.GetBool("tun.disabled", false):
		tun := newDisabledTun(tunCidr, c.GetInt("tun.tx_queue", 500), c.GetBool("stats.message_metrics", false), l)
		return tun, nil

	default:
		return newTun(c, l, tunCidr, routines > 1)
	}
}

func NewFdDeviceFromConfig(fd *int) DeviceFactory {
	return func(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, routines int) (Device, error) {
		return newTunFromFd(c, l, *fd, tunCidr)
	}
}

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
