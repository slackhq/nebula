package overlay

import (
	"fmt"
	"net"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
)

const DefaultMTU = 1300

func NewDeviceFromConfig(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, fd *int, routines int) (Device, error) {
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
			c.GetInt("tun.tx_queue", 500),
		)

	default:
		return newTun(
			l,
			c.GetString("tun.dev", ""),
			tunCidr,
			c.GetInt("tun.mtu", DefaultMTU),
			routes,
			c.GetInt("tun.tx_queue", 500),
			routines > 1,
		)
	}
}

func makeCidrTree(routes []Route, allowMTU bool) (*cidr.Tree4, error) {
	cidrTree := cidr.NewTree4()
	for _, r := range routes {
		if !allowMTU && r.MTU > 0 {
			return nil, fmt.Errorf("route MTU is not supported in %s", runtime.GOOS)
		}

		if r.Via != nil {
			cidrTree.AddCIDR(r.Cidr, r.Via)
		}
	}
	return cidrTree, nil
}
