//go:build ios && !e2e_testing
// +build ios,!e2e_testing

package overlay

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
)

type tun struct {
	io.ReadWriteCloser
	vpnNetworks []netip.Prefix
	Routes      atomic.Pointer[[]Route]
	routeTree   atomic.Pointer[bart.Table[routing.Gateways]]
	l           *slog.Logger
}

func newTun(_ *config.C, _ *slog.Logger, _ []netip.Prefix, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTun not supported in iOS")
}

func newTunFromFd(c *config.C, l *slog.Logger, deviceFd int, vpnNetworks []netip.Prefix) (*tun, error) {
	file := os.NewFile(uintptr(deviceFd), "/dev/tun")
	t := &tun{
		vpnNetworks:     vpnNetworks,
		ReadWriteCloser: file,
		l:               l,
	}

	err := t.reload(c, true)
	if err != nil {
		return nil, err
	}

	c.RegisterReloadCallback(func(c *config.C) {
		err := t.reload(c, false)
		if err != nil {
			util.LogWithContextIfNeeded("failed to reload tun device", err, t.l)
		}
	})

	return t, nil
}

func (t *tun) Activate() error {
	return nil
}

func (t *tun) reload(c *config.C, initial bool) error {
	change, routes, err := getAllRoutesFromConfig(c, t.vpnNetworks, initial)
	if err != nil {
		return err
	}

	if !initial && !change {
		return nil
	}

	routeTree, err := makeRouteTree(t.l, routes, false)
	if err != nil {
		return err
	}

	// Teach nebula how to handle the routes
	t.Routes.Store(&routes)
	t.routeTree.Store(routeTree)
	return nil
}

func (t *tun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
}

func (t *tun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

func (t *tun) Name() string {
	return "iOS"
}

func (t *tun) SupportsMultiqueue() bool {
	return false
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for ios")
}

// TunPrefixLen reports the 4-byte BSD AF_INET / AF_INET6 protocol-family
// marker the kernel prepends on read and expects on write.
func (t *tun) TunPrefixLen() int { return 4 }
