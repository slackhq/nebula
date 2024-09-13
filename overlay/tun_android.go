//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
)

type tun struct {
	io.ReadWriteCloser
	fd        int
	cidr      netip.Prefix
	Routes    atomic.Pointer[[]Route]
	routeTree atomic.Pointer[bart.Table[netip.Addr]]
	l         *logrus.Logger
}

func newTunFromFd(c *config.C, l *logrus.Logger, deviceFd int, cidr netip.Prefix) (*tun, error) {
	// XXX Android returns an fd in non-blocking mode which is necessary for shutdown to work properly.
	// Be sure not to call file.Fd() as it will set the fd to blocking mode.
	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")

	t := &tun{
		ReadWriteCloser: file,
		fd:              deviceFd,
		cidr:            cidr,
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

func newTun(_ *config.C, _ *logrus.Logger, _ netip.Prefix, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTun not supported in Android")
}

func (t *tun) RouteFor(ip netip.Addr) netip.Addr {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
}

func (t tun) Activate() error {
	return nil
}

func (t *tun) reload(c *config.C, initial bool) error {
	change, routes, err := getAllRoutesFromConfig(c, t.cidr, initial)
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

func (t *tun) Cidr() netip.Prefix {
	return t.cidr
}

func (t *tun) Name() string {
	return "android"
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for android")
}
