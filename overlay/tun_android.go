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
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
)

type tun struct {
	rwc         io.ReadWriteCloser
	fd          int
	vpnNetworks []netip.Prefix
	Routes      atomic.Pointer[[]Route]
	routeTree   atomic.Pointer[bart.Table[routing.Gateways]]
	l           *logrus.Logger

	readBuf  []byte
	batchRet [1][]byte
}

func (t *tun) Read() ([][]byte, error) {
	if t.readBuf == nil {
		t.readBuf = make([]byte, defaultBatchBufSize)
	}
	n, err := t.rwc.Read(t.readBuf)
	if err != nil {
		return nil, err
	}
	t.batchRet[0] = t.readBuf[:n]
	return t.batchRet[:], nil
}

func (t *tun) Write(p []byte) (int, error) {
	return t.rwc.Write(p)
}

func (t *tun) WriteReject(p []byte) (int, error) {
	return t.rwc.Write(p)
}

func (t *tun) Close() error {
	return t.rwc.Close()
}

func newTunFromFd(c *config.C, l *logrus.Logger, deviceFd int, vpnNetworks []netip.Prefix) (*tun, error) {
	// XXX Android returns an fd in non-blocking mode which is necessary for shutdown to work properly.
	// Be sure not to call file.Fd() as it will set the fd to blocking mode.
	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")

	t := &tun{
		rwc:         file,
		fd:          deviceFd,
		vpnNetworks: vpnNetworks,
		l:           l,
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

func newTun(_ *config.C, _ *logrus.Logger, _ []netip.Prefix, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTun not supported in Android")
}

func (t *tun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
}

func (t tun) Activate() error {
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

func (t *tun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

func (t *tun) Name() string {
	return "android"
}

func (t *tun) SupportsMultiqueue() bool {
	return false
}

func (t *tun) NewMultiQueueReader() (tio.Queue, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for android")
}
