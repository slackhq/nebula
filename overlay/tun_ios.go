//go:build ios && !e2e_testing
// +build ios,!e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
)

type tun struct {
	io.ReadWriteCloser
	vpnNetworks []netip.Prefix
	Routes      atomic.Pointer[[]Route]
	routeTree   atomic.Pointer[bart.Table[routing.Gateways]]
	l           *logrus.Logger
}

func newTun(_ *config.C, _ *logrus.Logger, _ []netip.Prefix, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTun not supported in iOS")
}

func newTunFromFd(c *config.C, l *logrus.Logger, deviceFd int, vpnNetworks []netip.Prefix) (*tun, error) {
	file := os.NewFile(uintptr(deviceFd), "/dev/tun")
	t := &tun{
		vpnNetworks:     vpnNetworks,
		ReadWriteCloser: &tunReadCloser{f: file},
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

// The following is hoisted up from water, we do this so we can inject our own fd on iOS
type tunReadCloser struct {
	f io.ReadWriteCloser

	rMu  sync.Mutex
	rBuf []byte

	wMu  sync.Mutex
	wBuf []byte
}

func (tr *tunReadCloser) Read(to []byte) (int, error) {
	tr.rMu.Lock()
	defer tr.rMu.Unlock()

	if cap(tr.rBuf) < len(to)+4 {
		tr.rBuf = make([]byte, len(to)+4)
	}
	tr.rBuf = tr.rBuf[:len(to)+4]

	n, err := tr.f.Read(tr.rBuf)
	copy(to, tr.rBuf[4:])
	return n - 4, err
}

func (tr *tunReadCloser) Write(from []byte) (int, error) {
	if len(from) == 0 {
		return 0, syscall.EIO
	}

	tr.wMu.Lock()
	defer tr.wMu.Unlock()

	if cap(tr.wBuf) < len(from)+4 {
		tr.wBuf = make([]byte, len(from)+4)
	}
	tr.wBuf = tr.wBuf[:len(from)+4]

	// Determine the IP Family for the NULL L2 Header
	ipVer := from[0] >> 4
	if ipVer == 4 {
		tr.wBuf[3] = syscall.AF_INET
	} else if ipVer == 6 {
		tr.wBuf[3] = syscall.AF_INET6
	} else {
		return 0, errors.New("unable to determine IP version from packet")
	}

	copy(tr.wBuf[4:], from)

	n, err := tr.f.Write(tr.wBuf)
	return n - 4, err
}

func (tr *tunReadCloser) Close() error {
	return tr.f.Close()
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
