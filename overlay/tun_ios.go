//go:build ios && !e2e_testing
// +build ios,!e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
)

type tun struct {
	io.ReadWriteCloser
	cidr      *net.IPNet
	routeTree *cidr.Tree4
}

func newTun(_ *logrus.Logger, _ string, _ *net.IPNet, _ int, _ []Route, _ int, _ bool, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTun not supported in iOS")
}

func newTunFromFd(l *logrus.Logger, deviceFd int, cidr *net.IPNet, _ int, routes []Route, _ int, _ bool) (*tun, error) {
	routeTree, err := makeRouteTree(l, routes, false)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(deviceFd), "/dev/tun")
	return &tun{
		cidr:            cidr,
		ReadWriteCloser: &tunReadCloser{f: file},
		routeTree:       routeTree,
	}, nil
}

func (t *tun) Activate() error {
	return nil
}

func (t *tun) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	r := t.routeTree.MostSpecificContains(ip)
	if r != nil {
		return r.(iputil.VpnIp)
	}

	return 0
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

func (t *tun) Cidr() *net.IPNet {
	return t.cidr
}

func (t *tun) Name() string {
	return "iOS"
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for ios")
}
