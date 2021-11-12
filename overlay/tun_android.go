//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/iputil"
	"golang.org/x/sys/unix"
)

type tun struct {
	io.ReadWriteCloser
	fd   int
	Cidr *net.IPNet
	l    *logrus.Logger
}

func newTunFromFd(l *logrus.Logger, deviceFd int, cidr *net.IPNet, _ int, routes []Route, _ int) (*tun, error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("routes are not supported in %s", runtime.GOOS)
	}

	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")

	return &tun{
		ReadWriteCloser: file,
		fd:              int(file.Fd()),
		Cidr:            cidr,
		l:               l,
	}, nil
}

func newTun(_ *logrus.Logger, _ string, _ *net.IPNet, _ int, _ []Route, _ int, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTun not supported in Android")
}

func (t *tun) RouteFor(iputil.VpnIp) iputil.VpnIp {
	return 0
}

func (t *tun) WriteRaw(b []byte) error {
	var nn int
	for {
		max := len(b)
		n, err := unix.Write(t.fd, b[nn:max])
		if n > 0 {
			nn += n
		}
		if nn == len(b) {
			return err
		}

		if err != nil {
			return err
		}

		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
}

func (t tun) Activate() error {
	return nil
}

func (t *tun) CidrNet() *net.IPNet {
	return t.Cidr
}

func (t *tun) DeviceName() string {
	return "android"
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for android")
}
