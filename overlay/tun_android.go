//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type tun struct {
	io.ReadWriteCloser
	fd           int
	Device       string
	Cidr         *net.IPNet
	MaxMTU       int
	DefaultMTU   int
	TXQueueLen   int
	Routes       []Route
	UnsafeRoutes []Route
	l            *logrus.Logger
}

func newTunFromFd(l *logrus.Logger, deviceFd int, cidr *net.IPNet, defaultMTU int, routes []Route, unsafeRoutes []Route, txQueueLen int) (*tun, error) {
	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")

	return &tun{
		ReadWriteCloser: file,
		fd:              int(file.Fd()),
		Device:          "android",
		Cidr:            cidr,
		DefaultMTU:      defaultMTU,
		TXQueueLen:      txQueueLen,
		Routes:          routes,
		UnsafeRoutes:    unsafeRoutes,
		l:               l,
	}, nil
}

func newTun(_ *logrus.Logger, _ string, _ *net.IPNet, _ int, _ []Route, _ []Route, _ int, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTun not supported in Android")
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
	return t.Device
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for android")
}
