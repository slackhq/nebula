// +build ios
// +build !e2e_testing

package nebula

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
)

type Tun struct {
	io.ReadWriteCloser
	Device string
	Cidr   *net.IPNet
}

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int, multiqueue bool) (ifce *Tun, err error) {
	return nil, fmt.Errorf("newTun not supported in iOS")
}

func newTunFromFd(l *logrus.Logger, deviceFd int, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int) (ifce *Tun, err error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("route MTU not supported in Darwin")
	}

	file := os.NewFile(uintptr(deviceFd), "/dev/tun")
	ifce = &Tun{
		Cidr:            cidr,
		Device:          "iOS",
		ReadWriteCloser: &tunReadCloser{f: file},
	}
	return
}

func (c *Tun) Activate() error {
	return nil
}

func (c *Tun) WriteRaw(b []byte) error {
	_, err := c.Write(b)
	return err
}

// The following is hoisted up from water, we do this so we can inject our own fd on iOS
type tunReadCloser struct {
	f io.ReadWriteCloser

	rMu  sync.Mutex
	rBuf []byte

	wMu  sync.Mutex
	wBuf []byte
}

func (t *tunReadCloser) Read(to []byte) (int, error) {
	t.rMu.Lock()
	defer t.rMu.Unlock()

	if cap(t.rBuf) < len(to)+4 {
		t.rBuf = make([]byte, len(to)+4)
	}
	t.rBuf = t.rBuf[:len(to)+4]

	n, err := t.f.Read(t.rBuf)
	copy(to, t.rBuf[4:])
	return n - 4, err
}

func (t *tunReadCloser) Write(from []byte) (int, error) {

	if len(from) == 0 {
		return 0, syscall.EIO
	}

	t.wMu.Lock()
	defer t.wMu.Unlock()

	if cap(t.wBuf) < len(from)+4 {
		t.wBuf = make([]byte, len(from)+4)
	}
	t.wBuf = t.wBuf[:len(from)+4]

	// Determine the IP Family for the NULL L2 Header
	ipVer := from[0] >> 4
	if ipVer == 4 {
		t.wBuf[3] = syscall.AF_INET
	} else if ipVer == 6 {
		t.wBuf[3] = syscall.AF_INET6
	} else {
		return 0, errors.New("unable to determine IP version from packet")
	}

	copy(t.wBuf[4:], from)

	n, err := t.f.Write(t.wBuf)
	return n - 4, err
}

func (t *tunReadCloser) Close() error {
	return t.f.Close()
}

func (c *Tun) CidrNet() *net.IPNet {
	return c.Cidr
}

func (c *Tun) DeviceName() string {
	return c.Device
}

func (t *Tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for ios")
}
