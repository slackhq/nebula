//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

var deviceNameRE = regexp.MustCompile(`^tun[0-9]+$`)

type tun struct {
	Device       string
	Cidr         *net.IPNet
	MTU          int
	UnsafeRoutes []Route
	l            *logrus.Logger

	io.ReadWriteCloser
}

func (t *tun) Close() error {
	if t.ReadWriteCloser != nil {
		return t.ReadWriteCloser.Close()
	}
	return nil
}

func newTunFromFd(_ *logrus.Logger, _ int, _ *net.IPNet, _ int, _ []Route, _ []Route, _ int) (*tun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in FreeBSD")
}

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []Route, unsafeRoutes []Route, _ int, _ bool) (*tun, error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("route MTU not supported in FreeBSD")
	}
	if strings.HasPrefix(deviceName, "/dev/") {
		deviceName = strings.TrimPrefix(deviceName, "/dev/")
	}
	if !deviceNameRE.MatchString(deviceName) {
		return nil, fmt.Errorf("tun.dev must match `tun[0-9]+`")
	}
	return &tun{
		Device:       deviceName,
		Cidr:         cidr,
		MTU:          defaultMTU,
		UnsafeRoutes: unsafeRoutes,
		l:            l,
	}, nil
}

func (t *tun) Activate() error {
	var err error
	t.ReadWriteCloser, err = os.OpenFile("/dev/"+t.Device, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("activate failed: %v", err)
	}

	// TODO use syscalls instead of exec.Command
	t.l.Debug("command: ifconfig", t.Device, t.Cidr.String(), t.Cidr.IP.String())
	if err = exec.Command("/sbin/ifconfig", t.Device, t.Cidr.String(), t.Cidr.IP.String()).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	t.l.Debug("command: route", "-n", "add", "-net", t.Cidr.String(), "-interface", t.Device)
	if err = exec.Command("/sbin/route", "-n", "add", "-net", t.Cidr.String(), "-interface", t.Device).Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}
	t.l.Debug("command: ifconfig", t.Device, "mtu", strconv.Itoa(t.MTU))
	if err = exec.Command("/sbin/ifconfig", t.Device, "mtu", strconv.Itoa(t.MTU)).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	// Unsafe path routes
	for _, r := range t.UnsafeRoutes {
		t.l.Debug("command: route", "-n", "add", "-net", r.Cidr.String(), "-interface", t.Device)
		if err = exec.Command("/sbin/route", "-n", "add", "-net", r.Cidr.String(), "-interface", t.Device).Run(); err != nil {
			return fmt.Errorf("failed to run 'route add' for unsafe_route %s: %s", r.Cidr.String(), err)
		}
	}

	return nil
}

func (t *tun) CidrNet() *net.IPNet {
	return t.Cidr
}

func (t *tun) DeviceName() string {
	return t.Device
}

func (t *tun) WriteRaw(b []byte) error {
	_, err := t.Write(b)
	return err
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for freebsd")
}
