// +build !e2e_testing

package nebula

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

type Tun struct {
	Device       string
	Cidr         *net.IPNet
	MTU          int
	UnsafeRoutes []route
	l            *logrus.Logger

	io.ReadWriteCloser
}

func newTunFromFd(l *logrus.Logger, deviceFd int, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int) (ifce *Tun, err error) {
	return nil, fmt.Errorf("newTunFromFd not supported in FreeBSD")
}

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int, multiqueue bool) (ifce *Tun, err error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("Route MTU not supported in FreeBSD")
	}
	if strings.HasPrefix(deviceName, "/dev/") {
		deviceName = strings.TrimPrefix(deviceName, "/dev/")
	}
	if !deviceNameRE.MatchString(deviceName) {
		return nil, fmt.Errorf("tun.dev must match `tun[0-9]+`")
	}
	return &Tun{
		Device:       deviceName,
		Cidr:         cidr,
		MTU:          defaultMTU,
		UnsafeRoutes: unsafeRoutes,
		l:            l,
	}, nil
}

func (c *Tun) Activate() error {
	var err error
	c.ReadWriteCloser, err = os.OpenFile("/dev/"+c.Device, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("Activate failed: %v", err)
	}

	// TODO use syscalls instead of exec.Command
	c.l.Debug("command: ifconfig", c.Device, c.Cidr.String(), c.Cidr.IP.String())
	if err = exec.Command("/sbin/ifconfig", c.Device, c.Cidr.String(), c.Cidr.IP.String()).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	c.l.Debug("command: route", "-n", "add", "-net", c.Cidr.String(), "-interface", c.Device)
	if err = exec.Command("/sbin/route", "-n", "add", "-net", c.Cidr.String(), "-interface", c.Device).Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}
	c.l.Debug("command: ifconfig", c.Device, "mtu", strconv.Itoa(c.MTU))
	if err = exec.Command("/sbin/ifconfig", c.Device, "mtu", strconv.Itoa(c.MTU)).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	// Unsafe path routes
	for _, r := range c.UnsafeRoutes {
		c.l.Debug("command: route", "-n", "add", "-net", r.route.String(), "-interface", c.Device)
		if err = exec.Command("/sbin/route", "-n", "add", "-net", r.route.String(), "-interface", c.Device).Run(); err != nil {
			return fmt.Errorf("failed to run 'route add' for unsafe_route %s: %s", r.route.String(), err)
		}
	}

	return nil
}

func (c *Tun) CidrNet() *net.IPNet {
	return c.Cidr
}

func (c *Tun) DeviceName() string {
	return c.Device
}

func (c *Tun) WriteRaw(b []byte) error {
	_, err := c.Write(b)
	return err
}

func (t *Tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for freebsd")
}
