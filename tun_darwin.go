// +build !ios
// +build !e2e_testing

package nebula

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

type Tun struct {
	Device       string
	Cidr         *net.IPNet
	MTU          int
	UnsafeRoutes []route
	l            *logrus.Logger
	*water.Interface
}

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int, multiqueue bool) (ifce *Tun, err error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("route MTU not supported in Darwin")
	}

	// NOTE: You cannot set the deviceName under Darwin, so you must check tun.Device after calling .Activate()
	return &Tun{
		Cidr:         cidr,
		MTU:          defaultMTU,
		UnsafeRoutes: unsafeRoutes,
		l:            l,
	}, nil
}

func newTunFromFd(l *logrus.Logger, deviceFd int, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int) (ifce *Tun, err error) {
	return nil, fmt.Errorf("newTunFromFd not supported in Darwin")
}

func (c *Tun) Activate() error {
	var err error
	c.Interface, err = water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return fmt.Errorf("activate failed: %v", err)
	}

	c.Device = c.Interface.Name()

	// TODO use syscalls instead of exec.Command
	if err = exec.Command("/sbin/ifconfig", c.Device, c.Cidr.String(), c.Cidr.IP.String()).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	if err = exec.Command("/sbin/route", "-n", "add", "-net", c.Cidr.String(), "-interface", c.Device).Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}
	if err = exec.Command("/sbin/ifconfig", c.Device, "mtu", strconv.Itoa(c.MTU)).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	// Unsafe path routes
	for _, r := range c.UnsafeRoutes {
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
	return nil, fmt.Errorf("TODO: multiqueue not implemented for darwin")
}
