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

func newTunFromFd(l *logrus.Logger, deviceFd int, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int) (ifce *Tun, err error) {
	return nil, fmt.Errorf("newTunFromFd not supported in Windows")
}

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int, multiqueue bool) (ifce *Tun, err error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("route MTU not supported in Windows")
	}

	// NOTE: You cannot set the deviceName under Windows, so you must check tun.Device after calling .Activate()
	return &Tun{
		Cidr:         cidr,
		MTU:          defaultMTU,
		UnsafeRoutes: unsafeRoutes,
		l:            l,
	}, nil
}

func (c *Tun) Activate() error {
	var err error
	c.Interface, err = water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: "tap0901",
			Network:     c.Cidr.String(),
		},
	})
	if err != nil {
		return fmt.Errorf("Activate failed: %v", err)
	}

	c.Device = c.Interface.Name()

	// TODO use syscalls instead of exec.Command
	err = exec.Command(
		`C:\Windows\System32\netsh.exe`, "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", c.Device),
		"source=static",
		fmt.Sprintf("addr=%s", c.Cidr.IP),
		fmt.Sprintf("mask=%s", net.IP(c.Cidr.Mask)),
		"gateway=none",
	).Run()
	if err != nil {
		return fmt.Errorf("failed to run 'netsh' to set address: %s", err)
	}
	err = exec.Command(
		`C:\Windows\System32\netsh.exe`, "interface", "ipv4", "set", "interface",
		c.Device,
		fmt.Sprintf("mtu=%d", c.MTU),
	).Run()
	if err != nil {
		return fmt.Errorf("failed to run 'netsh' to set MTU: %s", err)
	}

	iface, err := net.InterfaceByName(c.Device)
	if err != nil {
		return fmt.Errorf("failed to find interface named %s: %v", c.Device, err)
	}

	for _, r := range c.UnsafeRoutes {
		err = exec.Command(
			"C:\\Windows\\System32\\route.exe", "add", r.route.String(), r.via.String(), "IF", strconv.Itoa(iface.Index),
		).Run()
		if err != nil {
			return fmt.Errorf("failed to add the unsafe_route %s: %v", r.route.String(), err)
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
	return nil, fmt.Errorf("TODO: multiqueue not implemented for windows")
}
