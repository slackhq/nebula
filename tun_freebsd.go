package nebula

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"

	"github.com/yggdrasil-network/water"
)

type Tun struct {
	Device string
	Cidr   *net.IPNet
	MTU    int

	*water.Interface
}

func newTun(deviceName string, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int) (ifce *Tun, err error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("Route MTU not supported in FreeBSD")
	}
	if len(unsafeRoutes) > 0 {
		return nil, fmt.Errorf("unsafeRoutes not supported in FreeBSD")
	}
	// NOTE: You cannot set the deviceName under FreeBSD, so you must check tun.Device after calling .Activate()
	return &Tun{
		Cidr: cidr,
		MTU:  defaultMTU,
	}, nil
}

func (c *Tun) Activate() error {
	var err error
	c.Interface, err = water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return fmt.Errorf("Activate failed: %v", err)
	}

	c.Device = c.Interface.Name()

	// TODO use syscalls instead of exec.Command
	fmt.Println("command: ifconfig", c.Device, c.Cidr.String(), c.Cidr.IP.String())
	if err = exec.Command("ifconfig", c.Device, c.Cidr.String(), c.Cidr.IP.String()).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	/* This is not needed on FreeBSD
	fmt.Println("command: route", "-n", "add", "-net", c.Cidr.String(), "-interface", c.Device)
	if err = exec.Command("route", "-n", "add", "-net", c.Cidr.String(), "-interface", c.Device).Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}
	*/
	fmt.Println("command: ifconfig", c.Device, "mtu", strconv.Itoa(c.MTU))
	if err = exec.Command("ifconfig", c.Device, "mtu", strconv.Itoa(c.MTU)).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}

	return nil
}

func (c *Tun) WriteRaw(b []byte) error {
	_, err := c.Write(b)
	return err
}
