package nebula

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"

	"github.com/songgao/water"
)

type Tun struct {
	Device string
	Cidr   *net.IPNet
	MTU    int

	*water.Interface
}

func newTun(deviceName string, cidr *net.IPNet, defaultMTU int, routes []route, txQueueLen int) (ifce *Tun, err error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("Route MTU not supported in Darwin")
	}
	// NOTE: You cannot set the deviceName under Darwin, so you must check tun.Device after calling .Activate()
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
	if err = exec.Command("ifconfig", c.Device, c.Cidr.String(), c.Cidr.IP.String()).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	if err = exec.Command("route", "-n", "add", "-net", c.Cidr.String(), "-interface", c.Device).Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}
	if err = exec.Command("route", "-n", "delete", c.Cidr.IP.String()).Run(); err != nil {
		return fmt.Errorf("failed to run 'route delete': %s", err)
	}
	if err = exec.Command("route", "-n", "add", fmt.Sprintf("%s/32", c.Cidr.IP.String()), "127.0.0.1").Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}

	if err = exec.Command("ifconfig", c.Device, "mtu", strconv.Itoa(c.MTU)).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}

	return nil
}

func (c *Tun) WriteRaw(b []byte) error {
	_, err := c.Write(b)
	return err
}
