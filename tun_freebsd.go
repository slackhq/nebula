package nebula

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/yggdrasil-network/water"
)

var deviceNameRE = regexp.MustCompile(`^/dev/tun[0-9]+$`)

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
	if !strings.HasPrefix(deviceName, "/dev/") {
		deviceName = "/dev/" + deviceName
	}
	if !deviceNameRE.MatchString(deviceName) {
		return nil, fmt.Errorf("tun.dev must match `tun[0-9]+`")
	}
	return &Tun{
		Device: deviceName,
		Cidr:   cidr,
		MTU:    defaultMTU,
	}, nil
}

func (c *Tun) Activate() error {
	var err error
	c.Interface, err = water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: c.Device,
		},
	})
	if err != nil {
		return fmt.Errorf("Activate failed: %v", err)
	}

	c.Device = c.Interface.Name()

	// TODO use syscalls instead of exec.Command
	l.Debug("command: ifconfig", c.Device, c.Cidr.String(), c.Cidr.IP.String())
	if err = exec.Command("ifconfig", c.Device, c.Cidr.String(), c.Cidr.IP.String()).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	l.Debug("command: route", "-n", "add", "-net", c.Cidr.String(), "-interface", c.Device)
	if err = exec.Command("route", "-n", "add", "-net", c.Cidr.String(), "-interface", c.Device).Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}
	l.Debug("command: ifconfig", c.Device, "mtu", strconv.Itoa(c.MTU))
	if err = exec.Command("ifconfig", c.Device, "mtu", strconv.Itoa(c.MTU)).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}

	return nil
}

func (c *Tun) WriteRaw(b []byte) error {
	_, err := c.Write(b)
	return err
}
