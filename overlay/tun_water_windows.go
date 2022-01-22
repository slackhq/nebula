package overlay

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
	"github.com/songgao/water"
)

type waterTun struct {
	Device    string
	cidr      *net.IPNet
	MTU       int
	Routes    []Route
	routeTree *cidr.Tree4

	*water.Interface
}

func newWaterTun(l *logrus.Logger, cidr *net.IPNet, defaultMTU int, routes []Route) (*waterTun, error) {
	routeTree, err := makeRouteTree(l, routes, false)
	if err != nil {
		return nil, err
	}

	// NOTE: You cannot set the deviceName under Windows, so you must check tun.Device after calling .Activate()
	return &waterTun{
		cidr:      cidr,
		MTU:       defaultMTU,
		Routes:    routes,
		routeTree: routeTree,
	}, nil
}

func (t *waterTun) Activate() error {
	var err error
	t.Interface, err = water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: "tap0901",
			Network:     t.cidr.String(),
		},
	})
	if err != nil {
		return fmt.Errorf("activate failed: %v", err)
	}

	t.Device = t.Interface.Name()

	// TODO use syscalls instead of exec.Command
	err = exec.Command(
		`C:\Windows\System32\netsh.exe`, "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", t.Device),
		"source=static",
		fmt.Sprintf("addr=%s", t.cidr.IP),
		fmt.Sprintf("mask=%s", net.IP(t.cidr.Mask)),
		"gateway=none",
	).Run()
	if err != nil {
		return fmt.Errorf("failed to run 'netsh' to set address: %s", err)
	}
	err = exec.Command(
		`C:\Windows\System32\netsh.exe`, "interface", "ipv4", "set", "interface",
		t.Device,
		fmt.Sprintf("mtu=%d", t.MTU),
	).Run()
	if err != nil {
		return fmt.Errorf("failed to run 'netsh' to set MTU: %s", err)
	}

	iface, err := net.InterfaceByName(t.Device)
	if err != nil {
		return fmt.Errorf("failed to find interface named %s: %v", t.Device, err)
	}

	for _, r := range t.Routes {
		if r.Via == nil {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		err = exec.Command(
			"C:\\Windows\\System32\\route.exe", "add", r.Cidr.String(), r.Via.String(), "IF", strconv.Itoa(iface.Index), "METRIC", strconv.Itoa(r.Metric),
		).Run()
		if err != nil {
			return fmt.Errorf("failed to add the unsafe_route %s: %v", r.Cidr.String(), err)
		}
	}

	return nil
}

func (t *waterTun) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	r := t.routeTree.MostSpecificContains(ip)
	if r != nil {
		return r.(iputil.VpnIp)
	}

	return 0
}

func (t *waterTun) Cidr() *net.IPNet {
	return t.cidr
}

func (t *waterTun) Name() string {
	return t.Device
}

func (t *waterTun) Close() error {
	if t.Interface == nil {
		return nil
	}

	return t.Interface.Close()
}

func (t *waterTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for windows")
}
