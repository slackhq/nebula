package overlay

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"

	"github.com/songgao/water"
)

type waterTun struct {
	Device       string
	Cidr         *net.IPNet
	MTU          int
	UnsafeRoutes []Route

	*water.Interface
}

func newWaterTun(cidr *net.IPNet, defaultMTU int, unsafeRoutes []Route) (*waterTun, error) {
	// NOTE: You cannot set the deviceName under Windows, so you must check tun.Device after calling .Activate()
	return &waterTun{
		Cidr:         cidr,
		MTU:          defaultMTU,
		UnsafeRoutes: unsafeRoutes,
	}, nil
}

func (t *waterTun) Activate() error {
	var err error
	t.Interface, err = water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: "tap0901",
			Network:     t.Cidr.String(),
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
		fmt.Sprintf("addr=%s", t.Cidr.IP),
		fmt.Sprintf("mask=%s", net.IP(t.Cidr.Mask)),
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

	for _, r := range t.UnsafeRoutes {
		err = exec.Command(
			"C:\\Windows\\System32\\route.exe", "add", r.Cidr.String(), r.Via.String(), "IF", strconv.Itoa(iface.Index), "METRIC", strconv.Itoa(r.Metric),
		).Run()
		if err != nil {
			return fmt.Errorf("failed to add the unsafe_route %s: %v", r.Cidr.String(), err)
		}
	}

	return nil
}

func (t *waterTun) CidrNet() *net.IPNet {
	return t.Cidr
}

func (t *waterTun) DeviceName() string {
	return t.Device
}

func (t *waterTun) WriteRaw(b []byte) error {
	_, err := t.Write(b)
	return err
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
