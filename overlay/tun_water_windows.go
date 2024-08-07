package overlay

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
	"github.com/songgao/water"
)

type waterTun struct {
	Device    string
	cidr      netip.Prefix
	MTU       int
	Routes    atomic.Pointer[[]Route]
	routeTree atomic.Pointer[bart.Table[netip.Addr]]
	l         *logrus.Logger
	f         *net.Interface
	*water.Interface
}

func newWaterTun(c *config.C, l *logrus.Logger, cidr netip.Prefix, _ bool) (*waterTun, error) {
	// NOTE: You cannot set the deviceName under Windows, so you must check tun.Device after calling .Activate()
	t := &waterTun{
		cidr: cidr,
		MTU:  c.GetInt("tun.mtu", DefaultMTU),
		l:    l,
	}

	err := t.reload(c, true)
	if err != nil {
		return nil, err
	}

	c.RegisterReloadCallback(func(c *config.C) {
		err := t.reload(c, false)
		if err != nil {
			util.LogWithContextIfNeeded("failed to reload tun device", err, t.l)
		}
	})

	return t, nil
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
		fmt.Sprintf("addr=%s", t.cidr.Addr()),
		fmt.Sprintf("mask=%s", net.CIDRMask(t.cidr.Bits(), t.cidr.Addr().BitLen())),
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

	t.f, err = net.InterfaceByName(t.Device)
	if err != nil {
		return fmt.Errorf("failed to find interface named %s: %v", t.Device, err)
	}

	err = t.addRoutes(false)
	if err != nil {
		return err
	}

	return nil
}

func (t *waterTun) reload(c *config.C, initial bool) error {
	change, routes, err := getAllRoutesFromConfig(c, t.cidr, initial)
	if err != nil {
		return err
	}

	if !initial && !change {
		return nil
	}

	routeTree, err := makeRouteTree(t.l, routes, false)
	if err != nil {
		return err
	}

	// Teach nebula how to handle the routes before establishing them in the system table
	oldRoutes := t.Routes.Swap(&routes)
	t.routeTree.Store(routeTree)

	if !initial {
		// Remove first, if the system removes a wanted route hopefully it will be re-added next
		t.removeRoutes(findRemovedRoutes(routes, *oldRoutes))

		// Ensure any routes we actually want are installed
		err = t.addRoutes(true)
		if err != nil {
			// Catch any stray logs
			util.LogWithContextIfNeeded("Failed to set routes", err, t.l)
		} else {
			for _, r := range findRemovedRoutes(routes, *oldRoutes) {
				t.l.WithField("route", r).Info("Removed route")
			}
		}
	}

	return nil
}

func (t *waterTun) addRoutes(logErrors bool) error {
	// Path routes
	routes := *t.Routes.Load()
	for _, r := range routes {
		if !r.Via.IsValid() || !r.Install {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		err := exec.Command(
			"C:\\Windows\\System32\\route.exe", "add", r.Cidr.String(), r.Via.String(), "IF", strconv.Itoa(t.f.Index), "METRIC", strconv.Itoa(r.Metric),
		).Run()

		if err != nil {
			retErr := util.NewContextualError("Failed to add route", map[string]interface{}{"route": r}, err)
			if logErrors {
				retErr.Log(t.l)
			} else {
				return retErr
			}
		} else {
			t.l.WithField("route", r).Info("Added route")
		}
	}

	return nil
}

func (t *waterTun) removeRoutes(routes []Route) {
	for _, r := range routes {
		if !r.Install {
			continue
		}

		err := exec.Command(
			"C:\\Windows\\System32\\route.exe", "delete", r.Cidr.String(), r.Via.String(), "IF", strconv.Itoa(t.f.Index), "METRIC", strconv.Itoa(r.Metric),
		).Run()
		if err != nil {
			t.l.WithError(err).WithField("route", r).Error("Failed to remove route")
		} else {
			t.l.WithField("route", r).Info("Removed route")
		}
	}
}

func (t *waterTun) RouteFor(ip netip.Addr) netip.Addr {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
}

func (t *waterTun) Cidr() netip.Prefix {
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
