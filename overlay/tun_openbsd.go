//go:build openbsd && !e2e_testing
// +build openbsd,!e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type tun struct{}

func newTunFromFd(_ *config.C, _ *logrus.Logger, _ int, _ []netip.Prefix) (*wgTun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported on OpenBSD")
}

func newTun(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, _ bool) (*wgTun, error) {
	deviceName := c.GetString("tun.dev", "tun")
	mtu := c.GetInt("tun.mtu", DefaultMTU)

	// Create WireGuard TUN device
	tunDevice, err := wgtun.CreateTUN(deviceName, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	// Get the actual device name
	actualName, err := tunDevice.Name()
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("failed to get TUN device name: %w", err)
	}

	t := &wgTun{
		tunDevice:   tunDevice,
		vpnNetworks: vpnNetworks,
		MaxMTU:      mtu,
		DefaultMTU:  mtu,
		l:           l,
	}

	// Create OpenBSD-specific route manager
	t.routeManager = &tun{}

	err = t.reload(c, true)
	if err != nil {
		tunDevice.Close()
		return nil, err
	}

	c.RegisterReloadCallback(func(c *config.C) {
		err := t.reload(c, false)
		if err != nil {
			util.LogWithContextIfNeeded("failed to reload tun device", err, t.l)
		}
	})

	l.WithField("name", actualName).Info("Created WireGuard TUN device")

	return t, nil
}

func (rm *tun) Activate(t *wgTun) error {
	name, err := t.tunDevice.Name()
	if err != nil {
		return fmt.Errorf("failed to get device name: %w", err)
	}

	// Set the MTU
	rm.SetMTU(t, t.MaxMTU)

	// Add IP addresses
	for _, network := range t.vpnNetworks {
		if err := rm.addIP(t, name, network); err != nil {
			return err
		}
	}

	// Bring up the interface
	if err := runCommandBSD("ifconfig", name, "up"); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	// Set the routes
	if err := rm.AddRoutes(t, false); err != nil {
		return err
	}

	return nil
}

func (rm *tun) SetMTU(t *wgTun, mtu int) {
	name, err := t.tunDevice.Name()
	if err != nil {
		t.l.WithError(err).Error("Failed to get device name for MTU set")
		return
	}

	if err := runCommandBSD("ifconfig", name, "mtu", strconv.Itoa(mtu)); err != nil {
		t.l.WithError(err).Error("Failed to set tun mtu")
	}
}

func (rm *tun) SetDefaultRoute(t *wgTun, cidr netip.Prefix) error {
	// On OpenBSD, routes are set via ifconfig and route commands
	return nil
}

func (rm *tun) AddRoutes(t *wgTun, logErrors bool) error {
	name, err := t.tunDevice.Name()
	if err != nil {
		return fmt.Errorf("failed to get device name: %w", err)
	}

	routes := *t.Routes.Load()
	for _, r := range routes {
		if !r.Install {
			continue
		}

		// Add route using route command
		args := []string{"add"}

		if r.Cidr.Addr().Is6() {
			args = append(args, "-inet6")
		} else {
			args = append(args, "-inet")
		}

		args = append(args, r.Cidr.String(), "-interface", name)

		if r.Metric > 0 {
			// OpenBSD doesn't support route metrics directly like Linux
			t.l.WithField("route", r).Warn("Route metrics are not fully supported on OpenBSD")
		}

		err := runCommandBSD("route", args...)
		if err != nil {
			retErr := util.NewContextualError("Failed to add route", map[string]any{"route": r}, err)
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

func (rm *tun) RemoveRoutes(t *wgTun, routes []Route) {
	name, err := t.tunDevice.Name()
	if err != nil {
		t.l.WithError(err).Error("Failed to get device name for route removal")
		return
	}

	for _, r := range routes {
		if !r.Install {
			continue
		}

		args := []string{"delete"}

		if r.Cidr.Addr().Is6() {
			args = append(args, "-inet6")
		} else {
			args = append(args, "-inet")
		}

		args = append(args, r.Cidr.String(), "-interface", name)

		err := runCommandBSD("route", args...)
		if err != nil {
			t.l.WithError(err).WithField("route", r).Error("Failed to remove route")
		} else {
			t.l.WithField("route", r).Info("Removed route")
		}
	}
}

func (rm *tun) NewMultiQueueReader(t *wgTun) (io.ReadWriteCloser, error) {
	// OpenBSD doesn't support multi-queue TUN devices in the same way as Linux
	// Return a reader that wraps the same device
	return &wgTunReader{
		parent:    t,
		tunDevice: t.tunDevice,
		offset:    0,
		l:         t.l,
	}, nil
}

func (rm *tun) addIP(t *wgTun, name string, network netip.Prefix) error {
	addr := network.Addr()

	if addr.Is4() {
		// For IPv4: ifconfig tun0 10.0.0.1/24
		if err := runCommandBSD("ifconfig", name, network.String()); err != nil {
			return fmt.Errorf("failed to add IPv4 address: %w", err)
		}
	} else {
		// For IPv6: ifconfig tun0 inet6 add 2001:db8::1/64
		if err := runCommandBSD("ifconfig", name, "inet6", "add", network.String()); err != nil {
			return fmt.Errorf("failed to add IPv6 address: %w", err)
		}
	}

	return nil
}

func runCommandBSD(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w\nOutput: %s", name, strings.Join(args, " "), err, string(output))
	}
	return nil
}
