//go:build windows && !e2e_testing
// +build windows,!e2e_testing

package overlay

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const tunGUIDLabel = "Fixed Nebula Windows GUID v1"

type tun struct {
	luid windows.LUID
}

func newTunFromFd(_ *config.C, _ *logrus.Logger, _ int, _ []netip.Prefix) (*wgTun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in Windows")
}

func newTun(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, _ bool) (*wgTun, error) {
	deviceName := c.GetString("tun.dev", "Nebula")
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

	// Create Windows-specific route manager
	rm := &tun{}

	// Get LUID from the device name
	luid, err := winipcfg.LUIDFromAlias(actualName)
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("failed to get LUID: %w", err)
	}
	rm.luid = luid
	t.routeManager = rm

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
	// Set MTU
	err := rm.setMTU(t, t.MaxMTU)
	if err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	// Add IP addresses
	for _, network := range t.vpnNetworks {
		if err := rm.addIP(t, network); err != nil {
			return err
		}
	}

	// Add routes
	if err := rm.AddRoutes(t, false); err != nil {
		return err
	}

	return nil
}

func (rm *tun) SetMTU(t *wgTun, mtu int) {
	if err := rm.setMTU(t, mtu); err != nil {
		t.l.WithError(err).Error("Failed to set MTU")
	}
}

func (rm *tun) setMTU(t *wgTun, mtu int) error {
	// Set MTU using winipcfg
	return rm.luid.SetIPInterfaceMTU(uint32(mtu))
}

func (rm *tun) SetDefaultRoute(t *wgTun, cidr netip.Prefix) error {
	// On Windows, routes are managed differently
	return nil
}

func (rm *tun) AddRoutes(t *wgTun, logErrors bool) error {
	routes := *t.Routes.Load()
	for _, r := range routes {
		if !r.Install {
			continue
		}

		route := winipcfg.RouteData{
			Destination: r.Cidr,
			Metric:      uint32(r.Metric),
		}

		if r.MTU > 0 {
			// Windows route MTU is not directly supported
			t.l.WithField("route", r).Debug("Route MTU is not supported on Windows")
		}

		err := rm.luid.AddRoute(route.Destination, route.Destination.Addr(), route.Metric)
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
	for _, r := range routes {
		if !r.Install {
			continue
		}

		err := rm.luid.DeleteRoute(r.Cidr, r.Cidr.Addr())
		if err != nil {
			t.l.WithError(err).WithField("route", r).Error("Failed to remove route")
		} else {
			t.l.WithField("route", r).Info("Removed route")
		}
	}
}

func (rm *tun) NewMultiQueueReader(t *wgTun) (io.ReadWriteCloser, error) {
	// Windows doesn't support multi-queue TUN devices
	// Return a reader that wraps the same device
	return &wgTunReader{
		parent:    t,
		tunDevice: t.tunDevice,
		batchSize: 64,
		offset:    0,
		l:         t.l,
	}, nil
}

func (rm *tun) addIP(t *wgTun, network netip.Prefix) error {
	// Add IP address using winipcfg
	err := rm.luid.AddIPAddress(network)
	if err != nil {
		return fmt.Errorf("failed to add IP address %s: %w", network, err)
	}
	return nil
}

// generateGUIDByDeviceName generates a GUID based on the device name
func generateGUIDByDeviceName(deviceName string) (*windows.GUID, error) {
	// Hash the device name to create a deterministic GUID
	h := crypto.SHA256.New()
	h.Write([]byte(tunGUIDLabel))
	h.Write([]byte(deviceName))
	sum := h.Sum(nil)

	guid := &windows.GUID{
		Data1: binary.LittleEndian.Uint32(sum[0:4]),
		Data2: binary.LittleEndian.Uint16(sum[4:6]),
		Data3: binary.LittleEndian.Uint16(sum[6:8]),
	}
	copy(guid.Data4[:], sum[8:16])

	return guid, nil
}
