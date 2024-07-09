package overlay

import (
	"crypto"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"unsafe"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
	"github.com/slackhq/nebula/wintun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const tunGUIDLabel = "Fixed Nebula Windows GUID v1"

type winTun struct {
	Device    string
	cidr      netip.Prefix
	MTU       int
	Routes    atomic.Pointer[[]Route]
	routeTree atomic.Pointer[bart.Table[netip.Addr]]
	l         *logrus.Logger

	tun *wintun.NativeTun
}

func generateGUIDByDeviceName(name string) (*windows.GUID, error) {
	// GUID is 128 bit
	hash := crypto.MD5.New()

	_, err := hash.Write([]byte(tunGUIDLabel))
	if err != nil {
		return nil, err
	}

	_, err = hash.Write([]byte(name))
	if err != nil {
		return nil, err
	}

	sum := hash.Sum(nil)

	return (*windows.GUID)(unsafe.Pointer(&sum[0])), nil
}

func newWinTun(c *config.C, l *logrus.Logger, cidr netip.Prefix, _ bool) (*winTun, error) {
	deviceName := c.GetString("tun.dev", "")
	guid, err := generateGUIDByDeviceName(deviceName)
	if err != nil {
		return nil, fmt.Errorf("generate GUID failed: %w", err)
	}

	t := &winTun{
		Device: deviceName,
		cidr:   cidr,
		MTU:    c.GetInt("tun.mtu", DefaultMTU),
		l:      l,
	}

	err = t.reload(c, true)
	if err != nil {
		return nil, err
	}

	var tunDevice wintun.Device
	tunDevice, err = wintun.CreateTUNWithRequestedGUID(deviceName, guid, t.MTU)
	if err != nil {
		// Windows 10 has an issue with unclean shutdowns not fully cleaning up the wintun device.
		// Trying a second time resolves the issue.
		l.WithError(err).Debug("Failed to create wintun device, retrying")
		tunDevice, err = wintun.CreateTUNWithRequestedGUID(deviceName, guid, t.MTU)
		if err != nil {
			return nil, fmt.Errorf("create TUN device failed: %w", err)
		}
	}
	t.tun = tunDevice.(*wintun.NativeTun)

	c.RegisterReloadCallback(func(c *config.C) {
		err := t.reload(c, false)
		if err != nil {
			util.LogWithContextIfNeeded("failed to reload tun device", err, t.l)
		}
	})

	return t, nil
}

func (t *winTun) reload(c *config.C, initial bool) error {
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
		err := t.removeRoutes(findRemovedRoutes(routes, *oldRoutes))
		if err != nil {
			util.LogWithContextIfNeeded("Failed to remove routes", err, t.l)
		}

		// Ensure any routes we actually want are installed
		err = t.addRoutes(true)
		if err != nil {
			// Catch any stray logs
			util.LogWithContextIfNeeded("Failed to add routes", err, t.l)
		}
	}

	return nil
}

func (t *winTun) Activate() error {
	luid := winipcfg.LUID(t.tun.LUID())

	err := luid.SetIPAddresses([]netip.Prefix{t.cidr})
	if err != nil {
		return fmt.Errorf("failed to set address: %w", err)
	}

	err = t.addRoutes(false)
	if err != nil {
		return err
	}

	return nil
}

func (t *winTun) addRoutes(logErrors bool) error {
	luid := winipcfg.LUID(t.tun.LUID())
	routes := *t.Routes.Load()
	foundDefault4 := false

	for _, r := range routes {
		if !r.Via.IsValid() || !r.Install {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		// Add our unsafe route
		err := luid.AddRoute(r.Cidr, r.Via, uint32(r.Metric))
		if err != nil {
			retErr := util.NewContextualError("Failed to add route", map[string]interface{}{"route": r}, err)
			if logErrors {
				retErr.Log(t.l)
				continue
			} else {
				return retErr
			}
		} else {
			t.l.WithField("route", r).Info("Added route")
		}

		if !foundDefault4 {
			if r.Cidr.Bits() == 0 && r.Cidr.Addr().BitLen() == 32 {
				foundDefault4 = true
			}
		}
	}

	ipif, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("failed to get ip interface: %w", err)
	}

	ipif.NLMTU = uint32(t.MTU)
	if foundDefault4 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}

	if err := ipif.Set(); err != nil {
		return fmt.Errorf("failed to set ip interface: %w", err)
	}
	return nil
}

func (t *winTun) removeRoutes(routes []Route) error {
	luid := winipcfg.LUID(t.tun.LUID())

	for _, r := range routes {
		if !r.Install {
			continue
		}

		err := luid.DeleteRoute(r.Cidr, r.Via)
		if err != nil {
			t.l.WithError(err).WithField("route", r).Error("Failed to remove route")
		} else {
			t.l.WithField("route", r).Info("Removed route")
		}
	}
	return nil
}

func (t *winTun) RouteFor(ip netip.Addr) netip.Addr {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
}

func (t *winTun) Cidr() netip.Prefix {
	return t.cidr
}

func (t *winTun) Name() string {
	return t.Device
}

func (t *winTun) Read(b []byte) (int, error) {
	return t.tun.Read(b, 0)
}

func (t *winTun) Write(b []byte) (int, error) {
	return t.tun.Write(b, 0)
}

func (t *winTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for windows")
}

func (t *winTun) Close() error {
	// It seems that the Windows networking stack doesn't like it when we destroy interfaces that have active routes,
	// so to be certain, just remove everything before destroying.
	luid := winipcfg.LUID(t.tun.LUID())
	_ = luid.FlushRoutes(windows.AF_INET)
	_ = luid.FlushIPAddresses(windows.AF_INET)
	/* We don't support IPV6 yet
	_ = luid.FlushRoutes(windows.AF_INET6)
	_ = luid.FlushIPAddresses(windows.AF_INET6)
	*/
	_ = luid.FlushDNS(windows.AF_INET)

	return t.tun.Close()
}
