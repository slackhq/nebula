package nebula

import (
	"crypto"
	"fmt"
	"io"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const tunGUIDLabel = "Fixed Nebula Windows GUID v1"

type WinTun struct {
	Device       string
	Cidr         *net.IPNet
	MTU          int
	UnsafeRoutes []route

	tun *tun.NativeTun
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

func newWinTun(deviceName string, cidr *net.IPNet, defaultMTU int, unsafeRoutes []route, txQueueLen int) (ifce *WinTun, err error) {
	guid, err := generateGUIDByDeviceName(deviceName)
	if err != nil {
		return nil, fmt.Errorf("Generate GUID failed: %w", err)
	}

	tunDevice, err := tun.CreateTUNWithRequestedGUID(deviceName, guid, defaultMTU)
	if err != nil {
		return nil, fmt.Errorf("Create TUN device failed: %w", err)
	}

	ifce = &WinTun{
		Device:       deviceName,
		Cidr:         cidr,
		MTU:          defaultMTU,
		UnsafeRoutes: unsafeRoutes,

		tun: tunDevice.(*tun.NativeTun),
	}

	return ifce, nil
}

func (c *WinTun) Activate() error {
	luid := winipcfg.LUID(c.tun.LUID())

	if err := luid.SetIPAddresses([]net.IPNet{*c.Cidr}); err != nil {
		return fmt.Errorf("failed to set address: %w", err)
	}

	foundDefault4 := false
	routes := make([]*winipcfg.RouteData, 0, len(c.UnsafeRoutes)+1)

	mainRoute := net.IPNet{
		IP:   c.Cidr.IP.Mask(c.Cidr.Mask),
		Mask: c.Cidr.Mask,
	}

	// Try to clear our the current route if one exists
	luid.DeleteRoute(mainRoute, net.IPv4zero)

	// Add cidr route to overwrite metric
	routes = append(routes, &winipcfg.RouteData{
		Destination: mainRoute,
		NextHop: net.IPv4zero,
	})

	for _, r := range c.UnsafeRoutes {
		if !foundDefault4 {
			if cidr, bits := r.route.Mask.Size(); cidr == 0 && bits != 0 {
				foundDefault4 = true
			}
		}

		// Try to clear out an existing route if one exists
		luid.DeleteRoute(*r.route, *r.via)

		// Add our unsafe route
		routes = append(routes, &winipcfg.RouteData{
			Destination: *r.route,
			NextHop:     *r.via,
			Metric:      uint32(r.metric),
		})
	}

	if err := luid.AddRoutes(routes); err != nil {
		return fmt.Errorf("failed to add routes: %w", err)
	}

	ipif, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("failed to get ip interface: %w", err)
	}

	ipif.NLMTU = uint32(c.MTU)
	if foundDefault4 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}

	if err := ipif.Set(); err != nil {
		return fmt.Errorf("failed to set ip interface: %w", err)
	}

	return nil
}

func (c *WinTun) CidrNet() *net.IPNet {
	return c.Cidr
}

func (c *WinTun) DeviceName() string {
	return c.Device
}

func (c *WinTun) Read(b []byte) (int, error) {
	return c.tun.Read(b, 0)
}

func (c *WinTun) Write(b []byte) (int, error) {
	return c.tun.Write(b, 0)
}

func (c *WinTun) WriteRaw(b []byte) error {
	_, err := c.Write(b)
	return err
}

func (c *WinTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for windows")
}

func (c *WinTun) Close() error {
	// It seems that the Windows networking stack doesn't like it when we destroy interfaces that have active routes,
	// so to be certain, just remove everything before destroying.
	luid := winipcfg.LUID(c.tun.LUID())
	_ = luid.FlushRoutes(windows.AF_INET)
	_ = luid.FlushIPAddresses(windows.AF_INET)
	/* We don't support IPV6 yet
	_ = luid.FlushRoutes(windows.AF_INET6)
	_ = luid.FlushIPAddresses(windows.AF_INET6)
	*/
	_ = luid.FlushDNS(windows.AF_INET)

	return c.tun.Close()
}
