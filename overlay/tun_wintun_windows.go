package overlay

import (
	"crypto"
	"fmt"
	"io"
	"net"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/wintun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const tunGUIDLabel = "Fixed Nebula Windows GUID v1"

type winTun struct {
	Device    string
	cidr      *net.IPNet
	MTU       int
	Routes    []Route
	routeTree *cidr.Tree4

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

func newWinTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []Route) (*winTun, error) {
	guid, err := generateGUIDByDeviceName(deviceName)
	if err != nil {
		return nil, fmt.Errorf("generate GUID failed: %w", err)
	}

	tunDevice, err := wintun.CreateTUNWithRequestedGUID(deviceName, guid, defaultMTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN device failed: %w", err)
	}

	routeTree, err := makeRouteTree(l, routes, false)
	if err != nil {
		return nil, err
	}

	return &winTun{
		Device:    deviceName,
		cidr:      cidr,
		MTU:       defaultMTU,
		Routes:    routes,
		routeTree: routeTree,

		tun: tunDevice.(*wintun.NativeTun),
	}, nil
}

func (t *winTun) Activate() error {
	luid := winipcfg.LUID(t.tun.LUID())

	if err := luid.SetIPAddresses([]net.IPNet{*t.cidr}); err != nil {
		return fmt.Errorf("failed to set address: %w", err)
	}

	foundDefault4 := false
	routes := make([]*winipcfg.RouteData, 0, len(t.Routes)+1)

	for _, r := range t.Routes {
		if r.Via == nil {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		if !foundDefault4 {
			if ones, bits := r.Cidr.Mask.Size(); ones == 0 && bits != 0 {
				foundDefault4 = true
			}
		}

		// Add our unsafe route
		routes = append(routes, &winipcfg.RouteData{
			Destination: *r.Cidr,
			NextHop:     r.Via.ToIP(),
			Metric:      uint32(r.Metric),
		})
	}

	if err := luid.AddRoutes(routes); err != nil {
		return fmt.Errorf("failed to add routes: %w", err)
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

func (t *winTun) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	r := t.routeTree.MostSpecificContains(ip)
	if r != nil {
		return r.(iputil.VpnIp)
	}

	return 0
}

func (t *winTun) Cidr() *net.IPNet {
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
