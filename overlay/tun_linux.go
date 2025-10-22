//go:build linux && !android && !e2e_testing
// +build linux,!android,!e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type tun struct {
	deviceIndex               int
	ioctlFd                   uintptr
	useSystemRoutes           bool
	useSystemRoutesBufferSize int
}

func newTun(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, multiqueue bool) (*wgTun, error) {
	deviceName := c.GetString("tun.dev", "")
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

	// Create Linux-specific route manager
	routeManager := &tun{
		useSystemRoutes:           c.GetBool("tun.use_system_route_table", false),
		useSystemRoutesBufferSize: c.GetInt("tun.use_system_route_table_buffer_size", 0),
	}
	t.routeManager = routeManager

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

func newTunFromFd(c *config.C, l *logrus.Logger, deviceFd int, vpnNetworks []netip.Prefix) (*wgTun, error) {
	// Create TUN device from file descriptor
	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")
	mtu := c.GetInt("tun.mtu", DefaultMTU)
	tunDevice, err := wgtun.CreateTUNFromFile(file, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device from fd: %w", err)
	}

	t := &wgTun{
		tunDevice:   tunDevice,
		vpnNetworks: vpnNetworks,
		MaxMTU:      mtu,
		DefaultMTU:  mtu,
		l:           l,
	}

	// Create Linux-specific route manager
	routeManager := &tun{
		useSystemRoutes:           c.GetBool("tun.use_system_route_table", false),
		useSystemRoutesBufferSize: c.GetInt("tun.use_system_route_table_buffer_size", 0),
	}
	t.routeManager = routeManager

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

	return t, nil
}

func (rm *tun) Activate(t *wgTun) error {
	name, err := t.tunDevice.Name()
	if err != nil {
		return fmt.Errorf("failed to get device name: %w", err)
	}

	if t.routeManager.useSystemRoutes {
		t.watchRoutes()
	}

	// Get the netlink device
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get tun device link: %s", err)
	}

	rm.deviceIndex = link.Attrs().Index

	// Open socket for ioctl operations
	s, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		unix.IPPROTO_IP,
	)
	if err != nil {
		return err
	}
	rm.ioctlFd = uintptr(s)

	// Set the MTU
	rm.SetMTU(t, t.MaxMTU)

	// Set the transmit queue length
	txQueueLen := 500 // default
	devName := deviceBytes(name)
	ifrq := ifreqQLEN{Name: devName, Value: int32(txQueueLen)}
	if err = ioctl(t.routeManager.ioctlFd, unix.SIOCSIFTXQLEN, uintptr(unsafe.Pointer(&ifrq))); err != nil {
		t.l.WithError(err).Error("Failed to set tun tx queue length")
	}

	// Disable IPv6 link-local address generation
	const modeNone = 1
	if err = netlink.LinkSetIP6AddrGenMode(link, modeNone); err != nil {
		t.l.WithError(err).Warn("Failed to disable link local address generation")
	}

	// Add IP addresses
	if err = t.routeManager.addIPs(t, link); err != nil {
		return err
	}

	// Bring up the interface
	if err = netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring the tun device up: %s", err)
	}

	// Set route MTU
	for i := range t.vpnNetworks {
		if err = t.routeManager.SetDefaultRoute(t, t.vpnNetworks[i]); err != nil {
			return fmt.Errorf("failed to set default route MTU: %w", err)
		}
	}

	// Set the routes
	if err = t.routeManager.AddRoutes(t, false); err != nil {
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

	link, err := netlink.LinkByName(name)
	if err != nil {
		t.l.WithError(err).Error("Failed to get link for MTU set")
		return
	}

	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		t.l.WithError(err).Error("Failed to set tun mtu")
	}
}

func (rm *tun) SetDefaultRoute(t *wgTun, cidr netip.Prefix) error {
	dr := &net.IPNet{
		IP:   cidr.Masked().Addr().AsSlice(),
		Mask: net.CIDRMask(cidr.Bits(), cidr.Addr().BitLen()),
	}

	nr := netlink.Route{
		LinkIndex: t.routeManager.deviceIndex,
		Dst:       dr,
		MTU:       t.DefaultMTU,
		AdvMSS:    advMSS(Route{}, t.DefaultMTU, t.MaxMTU),
		Scope:     unix.RT_SCOPE_LINK,
		Src:       net.IP(cidr.Addr().AsSlice()),
		Protocol:  unix.RTPROT_KERNEL,
		Table:     unix.RT_TABLE_MAIN,
		Type:      unix.RTN_UNICAST,
	}
	err := netlink.RouteReplace(&nr)
	if err != nil {
		t.l.WithError(err).WithField("cidr", cidr).Warn("Failed to set default route MTU, retrying")
		// Retry twice more
		for i := 0; i < 2; i++ {
			time.Sleep(100 * time.Millisecond)
			err = netlink.RouteReplace(&nr)
			if err == nil {
				break
			} else {
				t.l.WithError(err).WithField("cidr", cidr).WithField("mtu", t.DefaultMTU).Warn("Failed to set default route MTU, retrying")
			}
		}
		if err != nil {
			return fmt.Errorf("failed to set mtu %v on the default route %v; %v", t.DefaultMTU, dr, err)
		}
	}

	return nil
}

func (rm *tun) AddRoutes(t *wgTun, logErrors bool) error {
	routes := *t.Routes.Load()
	for _, r := range routes {
		if !r.Install {
			continue
		}

		dr := &net.IPNet{
			IP:   r.Cidr.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(r.Cidr.Bits(), r.Cidr.Addr().BitLen()),
		}

		nr := netlink.Route{
			LinkIndex: t.routeManager.deviceIndex,
			Dst:       dr,
			MTU:       r.MTU,
			AdvMSS:    advMSS(r, t.DefaultMTU, t.MaxMTU),
			Scope:     unix.RT_SCOPE_LINK,
		}

		if r.Metric > 0 {
			nr.Priority = r.Metric
		}

		err := netlink.RouteReplace(&nr)
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

		dr := &net.IPNet{
			IP:   r.Cidr.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(r.Cidr.Bits(), r.Cidr.Addr().BitLen()),
		}

		nr := netlink.Route{
			LinkIndex: t.routeManager.deviceIndex,
			Dst:       dr,
			MTU:       r.MTU,
			AdvMSS:    advMSS(r, t.DefaultMTU, t.MaxMTU),
			Scope:     unix.RT_SCOPE_LINK,
		}

		if r.Metric > 0 {
			nr.Priority = r.Metric
		}

		err := netlink.RouteDel(&nr)
		if err != nil {
			t.l.WithError(err).WithField("route", r).Error("Failed to remove route")
		} else {
			t.l.WithField("route", r).Info("Removed route")
		}
	}
}

func (rm *tun) NewMultiQueueReader(t *wgTun) (io.ReadWriteCloser, error) {
	// For Linux with WireGuard TUN, we can reuse the same device
	// The vectorized I/O will handle batching
	return &wgTunReader{
		parent:    t,
		tunDevice: t.tunDevice,
		batchSize: 64, // Default batch size
		offset:    0,
		l:         t.l,
	}, nil
}

// Helper functions

func deviceBytes(name string) [16]byte {
	var o [16]byte
	for i, c := range name {
		if i >= 16 {
			break
		}
		o[i] = byte(c)
	}
	return o
}

func advMSS(r Route, defaultMTU, maxMTU int) int {
	mtu := r.MTU
	if r.MTU == 0 {
		mtu = defaultMTU
	}

	// We only need to set advmss if the route MTU does not match the device MTU
	if mtu != maxMTU {
		return mtu - 40
	}
	return 0
}

type ifreqQLEN struct {
	Name  [16]byte
	Value int32
	pad   [8]byte
}

func hasNetlinkAddr(al []*netlink.Addr, x netlink.Addr) bool {
	for i := range al {
		if al[i].Equal(x) {
			return true
		}
	}
	return false
}

func (rm *tun) addIPs(t *wgTun, link netlink.Link) error {
	newAddrs := make([]*netlink.Addr, len(t.vpnNetworks))
	for i := range t.vpnNetworks {
		newAddrs[i] = &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   t.vpnNetworks[i].Addr().AsSlice(),
				Mask: net.CIDRMask(t.vpnNetworks[i].Bits(), t.vpnNetworks[i].Addr().BitLen()),
			},
			Label: t.vpnNetworks[i].Addr().Zone(),
		}
	}

	// Add all new addresses
	for i := range newAddrs {
		if err := netlink.AddrReplace(link, newAddrs[i]); err != nil {
			return err
		}
	}

	// Iterate over remainder, remove whoever shouldn't be there
	al, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to get tun address list: %s", err)
	}

	for i := range al {
		if hasNetlinkAddr(newAddrs, al[i]) {
			continue
		}
		err = netlink.AddrDel(link, &al[i])
		if err != nil {
			t.l.WithError(err).Error("failed to remove address from tun address list")
		} else {
			t.l.WithField("removed", al[i].String()).Info("removed address not listed in cert(s)")
		}
	}

	return nil
}

// watchRoutes monitors system route changes
func (t *wgTun) watchRoutes() {

	rch := make(chan netlink.RouteUpdate)
	doneChan := make(chan struct{})

	netlinkOptions := netlink.RouteSubscribeOptions{
		ReceiveBufferSize:      t.routeManager.useSystemRoutesBufferSize,
		ReceiveBufferForceSize: t.routeManager.useSystemRoutesBufferSize != 0,
		ErrorCallback:          func(e error) { t.l.WithError(e).Errorf("netlink error") },
	}

	if err := netlink.RouteSubscribeWithOptions(rch, doneChan, netlinkOptions); err != nil {
		t.l.WithError(err).Errorf("failed to subscribe to system route changes")
		return
	}

	t.routeChan = doneChan

	go func() {
		for {
			select {
			case r, ok := <-rch:
				if ok {
					t.updateRoutes(r)
				} else {
					return
				}
			case <-doneChan:
				return
			}
		}
	}()
}

func (t *wgTun) updateRoutes(r netlink.RouteUpdate) {
	gateways := t.getGatewaysFromRoute(&r.Route, t.routeManager.deviceIndex)

	if len(gateways) == 0 {
		t.l.WithField("route", r).Debug("Ignoring route update, no gateways")
		return
	}

	if r.Dst == nil {
		t.l.WithField("route", r).Debug("Ignoring route update, no destination address")
		return
	}

	dstAddr, ok := netip.AddrFromSlice(r.Dst.IP)
	if !ok {
		t.l.WithField("route", r).Debug("Ignoring route update, invalid destination address")
		return
	}

	ones, _ := r.Dst.Mask.Size()
	dst := netip.PrefixFrom(dstAddr, ones)

	newTree := t.routeTree.Load().Clone()

	if r.Type == unix.RTM_NEWROUTE {
		t.l.WithField("destination", dst).WithField("via", gateways).Info("Adding route")
		newTree.Insert(dst, gateways)
	} else {
		t.l.WithField("destination", dst).WithField("via", gateways).Info("Removing route")
		newTree.Delete(dst)
	}
	t.routeTree.Store(newTree)
}

func (t *wgTun) getGatewaysFromRoute(r *netlink.Route, deviceIndex int) routing.Gateways {
	var gateways routing.Gateways

	name, err := t.tunDevice.Name()
	if err != nil {
		t.l.Error("Ignoring route update: failed to get device name")
		return gateways
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		t.l.WithField("DeviceName", name).Error("Ignoring route update: failed to get link by name")
		return gateways
	}

	// If this route is relevant to our interface and there is a gateway then add it
	if r.LinkIndex == link.Attrs().Index && len(r.Gw) > 0 {
		gwAddr, ok := netip.AddrFromSlice(r.Gw)
		if !ok {
			t.l.WithField("route", r).Debug("Ignoring route update, invalid gateway address")
		} else {
			gwAddr = gwAddr.Unmap()

			if !t.isGatewayInVpnNetworks(gwAddr) {
				t.l.WithField("route", r).Debug("Ignoring route update, not in our network")
			} else {
				gateways = append(gateways, routing.NewGateway(gwAddr, 1))
			}
		}
	}

	for _, p := range r.MultiPath {
		if p.LinkIndex == link.Attrs().Index && len(p.Gw) > 0 {
			gwAddr, ok := netip.AddrFromSlice(p.Gw)
			if !ok {
				t.l.WithField("route", r).Debug("Ignoring multipath route update, invalid gateway address")
			} else {
				gwAddr = gwAddr.Unmap()

				if !t.isGatewayInVpnNetworks(gwAddr) {
					t.l.WithField("route", r).Debug("Ignoring route update, not in our network")
				} else {
					gateways = append(gateways, routing.NewGateway(gwAddr, p.Hops+1))
				}
			}
		}
	}

	routing.CalculateBucketsForGateways(gateways)
	return gateways
}

func (t *wgTun) isGatewayInVpnNetworks(gwAddr netip.Addr) bool {
	for i := range t.vpnNetworks {
		if t.vpnNetworks[i].Contains(gwAddr) {
			return true
		}
	}
	return false
}

func ioctl(a1, a2, a3 uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, a1, a2, a3)
	if errno != 0 {
		return errno
	}
	return nil
}
