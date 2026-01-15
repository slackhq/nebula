//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type tun struct {
	io.ReadWriteCloser
	fd          int
	Device      string
	vpnNetworks []netip.Prefix
	MaxMTU      int
	DefaultMTU  int
	TXQueueLen  int
	deviceIndex int
	ioctlFd     uintptr

	Routes                    atomic.Pointer[[]Route]
	routeTree                 atomic.Pointer[bart.Table[routing.Gateways]]
	routeChan                 chan struct{}
	useSystemRoutes           bool
	useSystemRoutesBufferSize int

	// These are routes learned from `tun.use_system_route_table`
	// stored here to make it easier to restore them after a reload
	routesFromSystem     map[netip.Prefix]routing.Gateways
	routesFromSystemLock sync.Mutex

	l *logrus.Logger
}

func (t *tun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [8]byte
}

type ifreqMTU struct {
	Name [16]byte
	MTU  int32
	pad  [8]byte
}

type ifreqQLEN struct {
	Name  [16]byte
	Value int32
	pad   [8]byte
}

func newTunFromFd(c *config.C, l *logrus.Logger, deviceFd int, vpnNetworks []netip.Prefix) (*tun, error) {
	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")

	t, err := newTunGeneric(c, l, file, vpnNetworks)
	if err != nil {
		return nil, err
	}

	t.Device = "tun0"

	return t, nil
}

func newTun(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, multiqueue bool) (*tun, error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		// If /dev/net/tun doesn't exist, try to create it (will happen in docker)
		if os.IsNotExist(err) {
			err = os.MkdirAll("/dev/net", 0755)
			if err != nil {
				return nil, fmt.Errorf("/dev/net/tun doesn't exist, failed to mkdir -p /dev/net: %w", err)
			}
			err = unix.Mknod("/dev/net/tun", unix.S_IFCHR|0600, int(unix.Mkdev(10, 200)))
			if err != nil {
				return nil, fmt.Errorf("failed to create /dev/net/tun: %w", err)
			}

			fd, err = unix.Open("/dev/net/tun", os.O_RDWR, 0)
			if err != nil {
				return nil, fmt.Errorf("created /dev/net/tun, but still failed: %w", err)
			}
		} else {
			return nil, err
		}
	}

	var req ifReq
	req.Flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if multiqueue {
		req.Flags |= unix.IFF_MULTI_QUEUE
	}
	copy(req.Name[:], c.GetString("tun.dev", ""))
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		return nil, err
	}
	name := strings.Trim(string(req.Name[:]), "\x00")

	file := os.NewFile(uintptr(fd), "/dev/net/tun")
	t, err := newTunGeneric(c, l, file, vpnNetworks)
	if err != nil {
		return nil, err
	}

	t.Device = name

	return t, nil
}

func newTunGeneric(c *config.C, l *logrus.Logger, file *os.File, vpnNetworks []netip.Prefix) (*tun, error) {
	t := &tun{
		ReadWriteCloser:           file,
		fd:                        int(file.Fd()),
		vpnNetworks:               vpnNetworks,
		TXQueueLen:                c.GetInt("tun.tx_queue", 500),
		useSystemRoutes:           c.GetBool("tun.use_system_route_table", false),
		useSystemRoutesBufferSize: c.GetInt("tun.use_system_route_table_buffer_size", 0),
		l:                         l,
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

func (t *tun) reload(c *config.C, initial bool) error {
	routeChange, routes, err := getAllRoutesFromConfig(c, t.vpnNetworks, initial)
	if err != nil {
		return err
	}

	if !initial && !routeChange && !c.HasChanged("tun.mtu") {
		return nil
	}

	routeTree, err := makeRouteTree(t.l, routes, true)
	if err != nil {
		return err
	}

	// Bring along any routes learned from the system route table on reload
	t.routesFromSystemLock.Lock()
	for dst, gw := range t.routesFromSystem {
		routeTree.Insert(dst, gw)
	}
	t.routesFromSystemLock.Unlock()

	oldDefaultMTU := t.DefaultMTU
	oldMaxMTU := t.MaxMTU
	newDefaultMTU := c.GetInt("tun.mtu", DefaultMTU)
	newMaxMTU := newDefaultMTU
	for i, r := range routes {
		if r.MTU == 0 {
			routes[i].MTU = newDefaultMTU
		}

		if r.MTU > t.MaxMTU {
			newMaxMTU = r.MTU
		}
	}

	t.MaxMTU = newMaxMTU
	t.DefaultMTU = newDefaultMTU

	// Teach nebula how to handle the routes before establishing them in the system table
	oldRoutes := t.Routes.Swap(&routes)
	t.routeTree.Store(routeTree)

	if !initial {
		if oldMaxMTU != newMaxMTU {
			t.setMTU()
			t.l.Infof("Set max MTU to %v was %v", t.MaxMTU, oldMaxMTU)
		}

		if oldDefaultMTU != newDefaultMTU {
			for i := range t.vpnNetworks {
				err := t.setDefaultRoute(t.vpnNetworks[i])
				if err != nil {
					t.l.Warn(err)
				} else {
					t.l.Infof("Set default MTU to %v was %v", t.DefaultMTU, oldDefaultMTU)
				}
			}
		}

		// Remove first, if the system removes a wanted route hopefully it will be re-added next
		t.removeRoutes(findRemovedRoutes(routes, *oldRoutes))

		// Ensure any routes we actually want are installed
		err = t.addRoutes(true)
		if err != nil {
			// This should never be called since addRoutes should log its own errors in a reload condition
			util.LogWithContextIfNeeded("Failed to refresh routes", err, t.l)
		}
	}

	return nil
}

func (t *tun) SupportsMultiqueue() bool {
	return true
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var req ifReq
	req.Flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
	copy(req.Name[:], t.Device)
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "/dev/net/tun")

	return file, nil
}

func (t *tun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
}

func (t *tun) Write(b []byte) (int, error) {
	var nn int
	maximum := len(b)

	for {
		n, err := unix.Write(t.fd, b[nn:maximum])
		if n > 0 {
			nn += n
		}
		if nn == len(b) {
			return nn, err
		}

		if err != nil {
			return nn, err
		}

		if n == 0 {
			return nn, io.ErrUnexpectedEOF
		}
	}
}

func (t *tun) deviceBytes() (o [16]byte) {
	for i, c := range t.Device {
		o[i] = byte(c)
	}
	return
}

func hasNetlinkAddr(al []*netlink.Addr, x netlink.Addr) bool {
	for i := range al {
		if al[i].Equal(x) {
			return true
		}
	}
	return false
}

// addIPs uses netlink to add all addresses that don't exist, then it removes ones that should not be there
func (t *tun) addIPs(link netlink.Link) error {
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

	//add all new addresses
	for i := range newAddrs {
		//AddrReplace still adds new IPs, but if their properties change it will change them as well
		if err := netlink.AddrReplace(link, newAddrs[i]); err != nil {
			return err
		}
	}

	//iterate over remainder, remove whoever shouldn't be there
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

func (t *tun) Activate() error {
	devName := t.deviceBytes()

	if t.useSystemRoutes {
		t.watchRoutes()
	}

	s, err := unix.Socket(
		unix.AF_INET, //because everything we use t.ioctlFd for is address family independent, this is fine
		unix.SOCK_DGRAM,
		unix.IPPROTO_IP,
	)
	if err != nil {
		return err
	}
	t.ioctlFd = uintptr(s)

	// Set the device name
	ifrf := ifReq{Name: devName}
	if err = ioctl(t.ioctlFd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to set tun device name: %s", err)
	}

	link, err := netlink.LinkByName(t.Device)
	if err != nil {
		return fmt.Errorf("failed to get tun device link: %s", err)
	}

	t.deviceIndex = link.Attrs().Index

	// Setup our default MTU
	t.setMTU()

	// Set the transmit queue length
	ifrq := ifreqQLEN{Name: devName, Value: int32(t.TXQueueLen)}
	if err = ioctl(t.ioctlFd, unix.SIOCSIFTXQLEN, uintptr(unsafe.Pointer(&ifrq))); err != nil {
		// If we can't set the queue length nebula will still work but it may lead to packet loss
		t.l.WithError(err).Error("Failed to set tun tx queue length")
	}

	const modeNone = 1
	if err = netlink.LinkSetIP6AddrGenMode(link, modeNone); err != nil {
		t.l.WithError(err).Warn("Failed to disable link local address generation")
	}

	if err = t.addIPs(link); err != nil {
		return err
	}

	// Bring up the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP
	if err = ioctl(t.ioctlFd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to bring the tun device up: %s", err)
	}

	//set route MTU
	for i := range t.vpnNetworks {
		if err = t.setDefaultRoute(t.vpnNetworks[i]); err != nil {
			return fmt.Errorf("failed to set default route MTU: %w", err)
		}
	}

	// Set the routes
	if err = t.addRoutes(false); err != nil {
		return err
	}

	// Run the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if err = ioctl(t.ioctlFd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to run tun device: %s", err)
	}

	return nil
}

func (t *tun) setMTU() {
	// Set the MTU on the device
	ifm := ifreqMTU{Name: t.deviceBytes(), MTU: int32(t.MaxMTU)}
	if err := ioctl(t.ioctlFd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifm))); err != nil {
		// This is currently a non fatal condition because the route table must have the MTU set appropriately as well
		t.l.WithError(err).Error("Failed to set tun mtu")
	}
}

func (t *tun) setDefaultRoute(cidr netip.Prefix) error {
	dr := &net.IPNet{
		IP:   cidr.Masked().Addr().AsSlice(),
		Mask: net.CIDRMask(cidr.Bits(), cidr.Addr().BitLen()),
	}

	nr := netlink.Route{
		LinkIndex: t.deviceIndex,
		Dst:       dr,
		MTU:       t.DefaultMTU,
		AdvMSS:    t.advMSS(Route{}),
		Scope:     unix.RT_SCOPE_LINK,
		Src:       net.IP(cidr.Addr().AsSlice()),
		Protocol:  unix.RTPROT_KERNEL,
		Table:     unix.RT_TABLE_MAIN,
		Type:      unix.RTN_UNICAST,
	}
	err := netlink.RouteReplace(&nr)
	if err != nil {
		t.l.WithError(err).WithField("cidr", cidr).Warn("Failed to set default route MTU, retrying")
		//retry twice more -- on some systems there appears to be a race condition where if we set routes too soon, netlink says `invalid argument`
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

func (t *tun) addRoutes(logErrors bool) error {
	// Path routes
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
			LinkIndex: t.deviceIndex,
			Dst:       dr,
			MTU:       r.MTU,
			AdvMSS:    t.advMSS(r),
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

func (t *tun) removeRoutes(routes []Route) {
	for _, r := range routes {
		if !r.Install {
			continue
		}

		dr := &net.IPNet{
			IP:   r.Cidr.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(r.Cidr.Bits(), r.Cidr.Addr().BitLen()),
		}

		nr := netlink.Route{
			LinkIndex: t.deviceIndex,
			Dst:       dr,
			MTU:       r.MTU,
			AdvMSS:    t.advMSS(r),
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

func (t *tun) Name() string {
	return t.Device
}

func (t *tun) advMSS(r Route) int {
	mtu := r.MTU
	if r.MTU == 0 {
		mtu = t.DefaultMTU
	}

	// We only need to set advmss if the route MTU does not match the device MTU
	if mtu != t.MaxMTU {
		return mtu - 40
	}
	return 0
}

func (t *tun) watchRoutes() {
	rch := make(chan netlink.RouteUpdate)
	doneChan := make(chan struct{})

	netlinkOptions := netlink.RouteSubscribeOptions{
		ReceiveBufferSize:      t.useSystemRoutesBufferSize,
		ReceiveBufferForceSize: t.useSystemRoutesBufferSize != 0,
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
					// may be should do something here as
					// netlink stops sending updates
					return
				}
			case <-doneChan:
				// netlink.RouteSubscriber will close the rch for us
				return
			}
		}
	}()
}

func (t *tun) isGatewayInVpnNetworks(gwAddr netip.Addr) bool {
	withinNetworks := false
	for i := range t.vpnNetworks {
		if t.vpnNetworks[i].Contains(gwAddr) {
			withinNetworks = true
			break
		}
	}

	return withinNetworks
}

func (t *tun) getGatewaysFromRoute(r *netlink.Route) routing.Gateways {
	var gateways routing.Gateways

	link, err := netlink.LinkByName(t.Device)
	if err != nil {
		t.l.WithField("deviceName", t.Device).Error("Ignoring route update: failed to get link by name")
		return gateways
	}

	// If this route is relevant to our interface and there is a gateway then add it
	if r.LinkIndex == link.Attrs().Index {
		gwAddr, ok := getGatewayAddr(r.Gw, r.Via)
		if ok {
			if t.isGatewayInVpnNetworks(gwAddr) {
				gateways = append(gateways, routing.NewGateway(gwAddr, 1))
			} else {
				// Gateway isn't in our overlay network, ignore
				t.l.WithField("route", r).Debug("Ignoring route update, gateway is not in our network")
			}
		} else {
			t.l.WithField("route", r).Debug("Ignoring route update, invalid gateway or via address")
		}
	}

	for _, p := range r.MultiPath {
		// If this route is relevant to our interface and there is a gateway then add it
		if p.LinkIndex == link.Attrs().Index {
			gwAddr, ok := getGatewayAddr(p.Gw, p.Via)
			if ok {
				if t.isGatewayInVpnNetworks(gwAddr) {
					gateways = append(gateways, routing.NewGateway(gwAddr, p.Hops+1))
				} else {
					// Gateway isn't in our overlay network, ignore
					t.l.WithField("route", r).Debug("Ignoring route update, gateway is not in our network")
				}
			} else {
				t.l.WithField("route", r).Debug("Ignoring route update, invalid gateway or via address")
			}
		}
	}

	routing.CalculateBucketsForGateways(gateways)
	return gateways
}

func getGatewayAddr(gw net.IP, via netlink.Destination) (netip.Addr, bool) {
	// Try to use the old RTA_GATEWAY first
	gwAddr, ok := netip.AddrFromSlice(gw)
	if !ok {
		// Fallback to the new RTA_VIA
		rVia, ok := via.(*netlink.Via)
		if ok {
			gwAddr, ok = netip.AddrFromSlice(rVia.Addr)
		}
	}

	if gwAddr.IsValid() {
		gwAddr = gwAddr.Unmap()
		return gwAddr, true
	}

	return netip.Addr{}, false
}

func (t *tun) updateRoutes(r netlink.RouteUpdate) {
	gateways := t.getGatewaysFromRoute(&r.Route)
	if len(gateways) == 0 {
		// No gateways relevant to our network, no routing changes required.
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

	t.routesFromSystemLock.Lock()
	if r.Type == unix.RTM_NEWROUTE {
		t.l.WithField("destination", dst).WithField("via", gateways).Info("Adding route")
		t.routesFromSystem[dst] = gateways
		newTree.Insert(dst, gateways)

	} else {
		t.l.WithField("destination", dst).WithField("via", gateways).Info("Removing route")
		delete(t.routesFromSystem, dst)
		newTree.Delete(dst)
	}
	t.routesFromSystemLock.Unlock()
	t.routeTree.Store(newTree)
}

func (t *tun) Close() error {
	if t.routeChan != nil {
		close(t.routeChan)
	}

	if t.ReadWriteCloser != nil {
		_ = t.ReadWriteCloser.Close()
	}

	if t.ioctlFd > 0 {
		_ = os.NewFile(t.ioctlFd, "ioctlFd").Close()
	}

	return nil
}
