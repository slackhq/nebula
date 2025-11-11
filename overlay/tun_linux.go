//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
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
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type tun struct {
	io.ReadWriteCloser
	wgDevice    wgtun.Device
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

const (
	virtioNetHdrLen = 10 // Size of virtio_net_hdr structure
)

// wgDeviceWrapper wraps a wireguard Device to implement io.ReadWriteCloser
// This allows multiqueue readers to use the same wireguard Device batching as the main device
type wgDeviceWrapper struct {
	dev wgtun.Device
	buf []byte // Reusable buffer for single packet reads
}

func (w *wgDeviceWrapper) Read(b []byte) (int, error) {
	// Use wireguard Device's batch API for single packet
	bufs := [][]byte{b}
	sizes := make([]int, 1)
	n, err := w.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return sizes[0], nil
}

func (w *wgDeviceWrapper) Write(b []byte) (int, error) {
	// Allocate buffer with space for virtio header
	buf := make([]byte, virtioNetHdrLen+len(b))
	copy(buf[virtioNetHdrLen:], b)

	bufs := [][]byte{buf}
	n, err := w.dev.Write(bufs, virtioNetHdrLen)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

func (w *wgDeviceWrapper) Close() error {
	return w.dev.Close()
}

// BatchRead implements batching for multiqueue readers
func (w *wgDeviceWrapper) BatchRead(bufs [][]byte, sizes []int) (int, error) {
	return w.dev.Read(bufs, sizes, 0)
}

// BatchSize returns the optimal batch size
func (w *wgDeviceWrapper) BatchSize() int {
	return w.dev.BatchSize()
}

func newTunFromFd(c *config.C, l *logrus.Logger, deviceFd int, vpnNetworks []netip.Prefix) (*tun, error) {
	wgDev, name, err := wgtun.CreateUnmonitoredTUNFromFD(deviceFd)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN from FD: %w", err)
	}

	file := wgDev.File()
	t, err := newTunGeneric(c, l, file, vpnNetworks)
	if err != nil {
		_ = wgDev.Close()
		return nil, err
	}

	t.wgDevice = wgDev
	t.Device = name

	return t, nil
}

func newTun(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, multiqueue bool) (*tun, error) {
	// Check if /dev/net/tun exists, create if needed (for docker containers)
	if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
		if err := os.MkdirAll("/dev/net", 0755); err != nil {
			return nil, fmt.Errorf("/dev/net/tun doesn't exist, failed to mkdir -p /dev/net: %w", err)
		}
		if err := unix.Mknod("/dev/net/tun", unix.S_IFCHR|0600, int(unix.Mkdev(10, 200))); err != nil {
			return nil, fmt.Errorf("failed to create /dev/net/tun: %w", err)
		}
	}

	devName := c.GetString("tun.dev", "")
	mtu := c.GetInt("tun.mtu", DefaultMTU)

	// Create TUN device manually to support multiqueue
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var req ifReq
	req.Flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if multiqueue {
		req.Flags |= unix.IFF_MULTI_QUEUE
	}
	copy(req.Name[:], devName)
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		unix.Close(fd)
		return nil, err
	}

	// Set nonblocking
	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}

	// Enable TCP and UDP offload (TSO/GRO) for performance
	// This allows the kernel to handle segmentation/coalescing
	const (
		tunTCPOffloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
		tunUDPOffloads = unix.TUN_F_USO4 | unix.TUN_F_USO6
	)
	offloads := tunTCPOffloads | tunUDPOffloads
	if err = unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, offloads); err != nil {
		// Log warning but don't fail - offload is optional
		l.WithError(err).Warn("Failed to enable TUN offload (TSO/GRO), performance may be reduced")
	}

	file := os.NewFile(uintptr(fd), "/dev/net/tun")

	// Create wireguard device from file descriptor
	wgDev, err := wgtun.CreateTUNFromFile(file, mtu)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create TUN from file: %w", err)
	}

	name, err := wgDev.Name()
	if err != nil {
		_ = wgDev.Close()
		return nil, fmt.Errorf("failed to get TUN device name: %w", err)
	}

	// file is now owned by wgDev, get a new reference
	file = wgDev.File()
	t, err := newTunGeneric(c, l, file, vpnNetworks)
	if err != nil {
		_ = wgDev.Close()
		return nil, err
	}

	t.wgDevice = wgDev
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

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var req ifReq
	// MUST match the flags used in newTun - includes IFF_VNET_HDR
	req.Flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_MULTI_QUEUE)
	copy(req.Name[:], t.Device)
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		unix.Close(fd)
		return nil, err
	}

	// Set nonblocking mode - CRITICAL for proper netpoller integration
	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}

	// Get MTU from main device
	mtu := t.MaxMTU
	if mtu == 0 {
		mtu = DefaultMTU
	}

	file := os.NewFile(uintptr(fd), "/dev/net/tun")

	// Create wireguard Device from the file descriptor (just like the main device)
	wgDev, err := wgtun.CreateTUNFromFile(file, mtu)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create multiqueue TUN device: %w", err)
	}

	// Return a wrapper that uses the wireguard Device for all I/O
	return &wgDeviceWrapper{dev: wgDev}, nil
}

func (t *tun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
}

func (t *tun) Read(b []byte) (int, error) {
	if t.wgDevice != nil {
		// Use wireguard device which handles virtio headers internally
		bufs := [][]byte{b}
		sizes := make([]int, 1)
		n, err := t.wgDevice.Read(bufs, sizes, 0)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return sizes[0], nil
	}

	// Fallback: direct read from file (shouldn't happen in normal operation)
	return t.ReadWriteCloser.Read(b)
}

// BatchRead reads multiple packets at once for improved performance
// bufs: slice of buffers to read into
// sizes: slice that will be filled with packet sizes
// Returns number of packets read
func (t *tun) BatchRead(bufs [][]byte, sizes []int) (int, error) {
	if t.wgDevice != nil {
		return t.wgDevice.Read(bufs, sizes, 0)
	}

	// Fallback: single packet read
	n, err := t.ReadWriteCloser.Read(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// BatchSize returns the optimal number of packets to read/write in a batch
func (t *tun) BatchSize() int {
	if t.wgDevice != nil {
		return t.wgDevice.BatchSize()
	}
	return 1
}

func (t *tun) Write(b []byte) (int, error) {
	if t.wgDevice != nil {
		// Use wireguard device which handles virtio headers internally
		// Allocate buffer with space for virtio header
		buf := make([]byte, virtioNetHdrLen+len(b))
		copy(buf[virtioNetHdrLen:], b)

		bufs := [][]byte{buf}
		n, err := t.wgDevice.Write(bufs, virtioNetHdrLen)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.ErrShortWrite
		}
		return len(b), nil
	}

	// Fallback: direct write (shouldn't happen in normal operation)
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
		t.l.WithField("Devicename", t.Device).Error("Ignoring route update: failed to get link by name")
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
				// Gateway isn't in our overlay network, ignore
				t.l.WithField("route", r).Debug("Ignoring route update, not in our network")
			} else {
				gateways = append(gateways, routing.NewGateway(gwAddr, 1))
			}
		}
	}

	for _, p := range r.MultiPath {
		// If this route is relevant to our interface and there is a gateway then add it
		if p.LinkIndex == link.Attrs().Index && len(p.Gw) > 0 {
			gwAddr, ok := netip.AddrFromSlice(p.Gw)
			if !ok {
				t.l.WithField("route", r).Debug("Ignoring multipath route update, invalid gateway address")
			} else {
				gwAddr = gwAddr.Unmap()

				if !t.isGatewayInVpnNetworks(gwAddr) {
					// Gateway isn't in our overlay network, ignore
					t.l.WithField("route", r).Debug("Ignoring route update, not in our network")
				} else {
					// p.Hops+1 = weight of the route
					gateways = append(gateways, routing.NewGateway(gwAddr, p.Hops+1))
				}
			}
		}
	}

	routing.CalculateBucketsForGateways(gateways)
	return gateways
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

	if r.Type == unix.RTM_NEWROUTE {
		t.l.WithField("destination", dst).WithField("via", gateways).Info("Adding route")
		newTree.Insert(dst, gateways)

	} else {
		t.l.WithField("destination", dst).WithField("via", gateways).Info("Removing route")
		newTree.Delete(dst)
	}
	t.routeTree.Store(newTree)
}

func (t *tun) Close() error {
	if t.routeChan != nil {
		close(t.routeChan)
	}

	if t.wgDevice != nil {
		_ = t.wgDevice.Close()
	}

	if t.ReadWriteCloser != nil {
		_ = t.ReadWriteCloser.Close()
	}

	if t.ioctlFd > 0 {
		_ = os.NewFile(t.ioctlFd, "ioctlFd").Close()
	}

	return nil
}
