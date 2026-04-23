//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package overlay

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// tunFile wraps a TUN file descriptor with poll-based reads. The FD provided will be changed to non-blocking.
// A shared eventfd allows Close to wake all readers blocked in poll.
type tunFile struct {
	fd         int
	shutdownFd int
	lastOne    bool
	readPoll   [2]unix.PollFd
	writePoll  [2]unix.PollFd
	closed     bool
}

// newFriend makes a tunFile for a MultiQueueReader that copies the shutdown eventfd from the parent tun
func (r *tunFile) newFriend(fd int) (*tunFile, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("failed to set tun fd non-blocking: %w", err)
	}
	return &tunFile{
		fd:         fd,
		shutdownFd: r.shutdownFd,
		readPoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(r.shutdownFd), Events: unix.POLLIN},
		},
		writePoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLOUT},
			{Fd: int32(r.shutdownFd), Events: unix.POLLIN},
		},
	}, nil
}

func newTunFd(fd int) (*tunFile, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("failed to set tun fd non-blocking: %w", err)
	}

	shutdownFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("failed to create eventfd: %w", err)
	}

	out := &tunFile{
		fd:         fd,
		shutdownFd: shutdownFd,
		lastOne:    true,
		readPoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
		writePoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLOUT},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
	}

	return out, nil
}

func (r *tunFile) blockOnRead() error {
	const problemFlags = unix.POLLHUP | unix.POLLNVAL | unix.POLLERR
	var err error
	for {
		_, err = unix.Poll(r.readPoll[:], -1)
		if err != unix.EINTR {
			break
		}
	}
	//always reset these!
	tunEvents := r.readPoll[0].Revents
	shutdownEvents := r.readPoll[1].Revents
	r.readPoll[0].Revents = 0
	r.readPoll[1].Revents = 0
	//do the err check before trusting the potentially bogus bits we just got
	if err != nil {
		return err
	}
	if shutdownEvents&(unix.POLLIN|problemFlags) != 0 {
		return os.ErrClosed
	} else if tunEvents&problemFlags != 0 {
		return os.ErrClosed
	}
	return nil
}

func (r *tunFile) blockOnWrite() error {
	const problemFlags = unix.POLLHUP | unix.POLLNVAL | unix.POLLERR
	var err error
	for {
		_, err = unix.Poll(r.writePoll[:], -1)
		if err != unix.EINTR {
			break
		}
	}
	//always reset these!
	tunEvents := r.writePoll[0].Revents
	shutdownEvents := r.writePoll[1].Revents
	r.writePoll[0].Revents = 0
	r.writePoll[1].Revents = 0
	//do the err check before trusting the potentially bogus bits we just got
	if err != nil {
		return err
	}
	if shutdownEvents&(unix.POLLIN|problemFlags) != 0 {
		return os.ErrClosed
	} else if tunEvents&problemFlags != 0 {
		return os.ErrClosed
	}
	return nil
}

func (r *tunFile) Read(buf []byte) (int, error) {
	for {
		if n, err := unix.Read(r.fd, buf); err == nil {
			return n, nil
		} else if err == unix.EAGAIN {
			if err = r.blockOnRead(); err != nil {
				return 0, err
			}
			continue
		} else if err == unix.EINTR {
			continue
		} else if err == unix.EBADF {
			return 0, os.ErrClosed
		} else {
			return 0, err
		}
	}
}

func (r *tunFile) Write(buf []byte) (int, error) {
	for {
		if n, err := unix.Write(r.fd, buf); err == nil {
			return n, nil
		} else if err == unix.EAGAIN {
			if err = r.blockOnWrite(); err != nil {
				return 0, err
			}
			continue
		} else if err == unix.EINTR {
			continue
		} else if err == unix.EBADF {
			return 0, os.ErrClosed
		} else {
			return 0, err
		}
	}
}

func (r *tunFile) wakeForShutdown() error {
	var buf [8]byte
	binary.NativeEndian.PutUint64(buf[:], 1)
	_, err := unix.Write(int(r.readPoll[1].Fd), buf[:])
	return err
}

func (r *tunFile) Close() error {
	if r.closed { // avoid closing more than once. Technically a fd could get re-used, which would be a problem
		return nil
	}
	r.closed = true
	if r.lastOne {
		_ = unix.Close(r.shutdownFd)
	}
	return unix.Close(r.fd)
}

type tun struct {
	*tunFile
	readers     []*tunFile
	closeLock   sync.Mutex
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

	l *slog.Logger
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

func newTunFromFd(c *config.C, l *slog.Logger, deviceFd int, vpnNetworks []netip.Prefix) (*tun, error) {
	t, err := newTunGeneric(c, l, deviceFd, vpnNetworks)
	if err != nil {
		return nil, err
	}

	t.Device = "tun0"

	return t, nil
}

func newTun(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, multiqueue bool) (*tun, error) {
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
	nameStr := c.GetString("tun.dev", "")
	copy(req.Name[:], nameStr)
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		_ = unix.Close(fd)
		return nil, &NameError{
			Name:       nameStr,
			Underlying: err,
		}
	}
	name := strings.Trim(string(req.Name[:]), "\x00")

	t, err := newTunGeneric(c, l, fd, vpnNetworks)
	if err != nil {
		return nil, err
	}

	t.Device = name

	return t, nil
}

// newTunGeneric does all the stuff common to different tun initialization paths. It will close your files on error.
func newTunGeneric(c *config.C, l *slog.Logger, fd int, vpnNetworks []netip.Prefix) (*tun, error) {
	tfd, err := newTunFd(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	t := &tun{
		tunFile:                   tfd,
		readers:                   []*tunFile{tfd},
		closeLock:                 sync.Mutex{},
		vpnNetworks:               vpnNetworks,
		TXQueueLen:                c.GetInt("tun.tx_queue", 500),
		useSystemRoutes:           c.GetBool("tun.use_system_route_table", false),
		useSystemRoutesBufferSize: c.GetInt("tun.use_system_route_table_buffer_size", 0),
		routesFromSystem:          map[netip.Prefix]routing.Gateways{},
		l:                         l,
	}

	if err = t.reload(c, true); err != nil {
		_ = t.Close()
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
			t.l.Info("Set max MTU", "mtu", t.MaxMTU, "oldMTU", oldMaxMTU)
		}

		if oldDefaultMTU != newDefaultMTU {
			for i := range t.vpnNetworks {
				err := t.setDefaultRoute(t.vpnNetworks[i])
				if err != nil {
					t.l.Warn(err.Error())
				} else {
					t.l.Info("Set default MTU", "mtu", t.DefaultMTU, "oldMTU", oldDefaultMTU)
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
	t.closeLock.Lock()
	defer t.closeLock.Unlock()

	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var req ifReq
	req.Flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
	copy(req.Name[:], t.Device)
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	out, err := t.tunFile.newFriend(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	t.readers = append(t.readers, out)

	return out, nil
}

func (t *tun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
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
			t.l.Error("failed to remove address from tun address list", "error", err)
		} else {
			t.l.Info("removed address not listed in cert(s)", "removed", al[i].String())
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
		t.l.Error("Failed to set tun tx queue length", "error", err)
	}

	const modeNone = 1
	if err = netlink.LinkSetIP6AddrGenMode(link, modeNone); err != nil {
		t.l.Warn("Failed to disable link local address generation", "error", err)
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
		t.l.Error("Failed to set tun mtu", "error", err)
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
		t.l.Warn("Failed to set default route MTU, retrying", "error", err, "cidr", cidr)
		//retry twice more -- on some systems there appears to be a race condition where if we set routes too soon, netlink says `invalid argument`
		for i := 0; i < 2; i++ {
			time.Sleep(100 * time.Millisecond)
			err = netlink.RouteReplace(&nr)
			if err == nil {
				break
			} else {
				t.l.Warn("Failed to set default route MTU, retrying",
					"error", err,
					"cidr", cidr,
					"mtu", t.DefaultMTU,
				)
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
			t.l.Info("Added route", "route", r)
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
			t.l.Error("Failed to remove route", "error", err, "route", r)
		} else {
			t.l.Info("Removed route", "route", r)
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
		ErrorCallback:          func(e error) { t.l.Error("netlink error", "error", e) },
	}

	if err := netlink.RouteSubscribeWithOptions(rch, doneChan, netlinkOptions); err != nil {
		t.l.Error("failed to subscribe to system route changes", "error", err)
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
		t.l.Error("Ignoring route update: failed to get link by name", "deviceName", t.Device)
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
				t.l.Debug("Ignoring route update, gateway is not in our network", "route", r)
			}
		} else {
			t.l.Debug("Ignoring route update, invalid gateway or via address", "route", r)
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
					t.l.Debug("Ignoring route update, gateway is not in our network", "route", r)
				}
			} else {
				t.l.Debug("Ignoring route update, invalid gateway or via address", "route", r)
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
		t.l.Debug("Ignoring route update, no gateways", "route", r)
		return
	}

	if r.Dst == nil {
		t.l.Debug("Ignoring route update, no destination address", "route", r)
		return
	}

	dstAddr, ok := netip.AddrFromSlice(r.Dst.IP)
	if !ok {
		t.l.Debug("Ignoring route update, invalid destination address", "route", r)
		return
	}

	ones, _ := r.Dst.Mask.Size()
	dst := netip.PrefixFrom(dstAddr, ones)

	newTree := t.routeTree.Load().Clone()

	t.routesFromSystemLock.Lock()
	if r.Type == unix.RTM_NEWROUTE {
		t.l.Info("Adding route", "destination", dst, "via", gateways)
		t.routesFromSystem[dst] = gateways
		newTree.Insert(dst, gateways)

	} else {
		t.l.Info("Removing route", "destination", dst, "via", gateways)
		delete(t.routesFromSystem, dst)
		newTree.Delete(dst)
	}
	t.routesFromSystemLock.Unlock()
	t.routeTree.Store(newTree)
}

func (t *tun) Close() error {
	t.closeLock.Lock()
	defer t.closeLock.Unlock()

	if t.routeChan != nil {
		close(t.routeChan)
		t.routeChan = nil
	}

	// Signal all readers blocked in poll to wake up and exit
	_ = t.tunFile.wakeForShutdown()

	if t.ioctlFd > 0 {
		_ = unix.Close(int(t.ioctlFd))
		t.ioctlFd = 0
	}

	for i := range t.readers {
		if i == 0 {
			continue //we want to close the zeroth reader last
		}
		err := t.readers[i].Close()
		if err != nil {
			t.l.Error("error closing tun reader", "reader", i, "error", err)
		} else {
			t.l.Info("closed tun reader", "reader", i)
		}
	}

	//this is t.readers[0] too
	err := t.tunFile.Close()
	if err != nil {
		t.l.Error("error closing tun reader", "reader", 0, "error", err)
	} else {
		t.l.Info("closed tun reader", "reader", 0)
	}
	return err
}
