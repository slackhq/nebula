//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package overlay

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/util"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type tun struct {
	io.ReadWriteCloser
	fd          int
	Device      string
	cidr        *net.IPNet
	MaxMTU      int
	DefaultMTU  int
	TXQueueLen  int
	deviceIndex int

	Routes          atomic.Pointer[[]Route]
	routeTree       atomic.Pointer[cidr.Tree4[iputil.VpnIp]]
	routeChan       chan struct{}
	useSystemRoutes bool

	l *logrus.Logger
}

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [8]byte
}

type ifreqAddr struct {
	Name [16]byte
	Addr unix.RawSockaddrInet4
	pad  [8]byte
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

func newTunFromFd(c *config.C, l *logrus.Logger, deviceFd int, cidr *net.IPNet) (*tun, error) {
	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")

	t, err := newTunGeneric(c, l, file, cidr)
	if err != nil {
		return nil, err
	}

	t.Device = "tun0"

	return t, nil
}

func newTun(c *config.C, l *logrus.Logger, cidr *net.IPNet, multiqueue bool) (*tun, error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
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
	t, err := newTunGeneric(c, l, file, cidr)
	if err != nil {
		return nil, err
	}

	t.Device = name

	return t, nil
}

func newTunGeneric(c *config.C, l *logrus.Logger, file *os.File, cidr *net.IPNet) (*tun, error) {
	t := &tun{
		ReadWriteCloser: file,
		fd:              int(file.Fd()),
		cidr:            cidr,
		DefaultMTU:      c.GetInt("tun.mtu", DefaultMTU),
		TXQueueLen:      c.GetInt("tun.tx_queue", 500),
		useSystemRoutes: c.GetBool("tun.use_system_route_table", false),
		l:               l,
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
	routes, err := getAllRoutesFromConfig(c, t.cidr)
	if err != nil {
		return err
	}

	if !initial && !change {
		return nil
	}

	routeTree, err := makeRouteTree(t.l, routes, true)
	if err != nil {
		return err
	}

	for i, r := range routes {
		if r.MTU == 0 {
			//TODO: This was horribly broken before, I have doubts anyone is using it
			routes[i].MTU = t.DefaultMTU
		}

		if r.MTU > t.MaxMTU {
			//TODO: This needs to be atomic but it is not used so maybe its fine?
			//TODO: this is also not handled since it would adjust the main route and device mtu
			t.MaxMTU = r.MTU
		}
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
	req.Flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
	copy(req.Name[:], t.Device)
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "/dev/net/tun")

	return file, nil
}

func (t *tun) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	_, r := t.routeTree.Load().MostSpecificContains(ip)
	return r
}

func (t *tun) Write(b []byte) (int, error) {
	var nn int
	max := len(b)

	for {
		n, err := unix.Write(t.fd, b[nn:max])
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

func (t *tun) Activate() error {
	devName := t.deviceBytes()

	if t.useSystemRoutes {
		t.watchRoutes()
	}

	var addr, mask [4]byte

	copy(addr[:], t.cidr.IP.To4())
	copy(mask[:], t.cidr.Mask)

	s, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		unix.IPPROTO_IP,
	)
	if err != nil {
		return err
	}
	fd := uintptr(s)

	ifra := ifreqAddr{
		Name: devName,
		Addr: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   addr,
		},
	}

	// Set the device ip address
	if err = ioctl(fd, unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifra))); err != nil {
		return fmt.Errorf("failed to set tun address: %s", err)
	}

	// Set the device network
	ifra.Addr.Addr = mask
	if err = ioctl(fd, unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifra))); err != nil {
		return fmt.Errorf("failed to set tun netmask: %s", err)
	}

	// Set the device name
	ifrf := ifReq{Name: devName}
	if err = ioctl(fd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to set tun device name: %s", err)
	}

	// Set the MTU on the device
	ifm := ifreqMTU{Name: devName, MTU: int32(t.MaxMTU)}
	if err = ioctl(fd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifm))); err != nil {
		// This is currently a non fatal condition because the route table must have the MTU set appropriately as well
		t.l.WithError(err).Error("Failed to set tun mtu")
	}

	// Set the transmit queue length
	ifrq := ifreqQLEN{Name: devName, Value: int32(t.TXQueueLen)}
	if err = ioctl(fd, unix.SIOCSIFTXQLEN, uintptr(unsafe.Pointer(&ifrq))); err != nil {
		// If we can't set the queue length nebula will still work but it may lead to packet loss
		t.l.WithError(err).Error("Failed to set tun tx queue length")
	}

	// Bring up the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to bring the tun device up: %s", err)
	}

	// Set the routes
	link, err := netlink.LinkByName(t.Device)
	if err != nil {
		return fmt.Errorf("failed to get tun device link: %s", err)
	}

	t.deviceIndex = link.Attrs().Index

	// Default route
	dr := &net.IPNet{IP: t.cidr.IP.Mask(t.cidr.Mask), Mask: t.cidr.Mask}
	nr := netlink.Route{
		LinkIndex: t.deviceIndex,
		Dst:       dr,
		MTU:       t.DefaultMTU,
		AdvMSS:    t.advMSS(Route{}),
		Scope:     unix.RT_SCOPE_LINK,
		Src:       t.cidr.IP,
		Protocol:  unix.RTPROT_KERNEL,
		Table:     unix.RT_TABLE_MAIN,
		Type:      unix.RTN_UNICAST,
	}
	err = netlink.RouteReplace(&nr)
	if err != nil {
		return fmt.Errorf("failed to set mtu %v on the default route %v; %v", t.DefaultMTU, dr, err)
	}

	err = t.addRoutes(false)
	if err != nil {
		return err
	}

	// Run the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to run tun device: %s", err)
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

		nr := netlink.Route{
			LinkIndex: t.deviceIndex,
			Dst:       r.Cidr,
			MTU:       r.MTU,
			AdvMSS:    t.advMSS(r),
			Scope:     unix.RT_SCOPE_LINK,
		}

		if r.Metric > 0 {
			nr.Priority = r.Metric
		}

		err := netlink.RouteReplace(&nr)
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

func (t *tun) removeRoutes(routes []Route) {
	for _, r := range routes {
		if !r.Install {
			continue
		}

		nr := netlink.Route{
			LinkIndex: t.deviceIndex,
			Dst:       r.Cidr,
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

func (t *tun) Cidr() *net.IPNet {
	return t.cidr
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

	if err := netlink.RouteSubscribe(rch, doneChan); err != nil {
		t.l.WithError(err).Errorf("failed to subscribe to system route changes")
		return
	}

	t.routeChan = doneChan

	go func() {
		for {
			select {
			case r := <-rch:
				t.updateRoutes(r)
			case <-doneChan:
				// netlink.RouteSubscriber will close the rch for us
				return
			}
		}
	}()
}

func (t *tun) updateRoutes(r netlink.RouteUpdate) {
	if r.Gw == nil {
		// Not a gateway route, ignore
		t.l.WithField("route", r).Debug("Ignoring route update, not a gateway route")
		return
	}

	if !t.cidr.Contains(r.Gw) {
		// Gateway isn't in our overlay network, ignore
		t.l.WithField("route", r).Debug("Ignoring route update, not in our network")
		return
	}

	if x := r.Dst.IP.To4(); x == nil {
		// Nebula only handles ipv4 on the overlay currently
		t.l.WithField("route", r).Debug("Ignoring route update, destination is not ipv4")
		return
	}

	newTree := cidr.NewTree4[iputil.VpnIp]()
	if r.Type == unix.RTM_NEWROUTE {
		for _, oldR := range t.routeTree.Load().List() {
			newTree.AddCIDR(oldR.CIDR, oldR.Value)
		}

		t.l.WithField("destination", r.Dst).WithField("via", r.Gw).Info("Adding route")
		newTree.AddCIDR(r.Dst, iputil.Ip2VpnIp(r.Gw))

	} else {
		gw := iputil.Ip2VpnIp(r.Gw)
		for _, oldR := range t.routeTree.Load().List() {
			if bytes.Equal(oldR.CIDR.IP, r.Dst.IP) && bytes.Equal(oldR.CIDR.Mask, r.Dst.Mask) && oldR.Value == gw {
				// This is the record to delete
				t.l.WithField("destination", r.Dst).WithField("via", r.Gw).Info("Removing route")
				continue
			}

			newTree.AddCIDR(oldR.CIDR, oldR.Value)
		}
	}

	t.routeTree.Store(newTree)
}

func (t *tun) Close() error {
	if t.routeChan != nil {
		close(t.routeChan)
	}

	if t.ReadWriteCloser != nil {
		t.ReadWriteCloser.Close()
	}

	return nil
}
