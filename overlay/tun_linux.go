//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package overlay

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type tun struct {
	io.ReadWriteCloser
	fd         int
	Device     string
	cidr       *net.IPNet
	MaxMTU     int
	DefaultMTU int
	TXQueueLen int

	Routes          []Route
	routeTree       atomic.Pointer[cidr.Tree4]
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

type multiPathRoute struct {
	routes []weightedRoute
}

func (m multiPathRoute) via() string {
	if len(m.routes) == 1 {
		return fmt.Sprint(m.routes[1].gw)
	}
	parts := make([]string, len(m.routes))
	for i, r := range m.routes {
		parts[i] = fmt.Sprintf("%s(%d)", r.gw, r.weight)
	}
	return strings.Join(parts, "|")
}

type weightedRoute struct {
	gw     iputil.VpnIp
	weight int
}

func newTunFromFd(l *logrus.Logger, deviceFd int, cidr *net.IPNet, defaultMTU int, routes []Route, txQueueLen int, useSystemRoutes bool) (*tun, error) {
	routeTree, err := makeRouteTree(l, routes, true)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")

	t := &tun{
		ReadWriteCloser: file,
		fd:              int(file.Fd()),
		Device:          "tun0",
		cidr:            cidr,
		DefaultMTU:      defaultMTU,
		TXQueueLen:      txQueueLen,
		Routes:          routes,
		useSystemRoutes: useSystemRoutes,
		l:               l,
	}
	t.routeTree.Store(routeTree)
	return t, nil
}

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []Route, txQueueLen int, multiqueue bool, useSystemRoutes bool) (*tun, error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var req ifReq
	req.Flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if multiqueue {
		req.Flags |= unix.IFF_MULTI_QUEUE
	}
	copy(req.Name[:], deviceName)
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		return nil, err
	}
	name := strings.Trim(string(req.Name[:]), "\x00")

	file := os.NewFile(uintptr(fd), "/dev/net/tun")

	maxMTU := defaultMTU
	for _, r := range routes {
		if r.MTU == 0 {
			r.MTU = defaultMTU
		}

		if r.MTU > maxMTU {
			maxMTU = r.MTU
		}
	}

	routeTree, err := makeRouteTree(l, routes, true)
	if err != nil {
		return nil, err
	}

	t := &tun{
		ReadWriteCloser: file,
		fd:              int(file.Fd()),
		Device:          name,
		cidr:            cidr,
		MaxMTU:          maxMTU,
		DefaultMTU:      defaultMTU,
		TXQueueLen:      txQueueLen,
		Routes:          routes,
		useSystemRoutes: useSystemRoutes,
		l:               l,
	}
	t.routeTree.Store(routeTree)
	return t, nil
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

func (t *tun) RoutesFor(ip iputil.VpnIp) []iputil.VpnIp {
	r := t.routeTree.Load().MostSpecificContains(ip)
	switch v := r.(type) {
	case iputil.VpnIp:
		return []iputil.VpnIp{v}
	case multiPathRoute:
		routes := make([]weightedRoute, len(v.routes))
		vpnIps := make([]iputil.VpnIp, 0, len(routes))
		copy(routes, v.routes)
		sort.Slice(routes, func(i, j int) bool {
			// Randomize equal weight routes
			if routes[i].weight == routes[j].weight {
				rn, err := rand.Int(rand.Reader, big.NewInt(2))
				if err != nil {
					return false
				}
				return rn.Int64() == 0
			}
			// Highest weight preferred
			return routes[i].weight > routes[j].weight
		})

		for _, r := range routes {
			vpnIps = append(vpnIps, r.gw)
		}
		return vpnIps
	default:
		return nil
	}
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

	// Default route
	dr := &net.IPNet{IP: t.cidr.IP.Mask(t.cidr.Mask), Mask: t.cidr.Mask}
	nr := netlink.Route{
		LinkIndex: link.Attrs().Index,
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

	// Path routes
	for _, r := range t.Routes {
		if !r.Install {
			continue
		}

		nr := netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       r.Cidr,
			MTU:       r.MTU,
			AdvMSS:    t.advMSS(r),
			Scope:     unix.RT_SCOPE_LINK,
		}

		if r.Metric > 0 {
			nr.Priority = r.Metric
		}

		err = netlink.RouteAdd(&nr)
		if err != nil {
			return fmt.Errorf("failed to set mtu %v on route %v; %v", r.MTU, r.Cidr, err)
		}
	}

	// Run the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to run tun device: %s", err)
	}

	return nil
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
	var routes []weightedRoute
	if len(r.Gw) > 0 {
		routes = append(routes, weightedRoute{gw: iputil.Ip2VpnIp(r.Gw)})
	}
	for _, p := range r.MultiPath {
		if len(p.Gw) > 0 {
			routes = append(routes, weightedRoute{gw: iputil.Ip2VpnIp(p.Gw), weight: p.Hops + 1})
		}
	}

	mpr := multiPathRoute{
		routes: make([]weightedRoute, 0, len(routes)),
	}
	for _, route := range routes {
		if !t.cidr.Contains(route.gw.ToIP()) {
			// Gateway isn't in our overlay network, ignore
			t.l.WithField("gw", route.gw).Debug("Ignoring route gateway, not in our network")
			continue
		}
		mpr.routes = append(mpr.routes, route)
	}

	if len(mpr.routes) == 0 {
		t.l.WithField("route", r).Debug("Ignoring route update, no remaining gateways")
		return
	}

	if x := r.Dst.IP.To4(); x == nil {
		// Nebula only handles ipv4 on the overlay currently
		t.l.WithField("route", r).Debug("Ignoring route update, destination is not ipv4")
		return
	}

	sort.Slice(mpr.routes, func(i, j int) bool {
		if mpr.routes[i].weight == mpr.routes[j].weight {
			return mpr.routes[i].gw < mpr.routes[j].gw
		}
		// By weight DESC
		return mpr.routes[i].weight > mpr.routes[j].weight
	})

	newTree := cidr.NewTree4()
	if r.Type == unix.RTM_NEWROUTE {
		for _, oldR := range t.routeTree.Load().List() {
			newTree.AddCIDR(oldR.CIDR, oldR.Value)
		}

		t.l.WithField("destination", r.Dst).WithField("via", mpr.via()).Info("Adding route")
		if len(mpr.routes) == 1 {
			newTree.AddCIDR(r.Dst, mpr.routes[0].gw)
		} else {
			newTree.AddCIDR(r.Dst, mpr)
		}
	} else {
		for _, oldR := range t.routeTree.Load().List() {
			found := false
			if bytes.Equal(oldR.CIDR.IP, r.Dst.IP) && bytes.Equal(oldR.CIDR.Mask, r.Dst.Mask) {
				switch v := (*oldR.Value).(type) {
				case iputil.VpnIp:
					if v == iputil.Ip2VpnIp(r.Gw) {
						found = true
					}
				case multiPathRoute:
					if v.via() == mpr.via() {
						found = true
					}
				}
			}
			if found {
				// This is the record to delete
				t.l.WithField("destination", r.Dst).WithField("via", mpr.via()).Info("Removing route")
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
