//go:build !ios && !e2e_testing
// +build !ios,!e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

type tun struct {
	f           *os.File
	Device      string
	vpnNetworks []netip.Prefix
	DefaultMTU  int
	Routes      atomic.Pointer[[]Route]
	routeTree   atomic.Pointer[bart.Table[routing.Gateways]]
	linkAddr    *netroute.LinkAddr
	l           *slog.Logger
}

type ifReq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	pad   [8]byte
}

const (
	_SIOCAIFADDR_IN6 = 2155899162
	_UTUN_OPT_IFNAME = 2
	_IN6_IFF_NODAD   = 0x0020
	_IN6_IFF_SECURED = 0x0400
	utunControlName  = "com.apple.net.utun_control"
)

type ifreqMTU struct {
	Name [16]byte
	MTU  int32
	pad  [8]byte
}

type addrLifetime struct {
	Expire    float64
	Preferred float64
	Vltime    uint32
	Pltime    uint32
}

type ifreqAlias4 struct {
	Name     [unix.IFNAMSIZ]byte
	Addr     unix.RawSockaddrInet4
	DstAddr  unix.RawSockaddrInet4
	MaskAddr unix.RawSockaddrInet4
}

type ifreqAlias6 struct {
	Name       [unix.IFNAMSIZ]byte
	Addr       unix.RawSockaddrInet6
	DstAddr    unix.RawSockaddrInet6
	PrefixMask unix.RawSockaddrInet6
	Flags      uint32
	Lifetime   addrLifetime
}

func newTun(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, _ bool) (*tun, error) {
	name := c.GetString("tun.dev", "")
	ifIndex := -1
	if name != "" && name != "utun" {
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			// NOTE: we don't make this error so we don't break existing
			// configs that set a name before it was used.
			l.Warn("interface name must be utun[0-9]+ on Darwin, ignoring")
			ifIndex = -1
		}
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, unix.AF_SYS_CONTROL)
	if err != nil {
		return nil, fmt.Errorf("system socket: %v", err)
	}

	var ctlInfo = &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)

	err = unix.IoctlCtlInfo(fd, ctlInfo)
	if err != nil {
		return nil, fmt.Errorf("CTLIOCGINFO: %v", err)
	}

	err = unix.Connect(fd, &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	})
	if err != nil {
		return nil, fmt.Errorf("SYS_CONNECT: %v", err)
	}

	name, err = unix.GetsockoptString(fd, unix.AF_SYS_CONTROL, _UTUN_OPT_IFNAME)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve tun name: %w", err)
	}

	err = unix.SetNonblock(fd, true)
	if err != nil {
		return nil, fmt.Errorf("SetNonblock: %v", err)
	}

	t := &tun{
		f:           os.NewFile(uintptr(fd), ""),
		Device:      name,
		vpnNetworks: vpnNetworks,
		DefaultMTU:  c.GetInt("tun.mtu", DefaultMTU),
		l:           l,
	}

	err = t.reload(c, true)
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

func (t *tun) deviceBytes() (o [16]byte) {
	for i, c := range t.Device {
		o[i] = byte(c)
	}
	return
}

func newTunFromFd(_ *config.C, _ *slog.Logger, _ int, _ []netip.Prefix) (*tun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in Darwin")
}

func (t *tun) Close() error {
	if t.f != nil {
		return t.f.Close()
	}
	return nil
}

func (t *tun) Activate() error {
	devName := t.deviceBytes()

	s, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		unix.IPPROTO_IP,
	)
	if err != nil {
		return err
	}
	defer unix.Close(s)

	fd := uintptr(s)

	// Set the MTU on the device
	ifm := ifreqMTU{Name: devName, MTU: int32(t.DefaultMTU)}
	if err = ioctl(fd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifm))); err != nil {
		return fmt.Errorf("failed to set tun mtu: %v", err)
	}

	// Get the device flags
	ifrf := ifReq{Name: devName}
	if err = ioctl(fd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to get tun flags: %s", err)
	}

	linkAddr, err := getLinkAddr(t.Device)
	if err != nil {
		return err
	}
	if linkAddr == nil {
		return fmt.Errorf("unable to discover link_addr for tun interface")
	}
	t.linkAddr = linkAddr

	for _, network := range t.vpnNetworks {
		if network.Addr().Is4() {
			err = t.activate4(network)
			if err != nil {
				return err
			}
		} else {
			err = t.activate6(network)
			if err != nil {
				return err
			}
		}
	}

	// Run the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to run tun device: %s", err)
	}

	// Unsafe path routes
	return t.addRoutes(false)
}

func (t *tun) activate4(network netip.Prefix) error {
	s, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		unix.IPPROTO_IP,
	)
	if err != nil {
		return err
	}
	defer unix.Close(s)

	ifr := ifreqAlias4{
		Name: t.deviceBytes(),
		Addr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   network.Addr().As4(),
		},
		DstAddr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   network.Addr().As4(),
		},
		MaskAddr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   prefixToMask(network).As4(),
		},
	}

	if err := ioctl(uintptr(s), unix.SIOCAIFADDR, uintptr(unsafe.Pointer(&ifr))); err != nil {
		return fmt.Errorf("failed to set tun v4 address: %s", err)
	}

	err = addRoute(network, t.linkAddr)
	if err != nil {
		return err
	}

	return nil
}

func (t *tun) activate6(network netip.Prefix) error {
	s, err := unix.Socket(
		unix.AF_INET6,
		unix.SOCK_DGRAM,
		unix.IPPROTO_IP,
	)
	if err != nil {
		return err
	}
	defer unix.Close(s)

	ifr := ifreqAlias6{
		Name: t.deviceBytes(),
		Addr: unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   network.Addr().As16(),
		},
		PrefixMask: unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   prefixToMask(network).As16(),
		},
		Lifetime: addrLifetime{
			// never expires
			Vltime: 0xffffffff,
			Pltime: 0xffffffff,
		},
		Flags: _IN6_IFF_NODAD,
	}

	if err := ioctl(uintptr(s), _SIOCAIFADDR_IN6, uintptr(unsafe.Pointer(&ifr))); err != nil {
		return fmt.Errorf("failed to set tun address: %s", err)
	}

	return nil
}

func (t *tun) reload(c *config.C, initial bool) error {
	change, routes, err := getAllRoutesFromConfig(c, t.vpnNetworks, initial)
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

func (t *tun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, ok := t.routeTree.Load().Lookup(ip)
	if ok {
		return r
	}
	return routing.Gateways{}
}

// Get the LinkAddr for the interface of the given name
// Is there an easier way to fetch this when we create the interface?
// Maybe SIOCGIFINDEX? but this doesn't appear to exist in the darwin headers.
func getLinkAddr(name string) (*netroute.LinkAddr, error) {
	rib, err := netroute.FetchRIB(unix.AF_UNSPEC, unix.NET_RT_IFLIST, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := netroute.ParseRIB(unix.NET_RT_IFLIST, rib)
	if err != nil {
		return nil, err
	}

	for _, m := range msgs {
		switch m := m.(type) {
		case *netroute.InterfaceMessage:
			if m.Name == name {
				sa, ok := m.Addrs[unix.RTAX_IFP].(*netroute.LinkAddr)
				if ok {
					return sa, nil
				}
			}
		}
	}

	return nil, nil
}

func (t *tun) addRoutes(logErrors bool) error {
	routes := *t.Routes.Load()

	for _, r := range routes {
		if len(r.Via) == 0 || !r.Install {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		err := addRoute(r.Cidr, t.linkAddr)
		if err != nil {
			if errors.Is(err, unix.EEXIST) {
				t.l.Warn("unable to add unsafe_route, identical route already exists", "route", r.Cidr)
			} else {
				retErr := util.NewContextualError("Failed to add route", map[string]any{"route": r}, err)
				if logErrors {
					retErr.Log(t.l)
				} else {
					return retErr
				}
			}
		} else {
			t.l.Info("Added route", "route", r)
		}
	}

	return nil
}

func (t *tun) removeRoutes(routes []Route) error {
	for _, r := range routes {
		if !r.Install {
			continue
		}

		err := delRoute(r.Cidr, t.linkAddr)
		if err != nil {
			t.l.Error("Failed to remove route", "error", err, "route", r)
		} else {
			t.l.Info("Removed route", "route", r)
		}
	}
	return nil
}

func addRoute(prefix netip.Prefix, gateway netroute.Addr) error {
	sock, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("unable to create AF_ROUTE socket: %v", err)
	}
	defer unix.Close(sock)

	route := &netroute.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_ADD,
		Flags:   unix.RTF_UP,
		Seq:     1,
	}

	if prefix.Addr().Is4() {
		route.Addrs = []netroute.Addr{
			unix.RTAX_DST:     &netroute.Inet4Addr{IP: prefix.Masked().Addr().As4()},
			unix.RTAX_NETMASK: &netroute.Inet4Addr{IP: prefixToMask(prefix).As4()},
			unix.RTAX_GATEWAY: gateway,
		}
	} else {
		route.Addrs = []netroute.Addr{
			unix.RTAX_DST:     &netroute.Inet6Addr{IP: prefix.Masked().Addr().As16()},
			unix.RTAX_NETMASK: &netroute.Inet6Addr{IP: prefixToMask(prefix).As16()},
			unix.RTAX_GATEWAY: gateway,
		}
	}

	data, err := route.Marshal()
	if err != nil {
		return fmt.Errorf("failed to create route.RouteMessage: %w", err)
	}

	_, err = unix.Write(sock, data[:])
	if err != nil {
		return fmt.Errorf("failed to write route.RouteMessage to socket: %w", err)
	}

	return nil
}

func delRoute(prefix netip.Prefix, gateway netroute.Addr) error {
	sock, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("unable to create AF_ROUTE socket: %v", err)
	}
	defer unix.Close(sock)

	route := netroute.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_DELETE,
		Seq:     1,
	}

	if prefix.Addr().Is4() {
		route.Addrs = []netroute.Addr{
			unix.RTAX_DST:     &netroute.Inet4Addr{IP: prefix.Masked().Addr().As4()},
			unix.RTAX_NETMASK: &netroute.Inet4Addr{IP: prefixToMask(prefix).As4()},
			unix.RTAX_GATEWAY: gateway,
		}
	} else {
		route.Addrs = []netroute.Addr{
			unix.RTAX_DST:     &netroute.Inet6Addr{IP: prefix.Masked().Addr().As16()},
			unix.RTAX_NETMASK: &netroute.Inet6Addr{IP: prefixToMask(prefix).As16()},
			unix.RTAX_GATEWAY: gateway,
		}
	}

	data, err := route.Marshal()
	if err != nil {
		return fmt.Errorf("failed to create route.RouteMessage: %w", err)
	}
	_, err = unix.Write(sock, data[:])
	if err != nil {
		return fmt.Errorf("failed to write route.RouteMessage to socket: %w", err)
	}

	return nil
}

// tunWritev and tunReadv are linkname'd to x/sys/unix's libc-routed writev/readv stubs so the
// calls go through libSystem's pinned trampoline. A raw syscall.Syscall(SYS_WRITEV/SYS_READV, ...)
// on darwin/arm64 emits an SVC #0x80 trap (see $GOROOT/src/syscall/asm_darwin_arm64.s), the path
// Apple keeps warning they will eventually disallow. We pull the low-level stubs instead of calling
// unix.Writev/unix.Readv because those take [][]byte and rebuild the []Iovec every call, which
// heap-allocates the header; linkname'ing the stubs lets us hand them our own stack-allocated
// iovecs. See golang/go#78049.

//go:linkname tunWritev golang.org/x/sys/unix.writev
//go:noescape
func tunWritev(fd int, iovecs []unix.Iovec) (n int, err error)

//go:linkname tunReadv golang.org/x/sys/unix.readv
//go:noescape
func tunReadv(fd int, iovecs []unix.Iovec) (n int, err error)

// Read pulls one IP packet off the utun device, scattering the 4 byte protocol header away from
// the packet so the payload lands directly in to.
func (t *tun) Read(to []byte) (int, error) {
	var head [4]byte

	rc, err := t.f.SyscallConn()
	if err != nil {
		return 0, err
	}

	var n int
	var callErr error
	err = rc.Read(func(fd uintptr) bool {
		iovecs := []unix.Iovec{
			{Base: &head[0], Len: 4},
			{Base: &to[0], Len: uint64(len(to))},
		}
		n, callErr = tunReadv(int(fd), iovecs)
		if errno, ok := callErr.(syscall.Errno); ok && errno.Temporary() {
			return false
		}
		return true
	})
	if err != nil {
		return 0, err
	}
	if callErr != nil {
		return 0, callErr
	}
	if n < 4 {
		return 0, nil
	}
	return n - 4, nil
}

// Write pushes one IP packet onto the utun device.
func (t *tun) Write(from []byte) (int, error) {
	if len(from) == 0 {
		return 0, syscall.EIO
	}

	ipVer := from[0] >> 4
	var head [4]byte
	switch ipVer {
	case 4:
		head[3] = syscall.AF_INET
	case 6:
		head[3] = syscall.AF_INET6
	default:
		return 0, fmt.Errorf("unable to determine IP version from packet")
	}

	// Grab rc as a local so the compiler can devirtualize the call and keep the closure on the stack.
	rc, err := t.f.SyscallConn()
	if err != nil {
		return 0, err
	}

	var n int
	var callErr error
	err = rc.Write(func(fd uintptr) bool {
		iovecs := []unix.Iovec{
			{Base: &head[0], Len: 4},
			{Base: &from[0], Len: uint64(len(from))},
		}
		n, callErr = tunWritev(int(fd), iovecs)
		// Type-assert to syscall.Errno so the EAGAIN/EWOULDBLOCK/EINTR check doesn't box the errno
		// constants into error interfaces on every call.
		if errno, ok := callErr.(syscall.Errno); ok && errno.Temporary() {
			return false
		}
		return true
	})
	if err != nil {
		return 0, err
	}
	if callErr != nil {
		return 0, callErr
	}

	return n - 4, nil
}

func (t *tun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

func (t *tun) Name() string {
	return t.Device
}

func (t *tun) SupportsMultiqueue() bool {
	return false
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for darwin")
}
