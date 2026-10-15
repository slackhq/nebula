//go:build !ios && !e2e_testing

package overlay

import (
	"fmt"
	"log/slog"
	"math/bits"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/tio"
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
	linkAddr    atomic.Pointer[netroute.LinkAddr]
	// hostOwned means the fd arrived from the OS, which has already configured addressing, mtu
	// and routes for it. NEPacketTunnelProvider on darwin does this.
	hostOwned bool
	l         *slog.Logger

	// routesMu serializes changes to the system routing table between reload and the route watcher, and guards the
	// fields below it
	routesMu sync.Mutex
	// routeStates is who held each installable unsafe_route prefix when we last looked
	routeStates map[netip.Prefix]routeState
	// routeWatch is the routing socket watchRoutes reads, Close closes it
	routeWatch *os.File
	// routeSweep reconciles the unsafe_routes every routeSweepEvery
	routeSweep      *time.Timer
	routeSweepEvery time.Duration
	closed          bool

	// lastRouteEvent is when the routing socket last reported something that may have freed a prefix, in unix nanos
	lastRouteEvent atomic.Int64
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
		f:               os.NewFile(uintptr(fd), ""),
		Device:          name,
		vpnNetworks:     vpnNetworks,
		DefaultMTU:      getMTU(l, c),
		routeSweepEvery: routeSweepInterval,
		l:               l,
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

// newTunFromFd adopts a utun the host already created and configured, which is how a darwin
// network extension is handed its device. Everything about moving packets is shared with newTun,
// only the setup differs: the host owns addressing and routing here.
func newTunFromFd(c *config.C, l *slog.Logger, deviceFd int, vpnNetworks []netip.Prefix) (*tun, error) {
	if err := unix.SetNonblock(deviceFd, true); err != nil {
		// We own the fd from the moment it is handed to us
		_ = unix.Close(deviceFd)
		return nil, fmt.Errorf("failed to set the tun fd to non-blocking mode: %w", err)
	}

	file := os.NewFile(uintptr(deviceFd), "/dev/tun")
	t := &tun{
		f:           file,
		Device:      utunNameFromFd(deviceFd),
		vpnNetworks: vpnNetworks,
		DefaultMTU:  getMTU(l, c),
		hostOwned:   true,
		l:           l,
	}

	if err := t.reload(c, true); err != nil {
		_ = file.Close()
		return nil, err
	}

	c.RegisterReloadCallback(func(c *config.C) {
		if err := t.reload(c, false); err != nil {
			util.LogWithContextIfNeeded("failed to reload tun device", err, t.l)
		}
	})

	return t, nil
}

// utunNameFromFd asks the socket what interface it is, for logs. A blank name is not worth
// failing a tunnel over, so an error just leaves it empty.
func utunNameFromFd(fd int) string {
	name, err := unix.GetsockoptString(fd, unix.AF_SYS_CONTROL, _UTUN_OPT_IFNAME)
	if err != nil {
		return ""
	}
	return name
}

func (t *tun) Close() error {
	t.routesMu.Lock()
	t.closed = true
	if t.routeWatch != nil {
		_ = t.routeWatch.Close()
	}
	if t.routeSweep != nil {
		t.routeSweep.Stop()
	}
	t.routesMu.Unlock()

	if t.f != nil {
		return t.f.Close()
	}
	return nil
}

func (t *tun) Activate() error {
	// The host handed us a configured device. Its addresses, mtu and routes come from the network
	// settings it applied, and a sandboxed extension cannot change them anyway.
	if t.hostOwned {
		return nil
	}

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
	t.linkAddr.Store(linkAddr)

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

	// Watch before adding so a route removed in between is still noticed
	watch, err := openRouteSocket()
	if err != nil {
		t.l.Error("Failed to watch the system routing table, unsafe_routes held by another interface are only retried every minute", "error", err)
	}

	// Unsafe path routes
	if err = t.addRoutes(false); err != nil {
		if watch != nil {
			_ = watch.Close()
		}
		return err
	}

	t.startRouteWatch(watch)
	return nil
}

// activate4 assigns our vpn address as a /32 and routes the vpn network to the tun explicitly.
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
			Addr:   [4]byte{255, 255, 255, 255}, //always make the address a /32
		},
	}

	// On Darwin, VPNs don't edit the routing table directly.
	// A network extension hands its routes to the system, and configd installs them.
	// configd replaces any route already holding the same prefix, including ours.
	// As an example, Tailscale with an exit node treats any interface prefix wider than one address as a LAN.
	// With LAN access off, it routes each LAN into Tailscale's utun.
	// With LAN access on, it excludes each LAN from its tunnel.
	// configd routes an excluded prefix like its own routes would, ignoring ours, so it goes out the default route.
	// Either way our route is replaced, and traffic for the vpn network no longer reaches nebula.
	// A single address isn't a LAN to Tailscale, so our route is left alone.
	// We route the vpn network to the tun explicitly instead.

	if err := ioctl(uintptr(s), unix.SIOCAIFADDR, uintptr(unsafe.Pointer(&ifr))); err != nil {
		return fmt.Errorf("failed to set tun v4 address: %s", err)
	}

	if err := addRoute(network, t.linkAddr.Load()); err != nil {
		return fmt.Errorf("failed to add route for %v: %w", network.Masked(), err)
	}
	return nil
}

// activate6 is activate4 for IPv6
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
			// Always set the netmask to be a /128. See activate4 for why we do this.
			Addr: [16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		},
		Lifetime: addrLifetime{
			// never expires
			Vltime: 0xffffffff,
			Pltime: 0xffffffff,
		},
		Flags: _IN6_IFF_NODAD, // No DAD, a utun has no neighbors.
	}

	if err := ioctl(uintptr(s), _SIOCAIFADDR_IN6, uintptr(unsafe.Pointer(&ifr))); err != nil {
		return fmt.Errorf("failed to set tun address: %s", err)
	}

	if err := addRoute(network, t.linkAddr.Load()); err != nil {
		return fmt.Errorf("failed to add route for %v: %w", network.Masked(), err)
	}
	return nil
}

func (t *tun) reload(c *config.C, initial bool) error {
	change, routes, err := getAllRoutesFromConfig(t.l, c, t.vpnNetworks, initial)
	if err != nil {
		return err
	}

	if !initial && !change {
		// Any reload puts back the unsafe_routes someone deleted
		return t.addRoutes(true)
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

func fetchRoutes() ([]netroute.Message, error) {
	rib, err := netroute.FetchRIB(unix.AF_UNSPEC, unix.NET_RT_DUMP, 0)
	if err != nil {
		return nil, err
	}
	return netroute.ParseRIB(unix.NET_RT_DUMP, rib)
}

// routeInterfaceIn returns the index of the interface prefix is routed through, or 0 if msgs has no route for exactly
// that prefix. Routes scoped to an interface are skipped, they don't stop us adding ours.
func routeInterfaceIn(msgs []netroute.Message, prefix netip.Prefix) int {
	for _, msg := range msgs {
		m, ok := msg.(*netroute.RouteMessage)
		if !ok || len(m.Addrs) <= unix.RTAX_NETMASK || m.Flags&unix.RTF_IFSCOPE != 0 {
			continue
		}
		if p, ok := routePrefix(m.Addrs[unix.RTAX_DST], m.Addrs[unix.RTAX_NETMASK]); ok && p == prefix.Masked() {
			return m.Index
		}
	}
	return 0
}

// routePrefix returns the prefix a route covers. Host routes have no netmask.
func routePrefix(dst, mask netroute.Addr) (netip.Prefix, bool) {
	switch d := dst.(type) {
	case *netroute.Inet4Addr:
		bits := 32
		if m, ok := mask.(*netroute.Inet4Addr); ok {
			bits = maskBits(m.IP[:])
		}
		return netip.PrefixFrom(netip.AddrFrom4(d.IP), bits), true
	case *netroute.Inet6Addr:
		bits := 128
		if m, ok := mask.(*netroute.Inet6Addr); ok {
			bits = maskBits(m.IP[:])
		}
		return netip.PrefixFrom(netip.AddrFrom16(d.IP), bits), true
	}
	return netip.Prefix{}, false
}

func maskBits(mask []byte) int {
	n := 0
	for _, b := range mask {
		n += bits.OnesCount8(b)
	}
	return n
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

// Write pushes one IP packet onto the utun device. Safe for concurrent use:
// the AF prefix and iovecs are per-call stack state, and the fd write itself
// serializes on the runtime's fd mutex (see the Queue contract in tio.go).
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

func (t *tun) Queues(int) ([]tio.Queue, error) {
	return []tio.Queue{tio.NewSingleQueue(t, defaultBatchBufSize)}, nil
}
