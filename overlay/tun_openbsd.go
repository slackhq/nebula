//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"regexp"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const (
	SIOCAIFADDR_IN6 = 0x8080691a
)

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
	Lifetime   [2]uint32
}

type ifreq struct {
	Name [unix.IFNAMSIZ]byte
	data int
}

type tun struct {
	Device      string
	vpnNetworks []netip.Prefix
	MTU         int
	Routes      atomic.Pointer[[]Route]
	routeTree   atomic.Pointer[bart.Table[routing.Gateways]]
	l           *slog.Logger
	f           *os.File
	fd          int

	readBuf  []byte
	batchRet [1]tio.Packet
}

func (t *tun) Read() ([]tio.Packet, error) {
	n, err := t.readOne(t.readBuf)
	if err != nil {
		return nil, err
	}
	t.batchRet[0] = tio.Packet{Bytes: t.readBuf[:n]}
	return t.batchRet[:], nil
}

var deviceNameRE = regexp.MustCompile(`^tun[0-9]+$`)

func newTunFromFd(_ *config.C, _ *slog.Logger, _ int, _ []netip.Prefix) (*tun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in openbsd")
}

func newTun(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, _ bool) (*tun, error) {
	// Try to open tun device
	var err error
	deviceName := c.GetString("tun.dev", "")
	if deviceName == "" {
		return nil, fmt.Errorf("a device name in the format of /dev/tunN must be specified")
	}
	if !deviceNameRE.MatchString(deviceName) {
		return nil, fmt.Errorf("a device name in the format of /dev/tunN must be specified")
	}

	fd, err := unix.Open("/dev/"+deviceName, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	err = unix.SetNonblock(fd, true)
	if err != nil {
		l.Warn("Failed to set the tun device as nonblocking", "error", err)
	}

	t := &tun{
		f:           os.NewFile(uintptr(fd), ""),
		fd:          fd,
		Device:      deviceName,
		vpnNetworks: vpnNetworks,
		MTU:         c.GetInt("tun.mtu", DefaultMTU),
		l:           l,
		readBuf:     make([]byte, defaultBatchBufSize),
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

func (t *tun) Close() error {
	if t.f != nil {
		if err := t.f.Close(); err != nil {
			return fmt.Errorf("error closing tun file: %w", err)
		}

		// t.f.Close should have handled it for us but let's be extra sure
		_ = unix.Close(t.fd)
	}
	return nil
}

// tunWritev and tunReadv are linkname'd to x/sys/unix's libc-routed writev/readv stubs so the
// calls go through libc's pinned trampoline. OpenBSD's pinsyscall protection rejects a raw
// syscall.Syscall(SYS_WRITEV/SYS_READV, ...) because it doesn't originate from a libc-pinned
// address, so we can't use the syscall.Syscall pattern that freebsd / netbsd use. We pull the
// low-level stubs instead of calling unix.Writev/unix.Readv because those take [][]byte and rebuild
// the []Iovec every call, which heap-allocates the header; linkname'ing the stubs lets us hand them
// our own stack-allocated iovecs. See golang/go#78049.

//go:linkname tunWritev golang.org/x/sys/unix.writev
//go:noescape
func tunWritev(fd int, iovecs []unix.Iovec) (n int, err error)

//go:linkname tunReadv golang.org/x/sys/unix.readv
//go:noescape
func tunReadv(fd int, iovecs []unix.Iovec) (n int, err error)

// readOne pulls one IP packet off the tun device, scattering the 4 byte protocol header away from
// the packet so the payload lands directly in to.
func (t *tun) readOne(to []byte) (int, error) {
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

// Write pushes one IP packet onto the tun device.
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

func (t *tun) addIp(cidr netip.Prefix) error {
	if cidr.Addr().Is4() {
		var req ifreqAlias4
		req.Name = t.deviceBytes()
		req.Addr = unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   cidr.Addr().As4(),
		}
		req.DstAddr = unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   cidr.Addr().As4(),
		}
		req.MaskAddr = unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   prefixToMask(cidr).As4(),
		}

		s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
		if err != nil {
			return err
		}
		defer syscall.Close(s)

		if err := ioctl(uintptr(s), unix.SIOCAIFADDR, uintptr(unsafe.Pointer(&req))); err != nil {
			return fmt.Errorf("failed to set tun address %s: %s", cidr.Addr(), err)
		}

		err = addRoute(cidr, t.vpnNetworks)
		if err != nil {
			return fmt.Errorf("failed to set route for vpn network %v: %w", cidr, err)
		}

		return nil
	}

	if cidr.Addr().Is6() {
		var req ifreqAlias6
		req.Name = t.deviceBytes()
		req.Addr = unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   cidr.Addr().As16(),
		}
		req.PrefixMask = unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   prefixToMask(cidr).As16(),
		}
		req.Lifetime[0] = 0xffffffff
		req.Lifetime[1] = 0xffffffff

		s, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_IP)
		if err != nil {
			return err
		}
		defer syscall.Close(s)

		if err := ioctl(uintptr(s), SIOCAIFADDR_IN6, uintptr(unsafe.Pointer(&req))); err != nil {
			return fmt.Errorf("failed to set tun address %s: %s", cidr.Addr().String(), err)
		}

		return nil
	}

	return fmt.Errorf("unknown address type %v", cidr)
}

func (t *tun) Activate() error {
	err := t.doIoctlByName(unix.SIOCSIFMTU, uint32(t.MTU))
	if err != nil {
		return fmt.Errorf("failed to set tun mtu: %w", err)
	}

	for i := range t.vpnNetworks {
		err = t.addIp(t.vpnNetworks[i])
		if err != nil {
			return err
		}
	}

	return t.addRoutes(false)
}

func (t *tun) doIoctlByName(ctl uintptr, value uint32) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer syscall.Close(s)

	ir := ifreq{Name: t.deviceBytes(), data: int(value)}
	err = ioctl(uintptr(s), ctl, uintptr(unsafe.Pointer(&ir)))
	return err
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
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
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

func (t *tun) NewMultiQueueReader() error {
	return fmt.Errorf("TODO: multiqueue not implemented for openbsd")
}

func (t *tun) addRoutes(logErrors bool) error {
	routes := *t.Routes.Load()

	for _, r := range routes {
		if len(r.Via) == 0 || !r.Install {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		err := addRoute(r.Cidr, t.vpnNetworks)
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

func (t *tun) removeRoutes(routes []Route) error {
	for _, r := range routes {
		if !r.Install {
			continue
		}

		err := delRoute(r.Cidr, t.vpnNetworks)
		if err != nil {
			t.l.Error("Failed to remove route", "error", err, "route", r)
		} else {
			t.l.Info("Removed route", "route", r)
		}
	}
	return nil
}

func (t *tun) deviceBytes() (o [16]byte) {
	for i, c := range t.Device {
		o[i] = byte(c)
	}
	return
}

func (t *tun) Readers() []tio.Queue {
	return []tio.Queue{t}
}

func addRoute(prefix netip.Prefix, gateways []netip.Prefix) error {
	sock, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("unable to create AF_ROUTE socket: %v", err)
	}
	defer unix.Close(sock)

	route := &netroute.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_ADD,
		Flags:   unix.RTF_UP | unix.RTF_GATEWAY,
		Seq:     1,
	}

	if prefix.Addr().Is4() {
		gw, err := selectGateway(prefix, gateways)
		if err != nil {
			return err
		}
		route.Addrs = []netroute.Addr{
			unix.RTAX_DST:     &netroute.Inet4Addr{IP: prefix.Masked().Addr().As4()},
			unix.RTAX_NETMASK: &netroute.Inet4Addr{IP: prefixToMask(prefix).As4()},
			unix.RTAX_GATEWAY: &netroute.Inet4Addr{IP: gw.Addr().As4()},
		}
	} else {
		gw, err := selectGateway(prefix, gateways)
		if err != nil {
			return err
		}
		route.Addrs = []netroute.Addr{
			unix.RTAX_DST:     &netroute.Inet6Addr{IP: prefix.Masked().Addr().As16()},
			unix.RTAX_NETMASK: &netroute.Inet6Addr{IP: prefixToMask(prefix).As16()},
			unix.RTAX_GATEWAY: &netroute.Inet6Addr{IP: gw.Addr().As16()},
		}
	}

	data, err := route.Marshal()
	if err != nil {
		return fmt.Errorf("failed to create route.RouteMessage: %w", err)
	}

	_, err = unix.Write(sock, data[:])
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			// Try to do a change
			route.Type = unix.RTM_CHANGE
			data, err = route.Marshal()
			if err != nil {
				return fmt.Errorf("failed to create route.RouteMessage for change: %w", err)
			}
			_, err = unix.Write(sock, data[:])
			return err
		}
		return fmt.Errorf("failed to write route.RouteMessage to socket: %w", err)
	}

	return nil
}

func delRoute(prefix netip.Prefix, gateways []netip.Prefix) error {
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
		gw, err := selectGateway(prefix, gateways)
		if err != nil {
			return err
		}
		route.Addrs = []netroute.Addr{
			unix.RTAX_DST:     &netroute.Inet4Addr{IP: prefix.Masked().Addr().As4()},
			unix.RTAX_NETMASK: &netroute.Inet4Addr{IP: prefixToMask(prefix).As4()},
			unix.RTAX_GATEWAY: &netroute.Inet4Addr{IP: gw.Addr().As4()},
		}
	} else {
		gw, err := selectGateway(prefix, gateways)
		if err != nil {
			return err
		}
		route.Addrs = []netroute.Addr{
			unix.RTAX_DST:     &netroute.Inet6Addr{IP: prefix.Masked().Addr().As16()},
			unix.RTAX_NETMASK: &netroute.Inet6Addr{IP: prefixToMask(prefix).As16()},
			unix.RTAX_GATEWAY: &netroute.Inet6Addr{IP: gw.Addr().As16()},
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
