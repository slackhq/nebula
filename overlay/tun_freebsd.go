//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const (
	// FIODGNAME is defined in sys/sys/filio.h on FreeBSD
	// For 32-bit systems, use FIODGNAME_32 (not defined in this file: 0x80086678)
	FIODGNAME        = 0x80106678
	TUNSIFMODE       = 0x8004745e
	TUNSIFHEAD       = 0x80047460
	OSIOCAIFADDR_IN6 = 0x8088691b
	IN6_IFF_NODAD    = 0x0020
)

type fiodgnameArg struct {
	length int32
	pad    [4]byte
	buf    unsafe.Pointer
}

type ifreqRename struct {
	Name [unix.IFNAMSIZ]byte
	Data uintptr
}

type ifreqDestroy struct {
	Name [unix.IFNAMSIZ]byte
	pad  [16]byte
}

type ifReq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
}

type ifreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
}

type addrLifetime struct {
	Expire    uint64
	Preferred uint64
	Vltime    uint32
	Pltime    uint32
}

type ifreqAlias4 struct {
	Name     [unix.IFNAMSIZ]byte
	Addr     unix.RawSockaddrInet4
	DstAddr  unix.RawSockaddrInet4
	MaskAddr unix.RawSockaddrInet4
	VHid     uint32
}

type ifreqAlias6 struct {
	Name       [unix.IFNAMSIZ]byte
	Addr       unix.RawSockaddrInet6
	DstAddr    unix.RawSockaddrInet6
	PrefixMask unix.RawSockaddrInet6
	Flags      uint32
	Lifetime   addrLifetime
	VHid       uint32
}

type tun struct {
	Device      string
	vpnNetworks []netip.Prefix
	MTU         int
	Routes      atomic.Pointer[[]Route]
	routeTree   atomic.Pointer[bart.Table[routing.Gateways]]
	linkAddr    *netroute.LinkAddr
	l           *logrus.Logger
	devFd       int
}

func (t *tun) Read(to []byte) (int, error) {
	// use readv() to read from the tunnel device, to eliminate the need for copying the buffer
	if t.devFd < 0 {
		return -1, syscall.EINVAL
	}

	// first 4 bytes is protocol family, in network byte order
	head := make([]byte, 4)

	iovecs := []syscall.Iovec{
		{&head[0], 4},
		{&to[0], uint64(len(to))},
	}

	n, _, errno := syscall.Syscall(syscall.SYS_READV, uintptr(t.devFd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(2))

	var err error
	if errno != 0 {
		err = syscall.Errno(errno)
	} else {
		err = nil
	}
	// fix bytes read number to exclude header
	bytesRead := int(n)
	if bytesRead < 0 {
		return bytesRead, err
	} else if bytesRead < 4 {
		return 0, err
	} else {
		return bytesRead - 4, err
	}
}

// Write is only valid for single threaded use
func (t *tun) Write(from []byte) (int, error) {
	// use writev() to write to the tunnel device, to eliminate the need for copying the buffer
	if t.devFd < 0 {
		return -1, syscall.EINVAL
	}

	if len(from) <= 1 {
		return 0, syscall.EIO
	}
	ipVer := from[0] >> 4
	var head []byte
	// first 4 bytes is protocol family, in network byte order
	if ipVer == 4 {
		head = []byte{0, 0, 0, syscall.AF_INET}
	} else if ipVer == 6 {
		head = []byte{0, 0, 0, syscall.AF_INET6}
	} else {
		return 0, fmt.Errorf("unable to determine IP version from packet")
	}
	iovecs := []syscall.Iovec{
		{&head[0], 4},
		{&from[0], uint64(len(from))},
	}

	n, _, errno := syscall.Syscall(syscall.SYS_WRITEV, uintptr(t.devFd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(2))

	var err error
	if errno != 0 {
		err = syscall.Errno(errno)
	} else {
		err = nil
	}

	return int(n) - 4, err
}

func (t *tun) Close() error {
	if t.devFd >= 0 {
		err := syscall.Close(t.devFd)
		if err != nil {
			t.l.WithError(err).Error("Error closing device")
		}
		t.devFd = -1

		c := make(chan struct{})
		go func() {
			// destroying the interface can block if a read() is still pending. Do this asynchronously.
			defer close(c)
			s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
			if err == nil {
				defer syscall.Close(s)
				ifreq := ifreqDestroy{Name: t.deviceBytes()}
				err = ioctl(uintptr(s), syscall.SIOCIFDESTROY, uintptr(unsafe.Pointer(&ifreq)))
			}
			if err != nil {
				t.l.WithError(err).Error("Error destroying tunnel")
			}
		}()

		// wait up to 1 second so we start blocking at the ioctl
		select {
		case <-c:
		case <-time.After(1 * time.Second):
		}
	}

	return nil
}

func newTunFromFd(_ *config.C, _ *logrus.Logger, _ int, _ []netip.Prefix) (*tun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in FreeBSD")
}

func newTun(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, _ bool) (*tun, error) {
	// Try to open existing tun device
	var fd int
	var err error
	deviceName := c.GetString("tun.dev", "")
	if deviceName != "" {
		fd, err = syscall.Open("/dev/"+deviceName, syscall.O_RDWR, 0)
	}
	if errors.Is(err, fs.ErrNotExist) || deviceName == "" {
		// If the device doesn't already exist, request a new one and rename it
		fd, err = syscall.Open("/dev/tun", syscall.O_RDWR, 0)
	}
	if err != nil {
		return nil, err
	}

	// Read the name of the interface
	var name [16]byte
	arg := fiodgnameArg{length: 16, buf: unsafe.Pointer(&name)}
	ctrlErr := ioctl(uintptr(fd), FIODGNAME, uintptr(unsafe.Pointer(&arg)))

	if ctrlErr == nil {
		// set broadcast mode and multicast
		ifmode := uint32(unix.IFF_BROADCAST | unix.IFF_MULTICAST)
		ctrlErr = ioctl(uintptr(fd), TUNSIFMODE, uintptr(unsafe.Pointer(&ifmode)))
	}

	if ctrlErr == nil {
		// turn on link-layer mode, to support ipv6
		ifhead := uint32(1)
		ctrlErr = ioctl(uintptr(fd), TUNSIFHEAD, uintptr(unsafe.Pointer(&ifhead)))
	}

	if ctrlErr != nil {
		return nil, err
	}

	ifName := string(bytes.TrimRight(name[:], "\x00"))
	if deviceName == "" {
		deviceName = ifName
	}

	// If the name doesn't match the desired interface name, rename it now
	if ifName != deviceName {
		s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
		if err != nil {
			return nil, err
		}
		defer syscall.Close(s)

		fd := uintptr(s)

		var fromName [16]byte
		var toName [16]byte
		copy(fromName[:], ifName)
		copy(toName[:], deviceName)

		ifrr := ifreqRename{
			Name: fromName,
			Data: uintptr(unsafe.Pointer(&toName)),
		}

		// Set the device name
		ioctl(fd, syscall.SIOCSIFNAME, uintptr(unsafe.Pointer(&ifrr)))
	}

	t := &tun{
		Device:      deviceName,
		vpnNetworks: vpnNetworks,
		MTU:         c.GetInt("tun.mtu", DefaultMTU),
		l:           l,
		devFd:       fd,
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

func (t *tun) addIp(cidr netip.Prefix) error {
	if cidr.Addr().Is4() {
		ifr := ifreqAlias4{
			Name: t.deviceBytes(),
			Addr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   cidr.Addr().As4(),
			},
			DstAddr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   getBroadcast(cidr).As4(),
			},
			MaskAddr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   prefixToMask(cidr).As4(),
			},
			VHid: 0,
		}
		s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
		if err != nil {
			return err
		}
		defer syscall.Close(s)
		// Note: unix.SIOCAIFADDR corresponds to FreeBSD's OSIOCAIFADDR
		if err := ioctl(uintptr(s), unix.SIOCAIFADDR, uintptr(unsafe.Pointer(&ifr))); err != nil {
			return fmt.Errorf("failed to set tun address %s: %s", cidr.Addr().String(), err)
		}
		return nil
	}

	if cidr.Addr().Is6() {
		ifr := ifreqAlias6{
			Name: t.deviceBytes(),
			Addr: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   cidr.Addr().As16(),
			},
			PrefixMask: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   prefixToMask(cidr).As16(),
			},
			Lifetime: addrLifetime{
				Expire:    0,
				Preferred: 0,
				Vltime:    0xffffffff,
				Pltime:    0xffffffff,
			},
			Flags: IN6_IFF_NODAD,
		}
		s, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
		if err != nil {
			return err
		}
		defer syscall.Close(s)

		if err := ioctl(uintptr(s), OSIOCAIFADDR_IN6, uintptr(unsafe.Pointer(&ifr))); err != nil {
			return fmt.Errorf("failed to set tun address %s: %s", cidr.Addr().String(), err)
		}
		return nil
	}

	return fmt.Errorf("unknown address type %v", cidr)
}

func (t *tun) Activate() error {
	// Setup our default MTU
	err := t.setMTU()
	if err != nil {
		return err
	}

	linkAddr, err := getLinkAddr(t.Device)
	if err != nil {
		return err
	}
	if linkAddr == nil {
		return fmt.Errorf("unable to discover link_addr for tun interface")
	}
	t.linkAddr = linkAddr

	for i := range t.vpnNetworks {
		err := t.addIp(t.vpnNetworks[i])
		if err != nil {
			return err
		}
	}

	return t.addRoutes(false)
}

func (t *tun) setMTU() error {
	// Set the MTU on the device
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer syscall.Close(s)

	ifm := ifreqMTU{Name: t.deviceBytes(), MTU: int32(t.MTU)}
	err = ioctl(uintptr(s), unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifm)))
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

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for freebsd")
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

func (t *tun) removeRoutes(routes []Route) error {
	for _, r := range routes {
		if !r.Install {
			continue
		}

		err := delRoute(r.Cidr, t.linkAddr)
		if err != nil {
			t.l.WithError(err).WithField("route", r).Error("Failed to remove route")
		} else {
			t.l.WithField("route", r).Info("Removed route")
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
		if errors.Is(err, unix.EEXIST) {
			// Try to do a change
			route.Type = unix.RTM_CHANGE
			data, err = route.Marshal()
			if err != nil {
				return fmt.Errorf("failed to create route.RouteMessage for change: %w", err)
			}
			_, err = unix.Write(sock, data[:])
			fmt.Println("DOING CHANGE")
			return err
		}
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

// getLinkAddr Gets the link address for the interface of the given name
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
