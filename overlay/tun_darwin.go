//go:build darwin && !ios && !e2e_testing
// +build darwin,!ios,!e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type tun struct {
	linkAddr *netroute.LinkAddr
}

// ioctl structures for Darwin network configuration
type ifReq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	pad   [8]byte
}

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

const (
	_SIOCAIFADDR_IN6 = 2155899162
	_IN6_IFF_NODAD   = 0x0020
)

func newTunFromFd(_ *config.C, _ *logrus.Logger, _ int, _ []netip.Prefix) (*wgTun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported on Darwin")
}

func newTun(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, _ bool) (*wgTun, error) {
	deviceName := c.GetString("tun.dev", "utun")
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

	// Create Darwin-specific route manager
	t.routeManager = &tun{}

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

func (rm *tun) Activate(t *wgTun) error {
	name, err := t.tunDevice.Name()
	if err != nil {
		return fmt.Errorf("failed to get device name: %w", err)
	}

	// Set the MTU
	rm.SetMTU(t, t.MaxMTU)

	// Add IP addresses
	for _, network := range t.vpnNetworks {
		if err := rm.addIP(t, name, network); err != nil {
			return err
		}
	}

	// Bring up the interface using ioctl
	if err := rm.bringUpInterface(name); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	// Get the link address for routing
	linkAddr, err := getLinkAddr(name)
	if err != nil {
		return fmt.Errorf("failed to get link address: %w", err)
	}
	if linkAddr == nil {
		return fmt.Errorf("unable to discover link_addr for tun interface")
	}
	rm.linkAddr = linkAddr

	// Set the routes
	if err := rm.AddRoutes(t, false); err != nil {
		return err
	}

	return nil
}

func (rm *tun) bringUpInterface(name string) error {
	// Open a socket for ioctl
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer unix.Close(fd)

	// Get current flags
	var ifrf ifReq
	copy(ifrf.Name[:], name)

	if err := ioctl(uintptr(fd), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to get interface flags: %w", err)
	}

	// Set IFF_UP and IFF_RUNNING flags
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING

	if err := ioctl(uintptr(fd), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to set interface flags: %w", err)
	}

	return nil
}

func (rm *tun) SetMTU(t *wgTun, mtu int) {
	name, err := t.tunDevice.Name()
	if err != nil {
		t.l.WithError(err).Error("Failed to get device name for MTU set")
		return
	}

	// Open a socket for ioctl
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.l.WithError(err).Error("Failed to create socket for MTU set")
		return
	}
	defer unix.Close(fd)

	// Prepare the ioctl request
	var ifr ifreqMTU
	copy(ifr.Name[:], name)
	ifr.MTU = int32(mtu)

	// Set the MTU using ioctl
	if err := ioctl(uintptr(fd), unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifr))); err != nil {
		t.l.WithError(err).Error("Failed to set tun mtu via ioctl")
	}
}

func (rm *tun) SetDefaultRoute(t *wgTun, cidr netip.Prefix) error {
	// On Darwin, routes are set via ifconfig and route commands
	return nil
}

func (rm *tun) AddRoutes(t *wgTun, logErrors bool) error {
	routes := *t.Routes.Load()
	for _, r := range routes {
		if !r.Install {
			continue
		}

		err := rm.addRoute(r.Cidr)
		if err != nil {
			if errors.Is(err, unix.EEXIST) {
				t.l.WithField("route", r.Cidr).
					Warnf("unable to add unsafe_route, identical route already exists")
			} else {
				retErr := util.NewContextualError("Failed to add route", map[string]any{"route": r}, err)
				if logErrors {
					retErr.Log(t.l)
				} else {
					return retErr
				}
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

		err := rm.delRoute(r.Cidr)
		if err != nil {
			t.l.WithError(err).WithField("route", r).Error("Failed to remove route")
		} else {
			t.l.WithField("route", r).Info("Removed route")
		}
	}
}

func (rm *tun) NewMultiQueueReader(t *wgTun) (io.ReadWriteCloser, error) {
	// Darwin doesn't support multi-queue TUN devices in the same way as Linux
	// Return a reader that wraps the same device
	return &wgTunReader{
		parent:    t,
		tunDevice: t.tunDevice,
		offset:    0,
		l:         t.l,
	}, nil
}

func (rm *tun) addIP(t *wgTun, name string, network netip.Prefix) error {
	addr := network.Addr()

	if addr.Is4() {
		return rm.addIPv4(name, network)
	} else {
		return rm.addIPv6(name, network)
	}
}

func (rm *tun) addIPv4(name string, network netip.Prefix) error {
	// Open an IPv4 socket for ioctl
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return fmt.Errorf("failed to create IPv4 socket: %w", err)
	}
	defer unix.Close(s)

	var ifr ifreqAlias4
	copy(ifr.Name[:], name)

	// Set the address
	ifr.Addr = unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   network.Addr().As4(),
	}

	// Set the destination address (same as address for point-to-point)
	ifr.DstAddr = unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   network.Addr().As4(),
	}

	// Set the netmask
	ifr.MaskAddr = unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   prefixToMask(network).As4(),
	}

	if err := ioctl(uintptr(s), unix.SIOCAIFADDR, uintptr(unsafe.Pointer(&ifr))); err != nil {
		return fmt.Errorf("failed to set IPv4 address via ioctl: %w", err)
	}

	return nil
}

func (rm *tun) addIPv6(name string, network netip.Prefix) error {
	// Open an IPv6 socket for ioctl
	s, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return fmt.Errorf("failed to create IPv6 socket: %w", err)
	}
	defer unix.Close(s)

	var ifr ifreqAlias6
	copy(ifr.Name[:], name)

	// Set the address
	ifr.Addr = unix.RawSockaddrInet6{
		Len:    unix.SizeofSockaddrInet6,
		Family: unix.AF_INET6,
		Addr:   network.Addr().As16(),
	}

	// Set the prefix mask
	ifr.PrefixMask = unix.RawSockaddrInet6{
		Len:    unix.SizeofSockaddrInet6,
		Family: unix.AF_INET6,
		Addr:   prefixToMask(network).As16(),
	}

	// Set lifetime (never expires)
	ifr.Lifetime = addrLifetime{
		Vltime: 0xffffffff,
		Pltime: 0xffffffff,
	}

	// Set flags (no DAD - Duplicate Address Detection)
	ifr.Flags = _IN6_IFF_NODAD

	if err := ioctl(uintptr(s), _SIOCAIFADDR_IN6, uintptr(unsafe.Pointer(&ifr))); err != nil {
		return fmt.Errorf("failed to set IPv6 address via ioctl: %w", err)
	}

	return nil
}

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

func (rm *tun) addRoute(prefix netip.Prefix) error {
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
			unix.RTAX_GATEWAY: rm.linkAddr,
		}
	} else {
		route.Addrs = []netroute.Addr{
			unix.RTAX_DST:     &netroute.Inet6Addr{IP: prefix.Masked().Addr().As16()},
			unix.RTAX_NETMASK: &netroute.Inet6Addr{IP: prefixToMask(prefix).As16()},
			unix.RTAX_GATEWAY: rm.linkAddr,
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

func (rm *tun) delRoute(prefix netip.Prefix) error {
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
			unix.RTAX_GATEWAY: rm.linkAddr,
		}
	} else {
		route.Addrs = []netroute.Addr{
			unix.RTAX_DST:     &netroute.Inet6Addr{IP: prefix.Masked().Addr().As16()},
			unix.RTAX_NETMASK: &netroute.Inet6Addr{IP: prefixToMask(prefix).As16()},
			unix.RTAX_GATEWAY: rm.linkAddr,
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

func ioctl(a1, a2, a3 uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, a1, a2, a3)
	if errno != 0 {
		return errno
	}
	return nil
}

func prefixToMask(prefix netip.Prefix) netip.Addr {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		// Create IPv4 netmask from prefix length
		mask := ^uint32(0) << (32 - bits)
		return netip.AddrFrom4([4]byte{
			byte(mask >> 24),
			byte(mask >> 16),
			byte(mask >> 8),
			byte(mask),
		})
	} else {
		// Create IPv6 netmask from prefix length
		var mask [16]byte
		for i := 0; i < bits/8; i++ {
			mask[i] = 0xff
		}
		if bits%8 != 0 {
			mask[bits/8] = ^byte(0) << (8 - bits%8)
		}
		return netip.AddrFrom16(mask)
	}
}
