package nebula

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Tun struct {
	io.ReadWriteCloser
	fd           int
	Device       string
	Cidr         *net.IPNet
	MaxMTU       int
	DefaultMTU   int
	TXQueueLen   int
	Routes       []route
	UnsafeRoutes []route
}

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [8]byte
}

func ioctl(a1, a2, a3 uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, a1, a2, a3)
	if errno != 0 {
		return errno
	}
	return nil
}

/*
func ipv4(addr string) (o [4]byte, err error) {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		err = fmt.Errorf("failed to parse addr %s", addr)
		return
	}
	for i, b := range ip {
		o[i] = b
	}
	return
}
*/

const (
	cIFF_TUN   = 0x0001
	cIFF_NO_PI = 0x1000
)

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

func newTunFromFd(deviceFd int, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int) (ifce *Tun, err error) {

	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")

	ifce = &Tun{
		ReadWriteCloser: file,
		fd:              int(file.Fd()),
		Device:          "tun0",
		Cidr:            cidr,
		DefaultMTU:      defaultMTU,
		TXQueueLen:      txQueueLen,
		Routes:          routes,
		UnsafeRoutes:    unsafeRoutes,
	}
	return
}

func newTun(deviceName string, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int) (ifce *Tun, err error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var req ifReq
	req.Flags = uint16(cIFF_TUN | cIFF_NO_PI)
	copy(req.Name[:], deviceName)
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		return
	}
	name := strings.Trim(string(req.Name[:]), "\x00")

	file := os.NewFile(uintptr(fd), "/dev/net/tun")

	maxMTU := defaultMTU
	for _, r := range routes {
		if r.mtu > maxMTU {
			maxMTU = r.mtu
		}
	}

	ifce = &Tun{
		ReadWriteCloser: file,
		fd:              int(file.Fd()),
		Device:          name,
		Cidr:            cidr,
		MaxMTU:          maxMTU,
		DefaultMTU:      defaultMTU,
		TXQueueLen:      txQueueLen,
		Routes:          routes,
		UnsafeRoutes:    unsafeRoutes,
	}
	return
}

func (c *Tun) WriteRaw(b []byte) error {
	var nn int
	for {
		max := len(b)
		n, err := unix.Write(c.fd, b[nn:max])
		if n > 0 {
			nn += n
		}
		if nn == len(b) {
			return err
		}

		if err != nil {
			return err
		}

		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
}

func (c Tun) deviceBytes() (o [16]byte) {
	for i, c := range c.Device {
		o[i] = byte(c)
	}
	return
}

func (c Tun) Activate() error {
	devName := c.deviceBytes()

	var addr, mask [4]byte

	copy(addr[:], c.Cidr.IP.To4())
	copy(mask[:], c.Cidr.Mask)

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
	ifm := ifreqMTU{Name: devName, MTU: int32(c.MaxMTU)}
	if err = ioctl(fd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifm))); err != nil {
		// This is currently a non fatal condition because the route table must have the MTU set appropriately as well
		l.WithError(err).Error("Failed to set tun mtu")
	}

	// Set the transmit queue length
	ifrq := ifreqQLEN{Name: devName, Value: int32(c.TXQueueLen)}
	if err = ioctl(fd, unix.SIOCSIFTXQLEN, uintptr(unsafe.Pointer(&ifrq))); err != nil {
		// If we can't set the queue length nebula will still work but it may lead to packet loss
		l.WithError(err).Error("Failed to set tun tx queue length")
	}

	// Bring up the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to bring the tun device up: %s", err)
	}

	// Set the routes
	link, err := netlink.LinkByName(c.Device)
	if err != nil {
		return fmt.Errorf("failed to get tun device link: %s", err)
	}

	// Default route
	dr := &net.IPNet{IP: c.Cidr.IP.Mask(c.Cidr.Mask), Mask: c.Cidr.Mask}
	nr := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dr,
		MTU:       c.DefaultMTU,
		Scope:     unix.RT_SCOPE_LINK,
		Src:       c.Cidr.IP,
		Protocol:  unix.RTPROT_KERNEL,
		Table:     unix.RT_TABLE_MAIN,
		Type:      unix.RTN_UNICAST,
	}
	err = netlink.RouteReplace(&nr)
	if err != nil {
		return fmt.Errorf("failed to set mtu %v on the default route %v; %v", c.DefaultMTU, dr, err)
	}

	// Path routes
	for _, r := range c.Routes {
		nr := netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       r.route,
			MTU:       r.mtu,
			Scope:     unix.RT_SCOPE_LINK,
		}

		err = netlink.RouteAdd(&nr)
		if err != nil {
			return fmt.Errorf("failed to set mtu %v on route %v; %v", r.mtu, r.route, err)
		}
	}

	// Unsafe path routes
	for _, r := range c.UnsafeRoutes {
		nr := netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       r.route,
			MTU:       r.mtu,
			Scope:     unix.RT_SCOPE_LINK,
		}

		err = netlink.RouteAdd(&nr)
		if err != nil {
			return fmt.Errorf("failed to set mtu %v on route %v; %v", r.mtu, r.route, err)
		}
	}

	// Run the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to run tun device: %s", err)
	}

	return nil
}
