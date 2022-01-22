//go:build !ios && !e2e_testing
// +build !ios,!e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

type tun struct {
	io.ReadWriteCloser
	Device     string
	cidr       *net.IPNet
	DefaultMTU int
	Routes     []Route
	routeTree  *cidr.Tree4
	l          *logrus.Logger

	// cache out buffer since we need to prepend 4 bytes for tun metadata
	out []byte
}

type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
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

var sockaddrCtlSize uintptr = 32

const (
	_SYSPROTO_CONTROL = 2              //define SYSPROTO_CONTROL 2 /* kernel control protocol */
	_AF_SYS_CONTROL   = 2              //#define AF_SYS_CONTROL 2 /* corresponding sub address type */
	_PF_SYSTEM        = unix.AF_SYSTEM //#define PF_SYSTEM AF_SYSTEM
	_CTLIOCGINFO      = 3227799043     //#define CTLIOCGINFO     _IOWR('N', 3, struct ctl_info)
	utunControlName   = "com.apple.net.utun_control"
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

func newTun(l *logrus.Logger, name string, cidr *net.IPNet, defaultMTU int, routes []Route, _ int, _ bool) (*tun, error) {
	routeTree, err := makeRouteTree(l, routes, false)
	if err != nil {
		return nil, err
	}

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

	fd, err := unix.Socket(_PF_SYSTEM, unix.SOCK_DGRAM, _SYSPROTO_CONTROL)
	if err != nil {
		return nil, fmt.Errorf("system socket: %v", err)
	}

	var ctlInfo = &struct {
		ctlID   uint32
		ctlName [96]byte
	}{}

	copy(ctlInfo.ctlName[:], utunControlName)

	err = ioctl(uintptr(fd), uintptr(_CTLIOCGINFO), uintptr(unsafe.Pointer(ctlInfo)))
	if err != nil {
		return nil, fmt.Errorf("CTLIOCGINFO: %v", err)
	}

	sc := sockaddrCtl{
		scLen:     uint8(sockaddrCtlSize),
		scFamily:  unix.AF_SYSTEM,
		ssSysaddr: _AF_SYS_CONTROL,
		scID:      ctlInfo.ctlID,
		scUnit:    uint32(ifIndex) + 1,
	}

	_, _, errno := unix.RawSyscall(
		unix.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sc)),
		sockaddrCtlSize,
	)
	if errno != 0 {
		return nil, fmt.Errorf("SYS_CONNECT: %v", errno)
	}

	var ifName struct {
		name [16]byte
	}
	ifNameSize := uintptr(len(ifName.name))
	_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		2, // SYSPROTO_CONTROL
		2, // UTUN_OPT_IFNAME
		uintptr(unsafe.Pointer(&ifName)),
		uintptr(unsafe.Pointer(&ifNameSize)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("SYS_GETSOCKOPT: %v", errno)
	}
	name = string(ifName.name[:ifNameSize-1])

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		return nil, fmt.Errorf("SetNonblock: %v", err)
	}

	file := os.NewFile(uintptr(fd), "")

	tun := &tun{
		ReadWriteCloser: file,
		Device:          name,
		cidr:            cidr,
		DefaultMTU:      defaultMTU,
		Routes:          routes,
		routeTree:       routeTree,
		l:               l,
	}

	return tun, nil
}

func (t *tun) deviceBytes() (o [16]byte) {
	for i, c := range t.Device {
		o[i] = byte(c)
	}
	return
}

func newTunFromFd(_ *logrus.Logger, _ int, _ *net.IPNet, _ int, _ []Route, _ int) (*tun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in Darwin")
}

func (t *tun) Close() error {
	if t.ReadWriteCloser != nil {
		return t.ReadWriteCloser.Close()
	}
	return nil
}

func (t *tun) Activate() error {
	devName := t.deviceBytes()

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
	ifm := ifreqMTU{Name: devName, MTU: int32(t.DefaultMTU)}
	if err = ioctl(fd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifm))); err != nil {
		return fmt.Errorf("failed to set tun mtu: %v", err)
	}

	/*
		// Set the transmit queue length
		ifrq := ifreqQLEN{Name: devName, Value: int32(t.TXQueueLen)}
		if err = ioctl(fd, unix.SIOCSIFTXQLEN, uintptr(unsafe.Pointer(&ifrq))); err != nil {
			// If we can't set the queue length nebula will still work but it may lead to packet loss
			l.WithError(err).Error("Failed to set tun tx queue length")
		}
	*/

	// Bring up the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to bring the tun device up: %s", err)
	}

	routeSock, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("unable to create AF_ROUTE socket: %v", err)
	}
	defer func() {
		unix.Shutdown(routeSock, unix.SHUT_RDWR)
		err := unix.Close(routeSock)
		if err != nil {
			t.l.WithError(err).Error("failed to close AF_ROUTE socket")
		}
	}()

	routeAddr := &netroute.Inet4Addr{}
	maskAddr := &netroute.Inet4Addr{}
	linkAddr, err := getLinkAddr(t.Device)
	if err != nil {
		return err
	}
	if linkAddr == nil {
		return fmt.Errorf("unable to discover link_addr for tun interface")
	}

	copy(routeAddr.IP[:], addr[:])
	copy(maskAddr.IP[:], mask[:])
	err = addRoute(routeSock, routeAddr, maskAddr, linkAddr)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			err = fmt.Errorf("unable to add tun route, identical route already exists: %s", t.cidr)
		}
		return err
	}

	// Run the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to run tun device: %s", err)
	}

	// Unsafe path routes
	for _, r := range t.Routes {
		if r.Via == nil {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		copy(routeAddr.IP[:], r.Cidr.IP.To4())
		copy(maskAddr.IP[:], net.IP(r.Cidr.Mask).To4())

		err = addRoute(routeSock, routeAddr, maskAddr, linkAddr)
		if err != nil {
			if errors.Is(err, unix.EEXIST) {
				t.l.WithField("route", r.Cidr).
					Warnf("unable to add unsafe_route, identical route already exists")
			} else {
				return err
			}
		}

		// TODO how to set metric
	}

	return nil
}

func (t *tun) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	r := t.routeTree.MostSpecificContains(ip)
	if r != nil {
		return r.(iputil.VpnIp)
	}

	return 0
}

// Get the LinkAddr for the interface of the given name
// TODO: Is there an easier way to fetch this when we create the interface?
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

func addRoute(sock int, addr, mask *netroute.Inet4Addr, link *netroute.LinkAddr) error {
	r := netroute.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_ADD,
		Flags:   unix.RTF_UP,
		Seq:     1,
		Addrs: []netroute.Addr{
			unix.RTAX_DST:     addr,
			unix.RTAX_GATEWAY: link,
			unix.RTAX_NETMASK: mask,
		},
	}

	data, err := r.Marshal()
	if err != nil {
		return fmt.Errorf("failed to create route.RouteMessage: %w", err)
	}
	_, err = unix.Write(sock, data[:])
	if err != nil {
		return fmt.Errorf("failed to write route.RouteMessage to socket: %w", err)
	}

	return nil
}

func (t *tun) Read(to []byte) (int, error) {

	buf := make([]byte, len(to)+4)

	n, err := t.ReadWriteCloser.Read(buf)

	copy(to, buf[4:])
	return n - 4, err
}

// Write is only valid for single threaded use
func (t *tun) Write(from []byte) (int, error) {
	buf := t.out
	if cap(buf) < len(from)+4 {
		buf = make([]byte, len(from)+4)
		t.out = buf
	}
	buf = buf[:len(from)+4]

	if len(from) == 0 {
		return 0, syscall.EIO
	}

	// Determine the IP Family for the NULL L2 Header
	ipVer := from[0] >> 4
	if ipVer == 4 {
		buf[3] = syscall.AF_INET
	} else if ipVer == 6 {
		buf[3] = syscall.AF_INET6
	} else {
		return 0, fmt.Errorf("unable to determine IP version from packet")
	}

	copy(buf[4:], from)

	n, err := t.ReadWriteCloser.Write(buf)
	return n - 4, err
}

func (t *tun) Cidr() *net.IPNet {
	return t.cidr
}

func (t *tun) Name() string {
	return t.Device
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for darwin")
}
