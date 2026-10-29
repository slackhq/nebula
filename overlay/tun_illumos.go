//go:build illumos && !e2e_testing

package overlay

// illumos tun support, on top of the STREAMS based tuntap driver (/dev/tun), which
// OmniOS, OpenIndiana and SmartOS ship or package.
//
// Plumbing follows what ifconfig(8), OpenVPN and the Joyent wireguard-go port do:
//
//  1. open /dev/tun and ask it for a PPA (unit number) with I_STR/TUNNEWPPA;
//     this fd is the one packets are read from and written to
//  2. for each address family in use, open /dev/tun again, push the "ip" module onto
//     it and name it tunN for that family (IF_UNITSEL for IPv4, SIOCSLIFNAME with
//     IFF_IPV6 for IPv6)
//  3. I_PLINK that stream under an IP mux of the family (/dev/udp, /dev/udp6) and record
//     the mux id on the interface with SIOCSLIFMUXID; the link is persistent, so the
//     stream's own fd is closed
//  4. on Close, I_PUNLINK the mux ids, which unplumbs the interface
//
// In tun mode the driver hands over bare IP packets of both families, one per STREAMS
// message, without the 4 byte address family header the BSDs use, so packets are moved
// with getmsg/putmsg on the stream from step 1.
//
// Addresses, netmasks, the MTU and the UP flag are set with the SIOC*LIF* ioctls, and
// routes with routing socket messages, the same interfaces ifconfig(8) and route(8) use.
// The first vpn network of each family goes on tunN itself; any further ones get a
// logical interface each (tunN:1, tunN:2, ...), which is how illumos carries more than
// one address of a family on an interface.

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
	"golang.org/x/sys/unix"
)

const (
	illumosTunDev = "/dev/tun"
	illumosIPMux  = "/dev/udp"
	illumosIP6Mux = "/dev/udp6"
)

var illumosTunNameRE = regexp.MustCompile(`^tun([0-9]+)$`)

type tun struct {
	Device      string
	vpnNetworks []netip.Prefix
	MTU         int
	Routes      atomic.Pointer[[]Route]
	routeTree   atomic.Pointer[bart.Table[routing.Gateways]]
	l           *slog.Logger

	f   *os.File // the packet stream from step 1
	ip4 ipLink   // the IPv4 side of the interface, if any vpn network is IPv4
	ip6 ipLink   // the IPv6 side of the interface, if any vpn network is IPv6
	seq atomic.Int32

	closeOnce sync.Once
	closeErr  error
}

func newTunFromFd(_ *config.C, _ *slog.Logger, _ int, _ []netip.Prefix) (*tun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in illumos")
}

func newTun(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, _ bool) (*tun, error) {
	want := -1
	if name := c.GetString("tun.dev", ""); name != "" {
		m := illumosTunNameRE.FindStringSubmatch(name)
		if m == nil {
			l.Warn("interface name must be tun[0-9]+ on illumos, ignoring", "name", name)
		} else {
			want, _ = strconv.Atoi(m[1])
		}
	}

	t := &tun{
		vpnNetworks: vpnNetworks,
		MTU:         getMTU(l, c),
		l:           l,
		ip4:         ipLink{muxFd: -1},
		ip6:         ipLink{muxFd: -1},
	}

	if err := t.plumb(want); err != nil {
		return nil, err
	}

	if err := t.reload(c, true, nil); err != nil {
		_ = t.Close()
		return nil, err
	}

	c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
		r.RestartRequiredIfChanged("tun.mtu", "tun.dev")
		if err := t.reload(c, false, r); err != nil {
			util.LogWithContextIfNeeded("failed to reload tun device", err, t.l)
			r.Failed()
		}
	})

	return t, nil
}

// ipLink is one address family's stream of the interface, linked under that family's IP mux.
type ipLink struct {
	muxFd int // -1 when the family is not plumbed
	muxID int
}

// plumb opens the tun device and links it into IP for every family in vpnNetworks, see
// the top of the file. want is the unit to ask for, or -1 for the first free one.
func (t *tun) plumb(want int) (err error) {
	tunFd, err := unix.Open(illumosTunDev, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("could not open %s, is the tuntap driver installed? %w", illumosTunDev, err)
	}
	defer func() {
		if err != nil {
			t.unplumb()
			_ = unix.Close(tunFd)
		}
	}()

	ppa, err := newPPA(tunFd, want)
	if want >= 0 && errors.Is(err, unix.EEXIST) {
		// Units are shared by every zone on the host, so tunN may well be taken by
		// another zone or the global zone. Like darwin, a name that can't be had is
		// not worth refusing to start over.
		t.l.Warn("requested tun unit is in use, possibly by another zone; using the first free one",
			"requested", fmt.Sprintf("tun%d", want))
		ppa, err = newPPA(tunFd, -1)
	}
	if err != nil {
		return err
	}
	t.Device = fmt.Sprintf("tun%d", ppa)

	var want4, want6 bool
	for _, n := range t.vpnNetworks {
		want4 = want4 || n.Addr().Is4()
		want6 = want6 || n.Addr().Is6()
	}
	if want4 {
		if t.ip4, err = plumbFamily(t.Device, ppa, false); err != nil {
			return err
		}
	}
	if want6 {
		if t.ip6, err = plumbFamily(t.Device, ppa, true); err != nil {
			return err
		}
	}

	// Non blocking, so the fd goes through the runtime poller (event ports) and
	// Close can wake a reader parked in Read.
	if err = unix.SetNonblock(tunFd, true); err != nil {
		return fmt.Errorf("could not set %s non blocking: %w", t.Device, err)
	}

	t.f = os.NewFile(uintptr(tunFd), illumosTunDev)
	t.l.Info("Plumbed tun interface", "interface", t.Device, "ipv4", want4, "ipv6", want6)
	return nil
}

// plumbFamily links a new stream for unit ppa of the tun driver under the IP mux of one
// address family, which brings the interface name into existence for that family.
func plumbFamily(name string, ppa int, v6 bool) (_ ipLink, err error) {
	family, muxDev := "IPv4", illumosIPMux
	if v6 {
		family, muxDev = "IPv6", illumosIP6Mux
	}

	muxFd, err := unix.Open(muxDev, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return ipLink{muxFd: -1}, fmt.Errorf("could not open %s: %w", muxDev, err)
	}
	defer func() {
		if err != nil {
			_ = unix.Close(muxFd)
		}
	}()

	ifFd, err := unix.Open(illumosTunDev, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return ipLink{muxFd: -1}, fmt.Errorf("could not open %s for %s: %w", illumosTunDev, family, err)
	}
	// The I_PLINK below is persistent, it survives closing this fd
	defer unix.Close(ifFd)

	ipMod := []byte("ip\x00")
	if err = ioctlPtr(ifFd, unix.I_PUSH, unsafe.Pointer(&ipMod[0])); err != nil {
		return ipLink{muxFd: -1}, fmt.Errorf("could not push the ip module onto %s for %s: %w", name, family, err)
	}

	if !v6 {
		// IPv4 is what IF_UNITSEL selects; OpenVPN plumbs its tun interfaces this way.
		unit := int32(ppa)
		if err = ioctlPtr(ifFd, unix.IF_UNITSEL, unsafe.Pointer(&unit)); err != nil {
			return ipLink{muxFd: -1}, fmt.Errorf("could not select unit %d: %w", ppa, err)
		}
	} else {
		// IPv6 has to be named explicitly, the way ifconfig(8) plumbs any interface:
		// keep the flags the driver reports, but a stream that has no name yet reports
		// itself as IPv4, so swap that for IFF_IPV6 (and drop IFF_BROADCAST, which IPv6
		// has no use for). The kernel refuses a name with both families set.
		var lifr unix.Lifreq
		_ = unix.IoctlLifreq(ifFd, unix.SIOCGLIFFLAGS, &lifr)
		flags := (lifrFlags(&lifr) | unix.IFF_IPV6) &^ (unix.IFF_IPV4 | unix.IFF_BROADCAST)
		lifr = unix.Lifreq{}
		if err = lifr.SetName(name); err != nil {
			return ipLink{muxFd: -1}, err
		}
		*(*uint32)(unsafe.Pointer(&lifr.Lifru1[0])) = uint32(ppa) // lifr_ppa
		setLifrFlags(&lifr, flags)
		if err = unix.IoctlLifreq(ifFd, unix.SIOCSLIFNAME, &lifr); err != nil {
			return ipLink{muxFd: -1}, fmt.Errorf("could not name %s for IPv6: %w", name, err)
		}
	}

	muxID, err := unix.IoctlSetIntRetInt(muxFd, unix.I_PLINK, ifFd)
	if err != nil {
		return ipLink{muxFd: -1}, fmt.Errorf("could not link %s into %s: %w", name, family, err)
	}

	var lifr unix.Lifreq
	if err = lifr.SetName(name); err != nil {
		_, _ = unix.IoctlSetIntRetInt(muxFd, unix.I_PUNLINK, muxID)
		return ipLink{muxFd: -1}, err
	}
	// lifr_ip_muxid is lif_muxid[0], an int at the start of the lifr_lifru union
	*(*int32)(unsafe.Pointer(&lifr.Lifru[0])) = int32(muxID)
	if err = unix.IoctlLifreq(muxFd, unix.SIOCSLIFMUXID, &lifr); err != nil {
		_, _ = unix.IoctlSetIntRetInt(muxFd, unix.I_PUNLINK, muxID)
		return ipLink{muxFd: -1}, fmt.Errorf("could not set the %s mux id of %s: %w", family, name, err)
	}

	return ipLink{muxFd: muxFd, muxID: muxID}, nil
}

// unplumb removes the interface from every family it was linked into. Logical
// interfaces, addresses and the routes through the interface go with it.
func (t *tun) unplumb() error {
	var errs []error
	for _, link := range []*ipLink{&t.ip6, &t.ip4} {
		if link.muxFd < 0 {
			continue
		}
		if _, err := unix.IoctlSetIntRetInt(link.muxFd, unix.I_PUNLINK, link.muxID); err != nil {
			errs = append(errs, fmt.Errorf("could not unplumb %s: %w", t.Device, err))
		}
		_ = unix.Close(link.muxFd)
		link.muxFd = -1
	}
	return errors.Join(errs...)
}

// newPPA asks the tun driver for unit want, or for the first free unit when want is -1.
func newPPA(fd int, want int) (int, error) {
	try := func(n int32) (int, error) {
		s := unix.Strioctl{
			Cmd: unix.TUNNEWPPA,
			Len: int32(unsafe.Sizeof(n)),
			Dp:  (*int8)(unsafe.Pointer(&n)),
		}
		return unix.IoctlSetStrioctlRetInt(fd, unix.I_STR, &s)
	}

	if want >= 0 {
		ppa, err := try(int32(want))
		if err != nil {
			return -1, fmt.Errorf("could not allocate tun%d: %w", want, err)
		}
		return ppa, nil
	}

	ppa, err := try(-1)
	if err == nil {
		return ppa, nil
	}
	// Some builds of the driver do not take -1; walk the units instead
	for n := int32(0); n < 256; n++ {
		ppa, err = try(n)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return -1, fmt.Errorf("could not allocate a tun unit: %w", err)
		}
		return ppa, nil
	}
	return -1, fmt.Errorf("could not allocate a tun unit: all are in use")
}

// ioctlPtr is linkname'd to x/sys/unix's own pointer taking ioctl, which keeps arg
// alive and pinned for the call; x/sys exports no such wrapper for these requests.
//
//go:linkname ioctlPtr golang.org/x/sys/unix.ioctlPtr
//go:noescape
func ioctlPtr(fd int, req int, arg unsafe.Pointer) (err error)

func (t *tun) Close() error {
	t.closeOnce.Do(func() {
		var errs []error
		if err := t.unplumb(); err != nil {
			errs = append(errs, err)
		}
		if t.f != nil {
			if err := t.f.Close(); err != nil {
				errs = append(errs, fmt.Errorf("error closing tun file: %w", err))
			}
		}
		t.closeErr = errors.Join(errs...)
	})
	return t.closeErr
}

// Read pulls one IP packet, one STREAMS message, off the tun device.
func (t *tun) Read(to []byte) (int, error) {
	rc, err := t.f.SyscallConn()
	if err != nil {
		return 0, err
	}

	var n int
	var callErr error
	err = rc.Read(func(fd uintptr) bool {
		_, data, _, e := unix.Getmsg(int(fd), nil, to)
		if errno, ok := e.(syscall.Errno); ok && errno.Temporary() {
			return false
		}
		callErr = e
		n = len(data)
		return true
	})
	if err != nil {
		return 0, err
	}
	if callErr != nil {
		return 0, callErr
	}
	return n, nil
}

// Write pushes one IP packet onto the tun device.
func (t *tun) Write(from []byte) (int, error) {
	if len(from) == 0 {
		return 0, syscall.EIO
	}

	rc, err := t.f.SyscallConn()
	if err != nil {
		return 0, err
	}

	var callErr error
	err = rc.Write(func(fd uintptr) bool {
		e := unix.Putmsg(int(fd), nil, from, 0)
		if errno, ok := e.(syscall.Errno); ok && errno.Temporary() {
			return false
		}
		callErr = e
		return true
	})
	if err != nil {
		return 0, err
	}
	if callErr != nil {
		return 0, callErr
	}
	return len(from), nil
}

func (t *tun) Activate() error {
	if err := t.checkOverlap(); err != nil {
		return err
	}

	s4, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("could not open an IPv4 socket: %w", err)
	}
	defer unix.Close(s4)
	s6, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("could not open an IPv6 socket: %w", err)
	}
	defer unix.Close(s6)

	var first4, first6 = true, true
	for _, cidr := range t.vpnNetworks {
		sock, first := s4, &first4
		if cidr.Addr().Is6() {
			sock, first = s6, &first6
		}

		name := t.Device
		if !*first {
			// Every further network of the family gets a logical interface of its own.
			if name, err = addLogicalIf(sock, t.Device); err != nil {
				return fmt.Errorf("failed to add a logical interface for %v: %w", cidr, err)
			}
		}

		if err := t.configureIf(sock, name, cidr, *first); err != nil {
			return fmt.Errorf("failed to configure %s for %v: %w", name, cidr, err)
		}
		*first = false

		if err := t.addRoute(cidr.Masked(), cidr.Addr()); err != nil {
			return fmt.Errorf("failed to set route for vpn network %v: %w", cidr, err)
		}
		t.l.Info("Configured vpn network", "interface", name, "network", cidr)
	}

	return t.addRoutes(false, nil)
}

// configureIf gives the (possibly logical) interface name the address of cidr, as a point
// to point link whose far end is this host itself, and brings it up; addRoute then sends
// the whole network through it. This is the "topology subnet" setup OpenVPN uses. The
// MTU belongs to the interface, so it is set on the first one of each family only.
func (t *tun) configureIf(sock int, name string, cidr netip.Prefix, setMTU bool) error {
	steps := []struct {
		what string
		req  int
		set  func(*unix.Lifreq)
	}{
		{"address", unix.SIOCSLIFADDR, func(l *unix.Lifreq) { setLifrAddr(l, cidr.Addr()) }},
		{"destination", unix.SIOCSLIFDSTADDR, func(l *unix.Lifreq) { setLifrAddr(l, cidr.Addr()) }},
		{"netmask", unix.SIOCSLIFNETMASK, func(l *unix.Lifreq) { setLifrAddr(l, prefixToMask(cidr)) }},
	}
	if setMTU {
		steps = append(steps, struct {
			what string
			req  int
			set  func(*unix.Lifreq)
		}{"mtu", unix.SIOCSLIFMTU, func(l *unix.Lifreq) { *(*uint32)(unsafe.Pointer(&l.Lifru[0])) = uint32(t.MTU) }})
	}

	for _, step := range steps {
		var lifr unix.Lifreq
		if err := lifr.SetName(name); err != nil {
			return err
		}
		step.set(&lifr)
		if err := unix.IoctlLifreq(sock, step.req, &lifr); err != nil {
			return fmt.Errorf("could not set the %s: %w", step.what, err)
		}
	}

	var lifr unix.Lifreq
	if err := lifr.SetName(name); err != nil {
		return err
	}
	if err := unix.IoctlLifreq(sock, unix.SIOCGLIFFLAGS, &lifr); err != nil {
		return fmt.Errorf("could not read the flags: %w", err)
	}
	setLifrFlags(&lifr, lifrFlags(&lifr)|unix.IFF_UP)
	if err := unix.IoctlLifreq(sock, unix.SIOCSLIFFLAGS, &lifr); err != nil {
		return fmt.Errorf("could not bring it up: %w", err)
	}
	return nil
}

// addLogicalIf adds the next free logical interface to dev and returns its name, tunN:k.
func addLogicalIf(sock int, dev string) (string, error) {
	var lifr unix.Lifreq
	if err := lifr.SetName(dev); err != nil {
		return "", err
	}
	if err := unix.IoctlLifreq(sock, unix.SIOCLIFADDIF, &lifr); err != nil {
		return "", err
	}
	return lifrName(&lifr), nil
}

func lifrName(l *unix.Lifreq) string {
	b := make([]byte, 0, len(l.Name))
	for _, c := range l.Name {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// lifr_flags is a uint64 at the start of the lifr_lifru union.
func lifrFlags(l *unix.Lifreq) uint64 { return *(*uint64)(unsafe.Pointer(&l.Lifru[0])) }

func setLifrFlags(l *unix.Lifreq, f uint64) { *(*uint64)(unsafe.Pointer(&l.Lifru[0])) = f }

// setLifrAddr writes a into lifr_addr, the sockaddr_storage at the start of lifr_lifru.
func setLifrAddr(l *unix.Lifreq, a netip.Addr) {
	if a.Is4() {
		*(*unix.RawSockaddrInet4)(unsafe.Pointer(&l.Lifru[0])) = unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: a.As4()}
		return
	}
	*(*unix.RawSockaddrInet6)(unsafe.Pointer(&l.Lifru[0])) = unix.RawSockaddrInet6{Family: unix.AF_INET6, Addr: a.As16()}
}

// checkOverlap refuses vpn networks that contain an address already on another
// interface. The kernel would then have two ways to reach that network, and the
// errors the routing socket returns then do not point at the cause.
func (t *tun) checkOverlap() error {
	ifs, err := net.Interfaces()
	if err != nil {
		t.l.Warn("could not list interfaces to check for overlapping networks", "error", err)
		return nil
	}
	for _, ifc := range ifs {
		if ifc.Name == t.Device || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || addr.IsLinkLocalUnicast() {
				continue
			}
			addr = addr.Unmap()
			for _, cidr := range t.vpnNetworks {
				if cidr.Contains(addr) {
					return fmt.Errorf("vpn network %v overlaps %s on interface %s; "+
						"sign the certificate for a subnet that is not in use on this host", cidr, addr, ifc.Name)
				}
			}
		}
	}
	return nil
}

func (t *tun) reload(c *config.C, initial bool, r *config.Reload) error {
	change, routes, err := getAllRoutesFromConfig(t.l, c, t.vpnNetworks, initial)
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
		err := t.removeRoutes(findRemovedRoutes(routes, *oldRoutes), r)
		if err != nil {
			util.LogWithContextIfNeeded("Failed to remove routes", err, t.l)
			r.Failed()
		}

		// Ensure any routes we actually want are installed
		err = t.addRoutes(true, r)
		if err != nil {
			util.LogWithContextIfNeeded("Failed to add routes", err, t.l)
			r.Failed()
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

func (t *tun) Queues(int) ([]tio.Queue, error) {
	return []tio.Queue{tio.NewSingleQueue(t, defaultBatchBufSize)}, nil
}

func (t *tun) addRoutes(logErrors bool, rl *config.Reload) error {
	routes := *t.Routes.Load()

	for _, r := range routes {
		if len(r.Via) == 0 || !r.Install {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		gw, err := selectGateway(r.Cidr, t.vpnNetworks)
		if err == nil {
			err = t.addRoute(r.Cidr, gw.Addr())
		}
		if err != nil {
			retErr := util.NewContextualError("Failed to add route", map[string]any{"route": r}, err)
			if logErrors {
				retErr.Log(t.l)
				rl.Failed()
			} else {
				return retErr
			}
		} else {
			t.l.Info("Added route", "route", r)
		}
	}

	return nil
}

func (t *tun) removeRoutes(routes []Route, rl *config.Reload) error {
	for _, r := range routes {
		if len(r.Via) == 0 || !r.Install {
			// addRoutes never installs these
			continue
		}

		gw, err := selectGateway(r.Cidr, t.vpnNetworks)
		if err == nil {
			err = t.delRoute(r.Cidr, gw.Addr())
		}
		if errors.Is(err, unix.ESRCH) {
			t.l.Info("Route was already removed", "route", r)
		} else if err != nil {
			t.l.Error("Failed to remove route", "error", err, "route", r)
			rl.Failed()
		} else {
			t.l.Info("Removed route", "route", r)
		}
	}
	return nil
}

// addRoute sends everything in prefix straight into the tun interface. local is one of
// this host's own vpn addresses of the same family; it names the interface, so the route
// is an interface route (RTF_GATEWAY clear), what route(8) calls -interface.
func (t *tun) addRoute(prefix netip.Prefix, local netip.Addr) error {
	err := t.routeMsg(unix.RTM_ADD, prefix, local)
	if errors.Is(err, unix.EEXIST) {
		err = t.routeMsg(unix.RTM_CHANGE, prefix, local)
	}
	return err
}

// delRoute removes a route addRoute installed. It returns unix.ESRCH if there was none.
func (t *tun) delRoute(prefix netip.Prefix, local netip.Addr) error {
	return t.routeMsg(unix.RTM_DELETE, prefix, local)
}

// routeMsg writes one message to a routing socket. illumos sockaddrs carry no length, so
// each one is the size of its family's sockaddr, appended right after the header in
// RTA_* bit order, as route(8) lays them out.
func (t *tun) routeMsg(typ uint8, prefix netip.Prefix, local netip.Addr) error {
	prefix = prefix.Masked()
	hdr := unix.RtMsghdr{
		Version: unix.RTM_VERSION,
		Type:    typ,
		Flags:   unix.RTF_UP | unix.RTF_STATIC,
		Addrs:   unix.RTA_DST | unix.RTA_GATEWAY,
		Pid:     int32(os.Getpid()),
		Seq:     t.seq.Add(1),
	}

	msg := make([]byte, unix.SizeofRtMsghdr, unix.SizeofRtMsghdr+3*unix.SizeofSockaddrInet6)
	msg = appendSockaddr(msg, prefix.Addr())
	msg = appendSockaddr(msg, local)
	if prefix.IsSingleIP() {
		hdr.Flags |= unix.RTF_HOST
	} else {
		hdr.Addrs |= unix.RTA_NETMASK
		msg = appendSockaddr(msg, prefixToMask(prefix))
	}
	hdr.Msglen = uint16(len(msg))
	copy(msg, unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), unix.SizeofRtMsghdr))

	sock, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("unable to create AF_ROUTE socket: %w", err)
	}
	defer unix.Close(sock)

	if _, err := unix.Write(sock, msg); err != nil {
		return fmt.Errorf("routing socket refused the route for %v: %w", prefix, err)
	}
	return nil
}

func appendSockaddr(b []byte, a netip.Addr) []byte {
	if a.Is4() {
		sa := unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: a.As4()}
		return append(b, unsafe.Slice((*byte)(unsafe.Pointer(&sa)), unix.SizeofSockaddrInet4)...)
	}
	sa := unix.RawSockaddrInet6{Family: unix.AF_INET6, Addr: a.As16()}
	return append(b, unsafe.Slice((*byte)(unsafe.Pointer(&sa)), unix.SizeofSockaddrInet6)...)
}
