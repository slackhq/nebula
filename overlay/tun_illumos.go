//go:build illumos && !e2e_testing

package overlay

// illumos tun support, on top of the STREAMS based tuntap driver (/dev/tun), which
// OmniOS, OpenIndiana and SmartOS ship or package.
//
// Plumbing follows what OpenVPN and the Joyent wireguard-go port do:
//
//  1. open /dev/tun and ask it for a PPA (unit number) with I_STR/TUNNEWPPA;
//     this fd is the one packets are read from and written to
//  2. open /dev/tun again, push the "ip" module onto it and select the unit (IF_UNITSEL)
//  3. I_PLINK that stream under an IP mux fd (/dev/udp) and record the mux id on the
//     interface with SIOCSLIFMUXID; the link is persistent, so the second fd is closed
//  4. on Close, I_PUNLINK the mux id, which unplumbs the interface
//
// In tun mode the driver hands over bare IP packets, one per STREAMS message, without
// the 4 byte address family header the BSDs use, so packets are moved with getmsg/putmsg.
//
// Addresses, MTU and routes are set with ifconfig(8) and route(8), the same way OpenVPN
// configures tun interfaces on illumos. The IPv6 side of the interface is plumbed by
// ifconfig ("inet6 plumb"), which links a second stream for the same unit under IPv6;
// the driver delivers packets of both families on the one packet stream from step 1,
// and picks the upper stream for a written packet by its IP version. Close unplumbs it
// again before unlinking the IPv4 side.

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
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
	illumosTunDev  = "/dev/tun"
	illumosIPMux   = "/dev/udp"
	illumosIfconfg = "/usr/sbin/ifconfig"
	illumosRoute   = "/usr/sbin/route"
)

var illumosTunNameRE = regexp.MustCompile(`^tun([0-9]+)$`)

type tun struct {
	Device      string
	vpnNetworks []netip.Prefix
	MTU         int
	Routes      atomic.Pointer[[]Route]
	routeTree   atomic.Pointer[bart.Table[routing.Gateways]]
	l           *slog.Logger

	f       *os.File // the packet stream from step 1
	ipFd    int      // the IP mux the interface is linked under, -1 once unplumbed
	ipMuxID int
	inet6   atomic.Bool // the IPv6 side was plumbed by Activate

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
		ipFd:        -1,
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

// plumb opens the tun device and links it into IP, see the top of the file.
// want is the unit to ask for, or -1 for the first free one.
func (t *tun) plumb(want int) (err error) {
	tunFd, err := unix.Open(illumosTunDev, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("could not open %s, is the tuntap driver installed? %w", illumosTunDev, err)
	}
	defer func() {
		if err != nil {
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

	ipFd, err := unix.Open(illumosIPMux, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("could not open %s: %w", illumosIPMux, err)
	}
	defer func() {
		if err != nil {
			_ = unix.Close(ipFd)
		}
	}()

	ifFd, err := unix.Open(illumosTunDev, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("could not open %s a second time: %w", illumosTunDev, err)
	}
	// The I_PLINK below is persistent, it survives closing this fd
	defer unix.Close(ifFd)

	ipMod := []byte("ip\x00")
	if err = ioctlPtr(ifFd, unix.I_PUSH, unsafe.Pointer(&ipMod[0])); err != nil {
		return fmt.Errorf("could not push the ip module onto %s: %w", t.Device, err)
	}

	unit := int32(ppa)
	if err = ioctlPtr(ifFd, unix.IF_UNITSEL, unsafe.Pointer(&unit)); err != nil {
		return fmt.Errorf("could not select unit %d: %w", ppa, err)
	}

	muxID, err := unix.IoctlSetIntRetInt(ipFd, unix.I_PLINK, ifFd)
	if err != nil {
		return fmt.Errorf("could not link %s into ip: %w", t.Device, err)
	}

	var lifr unix.Lifreq
	if err = lifr.SetName(t.Device); err != nil {
		return err
	}
	// lifr_ip_muxid is lif_muxid[0], an int at the start of the lifr_lifru union
	*(*int32)(unsafe.Pointer(&lifr.Lifru[0])) = int32(muxID)
	if err = unix.IoctlLifreq(ipFd, unix.SIOCSLIFMUXID, &lifr); err != nil {
		_, _ = unix.IoctlSetIntRetInt(ipFd, unix.I_PUNLINK, muxID)
		return fmt.Errorf("could not set the ip mux id of %s: %w", t.Device, err)
	}

	// Non blocking, so the fd goes through the runtime poller (event ports) and
	// Close can wake a reader parked in Read.
	if err = unix.SetNonblock(tunFd, true); err != nil {
		_, _ = unix.IoctlSetIntRetInt(ipFd, unix.I_PUNLINK, muxID)
		return fmt.Errorf("could not set %s non blocking: %w", t.Device, err)
	}

	t.f = os.NewFile(uintptr(tunFd), illumosTunDev)
	t.ipFd = ipFd
	t.ipMuxID = muxID
	t.l.Info("Plumbed tun interface", "interface", t.Device)
	return nil
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
		if t.inet6.Swap(false) {
			if err := runCmd(t.l, illumosIfconfg, t.Device, "inet6", "unplumb"); err != nil {
				errs = append(errs, err)
			}
		}
		if t.ipFd >= 0 {
			if _, err := unix.IoctlSetIntRetInt(t.ipFd, unix.I_PUNLINK, t.ipMuxID); err != nil {
				errs = append(errs, fmt.Errorf("could not unplumb %s: %w", t.Device, err))
			}
			_ = unix.Close(t.ipFd)
			t.ipFd = -1
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

	var have4, have6 bool
	for _, cidr := range t.vpnNetworks {
		var err error
		switch {
		case cidr.Addr().Is4() && !have4:
			err = t.configure4(cidr)
			have4 = true
		case cidr.Addr().Is6() && !have6:
			err = t.configure6(cidr)
			have6 = true
		default:
			t.l.Warn("only one vpn network per address family is configured on illumos tun interfaces, skipping", "network", cidr)
			continue
		}
		if err != nil {
			return err
		}

		if err := addRoute(t.l, t.Device, cidr.Masked(), t.vpnNetworks); err != nil {
			return fmt.Errorf("failed to set route for vpn network %v: %w", cidr, err)
		}
	}

	if !have4 && !have6 {
		return fmt.Errorf("no vpn network to configure on %s", t.Device)
	}

	return t.addRoutes(false, nil)
}

// checkOverlap refuses vpn networks that contain an address already on another
// interface. The kernel would then have two ways to reach that network, and the
// errors that follow from route(8) do not point at the cause.
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

// configure4 makes the IPv4 side a point to point link whose far end is this host itself;
// addRoute then sends the whole vpn network through it. This is OpenVPN's "topology
// subnet" setup on illumos.
func (t *tun) configure4(cidr netip.Prefix) error {
	addr := cidr.Addr().String()
	err := runCmd(t.l, illumosIfconfg, t.Device,
		addr, addr,
		"netmask", prefixToMask(cidr).String(),
		"mtu", strconv.Itoa(t.MTU),
		"up")
	if err != nil {
		return fmt.Errorf("failed to configure %s: %w", t.Device, err)
	}
	return nil
}

// configure6 plumbs the IPv6 side of the interface and sets it up the same way as IPv4.
func (t *tun) configure6(cidr netip.Prefix) error {
	// A leftover IPv6 instance, from a nebula that did not get to clean up, would make
	// plumb fail; there is normally nothing to unplumb, so the error is ignored.
	_ = runCmd(t.l, illumosIfconfg, t.Device, "inet6", "unplumb")

	addr := cidr.Addr().String()
	err := runCmd(t.l, illumosIfconfg, t.Device, "inet6", "plumb",
		addr+"/"+strconv.Itoa(cidr.Bits()), addr,
		"mtu", strconv.Itoa(t.MTU),
		"up")
	if err != nil {
		return fmt.Errorf("failed to configure IPv6 on %s: %w", t.Device, err)
	}
	t.inet6.Store(true)
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

		err := addRoute(t.l, t.Device, r.Cidr, t.vpnNetworks)
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

		err := delRoute(t.l, t.Device, r.Cidr, t.vpnNetworks)
		if err != nil {
			t.l.Error("Failed to remove route", "error", err, "route", r)
			rl.Failed()
		} else {
			t.l.Info("Removed route", "route", r)
		}
	}
	return nil
}

// addRoute sends everything in prefix straight into the tun interface dev.
//
// The only address the interface has is this host's own vpn address, and route(8)
// rejects that as an unreachable next hop unless it is told the route is an interface
// route. Which spelling of that route(8) takes has varied between illumos
// distributions and releases, so the forms in routeForms are tried in order and the
// first one route(8) accepts is kept. Every rejected attempt is logged at debug level
// and, when none is accepted, returned in the error.
func addRoute(l *slog.Logger, dev string, prefix netip.Prefix, gateways []netip.Prefix) error {
	gw, err := selectGateway(prefix, gateways)
	if err != nil {
		return err
	}

	var errs []error
	for i, form := range routeForms(dev, prefix, gw) {
		err := runCmd(l, illumosRoute, append([]string{"-n", "add"}, form...)...)
		if err != nil && strings.Contains(err.Error(), "entry exists") {
			err = runCmd(l, illumosRoute, append([]string{"-n", "change"}, form...)...)
		}
		if err == nil {
			if i > 0 {
				l.Info("route(8) accepted a fallback form", "route", prefix, "args", form)
			}
			return nil
		}
		l.Debug("route(8) rejected a form, trying the next", "route", prefix, "error", err)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// delRoute removes a route addRoute installed, trying the same forms.
func delRoute(l *slog.Logger, dev string, prefix netip.Prefix, gateways []netip.Prefix) error {
	gw, err := selectGateway(prefix, gateways)
	if err != nil {
		return err
	}

	var errs []error
	for _, form := range routeForms(dev, prefix, gw) {
		err := runCmd(l, illumosRoute, append([]string{"-n", "delete"}, form...)...)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	for _, err := range errs {
		if !strings.Contains(err.Error(), "not in table") {
			return errors.Join(errs...)
		}
	}
	l.Info("Route was already removed", "route", prefix)
	return nil
}

// routeForms lists the ways of telling route(8) to send prefix into dev, most specific
// first: an interface route pinned to dev, an interface route found through dev's
// address, and a route through dev's address pinned to dev.
func routeForms(dev string, prefix netip.Prefix, gw netip.Prefix) [][]string {
	family := "-inet"
	if prefix.Addr().Is6() {
		family = "-inet6"
	}
	dst := prefix.Masked().String()
	via := gw.Addr().String()
	return [][]string{
		{family, "-net", dst, via, "-interface", "-ifp", dev},
		{family, "-net", dst, via, "-interface"},
		{family, "-net", dst, via, "-ifp", dev},
	}
}

func runCmd(l *slog.Logger, name string, args ...string) error {
	l.Debug("command", "cmd", name, "args", args)
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
