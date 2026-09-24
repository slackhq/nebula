//go:build !ios && !e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
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

type tun struct {
	f           *os.File
	Device      string
	vpnNetworks []netip.Prefix
	DefaultMTU  int
	Routes      atomic.Pointer[[]Route]
	routeTree   atomic.Pointer[bart.Table[routing.Gateways]]
	linkAddr    *netroute.LinkAddr
	// hostOwned means the fd arrived from the OS, which has already configured addressing, mtu
	// and routes for it. NEPacketTunnelProvider on darwin does this.
	hostOwned bool
	l         *slog.Logger

	// noSendmsgX is set once sendmsg_x is refused; WriteBatch then writes one packet at a time.
	noSendmsgX atomic.Bool
	batchMu    sync.Mutex
	batch      tunBatch
}

// tunWriteBatch is how many packets one sendmsg_x call may carry.
const tunWriteBatch = 64

// tunBatch is WriteBatch's scratch, guarded by tun.batchMu. The kernel reads every entry in place.
type tunBatch struct {
	heads [tunWriteBatch][4]byte
	iovs  [tunWriteBatch][2]unix.Iovec
	hdrs  [tunWriteBatch]msghdrX
	pkts  [tunWriteBatch][]byte
}

// msghdrX mirrors xnu's struct msghdr_x (bsd/sys/socket_private.h).
// Keep in sync with msghdrX in udp/udp_darwin.go.
type msghdrX struct {
	Name       *byte
	Namelen    uint32
	Iov        *unix.Iovec
	Iovlen     int32
	Control    *byte
	Controllen uint32
	Flags      int32
	Datalen    uint64
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
		DefaultMTU:  c.GetInt("tun.mtu", DefaultMTU),
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
	// The route tree is still ours, the system routing table is not
	if t.hostOwned {
		return nil
	}

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
	if t.hostOwned {
		return nil
	}

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

// tunReadBatch is the most packets one tunQueue.Read returns.
const tunReadBatch = 64

// tunReadArena is tunQueue's receive buffer. Draining stops once less than defaultBatchBufSize of it
// is left, so every readv has room for the largest packet utun can return at any device MTU.
const tunReadArena = 4 * defaultBatchBufSize

// tunQueue is the darwin tun's Queue. Read drains every packet already queued on the utun, up to
// tunReadBatch, so the caller encrypts and sends them as one batch rather than one per wakeup.
type tunQueue struct {
	t    *tun
	buf  []byte
	pkts [tunReadBatch]tio.Packet
}

// Read waits for the utun to become readable, then reads packets until it would block. An error after
// at least one packet is dropped in favor of returning those packets; a persistent one recurs on the
// next Read.
func (q *tunQueue) Read() ([]tio.Packet, error) {
	rc, err := q.t.f.SyscallConn()
	if err != nil {
		return nil, err
	}

	var head [4]byte
	n, off := 0, 0
	var callErr error
	err = rc.Read(func(fd uintptr) bool {
		for n < tunReadBatch && len(q.buf)-off >= defaultBatchBufSize {
			iovecs := [2]unix.Iovec{
				{Base: &head[0], Len: 4},
				{Base: &q.buf[off], Len: uint64(len(q.buf) - off)},
			}
			l, e := tunReadv(int(fd), iovecs[:])
			if e != nil {
				if errno, ok := e.(syscall.Errno); ok && errno.Temporary() {
					// Park on the poller only while there is nothing to hand back.
					return n > 0
				}
				callErr = e
				return true
			}
			if l < 4 {
				// A datagram too short to carry the AF prefix, or end of file; stop rather than spin on it.
				return true
			}
			end := off + l - 4
			q.pkts[n] = tio.Packet{Bytes: q.buf[off:end:end]}
			n++
			off = end
		}
		return true
	})
	if n > 0 {
		return q.pkts[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return nil, callErr
}

func (q *tunQueue) Write(p []byte) (int, error) { return q.t.Write(p) }

func (q *tunQueue) WriteBatch(pkts [][]byte) error { return q.t.WriteBatch(pkts) }

func (q *tunQueue) Close() error { return q.t.Close() }

// Write pushes one IP packet onto the utun device. Safe for concurrent use:
// the AF prefix and iovecs are per-call stack state, and the fd write itself
// serializes on the runtime's fd mutex (see the Queue contract in tio.go).
func (t *tun) Write(from []byte) (int, error) {
	if len(from) == 0 {
		return 0, syscall.EIO
	}

	var head [4]byte
	af, err := tunAF(from)
	if err != nil {
		return 0, err
	}
	head[3] = af

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

// tunAF returns the utun address-family prefix byte for an IP packet.
func tunAF(pkt []byte) (byte, error) {
	switch pkt[0] >> 4 {
	case 4:
		return syscall.AF_INET, nil
	case 6:
		return syscall.AF_INET6, nil
	default:
		return 0, fmt.Errorf("unable to determine IP version from packet")
	}
}

// WriteBatch writes pkts to the utun device with sendmsg_x, xnu's private batched sendmsg, up to
// tunWriteBatch packets per syscall. The kernel still hands each packet to utun on its own, so this
// saves syscalls, not per-packet kernel work. Safe for concurrent use.
//
// An empty packet or one with no IP version is skipped and reported, as Write would. Any other
// error from sendmsg_x means the kernel took an unknown prefix of that call and dropped the rest, so
// it is reported rather than retried, which could deliver packets twice.
//
// Under mbuf exhaustion, sendmsg_x silently drops packets that writev would have delivered: the
// kernel counts each packet as sent once it is copied in, and when a later allocation fails it
// frees that prefix unsent and returns its length as a short count, which is indistinguishable
// from a real one.
func (t *tun) WriteBatch(pkts [][]byte) error {
	if t.noSendmsgX.Load() {
		return t.writeEach(pkts)
	}

	t.batchMu.Lock()
	defer t.batchMu.Unlock()
	b := &t.batch
	var firstErr error
	for len(pkts) > 0 {
		n := 0
		for len(pkts) > 0 && n < tunWriteBatch {
			p := pkts[0]
			pkts = pkts[1:]
			var af byte
			err := error(syscall.EIO)
			if len(p) > 0 {
				af, err = tunAF(p)
			}
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			b.heads[n] = [4]byte{3: af}
			b.iovs[n] = [2]unix.Iovec{
				{Base: &b.heads[n][0], Len: 4},
				{Base: &p[0], Len: uint64(len(p))},
			}
			b.hdrs[n] = msghdrX{Iov: &b.iovs[n][0], Iovlen: 2}
			b.pkts[n] = p
			n++
		}
		if n == 0 {
			continue
		}

		for off := 0; off < n; {
			sent, err := t.sendmsgX(off, n)
			switch {
			case err == nil && sent > 0:
				// The kernel stops early without an error on a packet larger than the socket's send
				// buffer, or when sending a later packet fails with ENOBUFS; resend the remainder.
				off += sent
			case err == nil:
				if werr := t.writeEach(b.pkts[off:n]); werr != nil && firstErr == nil {
					firstErr = werr
				}
				off = n
			case err == unix.EMSGSIZE:
				// Only the first packet being larger than the socket's send buffer fails the whole call,
				// before the kernel takes any; Write reports that one and the rest go out in the next call.
				if werr := t.writeEach(b.pkts[off : off+1]); werr != nil && firstErr == nil {
					firstErr = werr
				}
				off++
			case err == unix.ENOSYS || err == unix.EPERM || err == unix.EOPNOTSUPP:
				// sendmsg_x is private API: fall back to writev if a kernel or sandbox refuses it.
				if t.noSendmsgX.CompareAndSwap(false, true) {
					t.l.Warn("sendmsg_x unavailable on the tun device, writing one packet per syscall", "error", err)
				}
				if werr := t.writeEach(b.pkts[off:n]); werr != nil && firstErr == nil {
					firstErr = werr
				}
				clear(b.iovs[:n])
				clear(b.pkts[:n])
				if werr := t.writeEach(pkts); werr != nil && firstErr == nil {
					firstErr = werr
				}
				return firstErr
			default:
				if firstErr == nil {
					firstErr = err
				}
				off = n
			}
		}
		clear(b.iovs[:n])
		clear(b.pkts[:n])
	}
	return firstErr
}

// sendmsgX hands entries off through n-1 of t.batch to sendmsg_x and returns how many the kernel took.
func (t *tun) sendmsgX(off, n int) (int, error) {
	rc, err := t.f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var sent uintptr
	var errno syscall.Errno
	err = rc.Write(func(fd uintptr) bool {
		sent, _, errno = unix.Syscall6(unix.SYS_SENDMSG_X, fd, uintptr(unsafe.Pointer(&t.batch.hdrs[off])), uintptr(n-off), 0, 0, 0)
		// sendmsg_x reports EAGAIN only when it took nothing; a partial batch returns its count.
		return !errno.Temporary()
	})
	if err != nil {
		return 0, err
	}
	if errno != 0 {
		return 0, errno
	}
	return int(sent), nil
}

// writeEach writes pkts one at a time with Write.
func (t *tun) writeEach(pkts [][]byte) error {
	var firstErr error
	for _, p := range pkts {
		if _, err := t.Write(p); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (t *tun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

func (t *tun) Name() string {
	return t.Device
}

func (t *tun) Queues(int) ([]tio.Queue, error) {
	return []tio.Queue{&tunQueue{t: t, buf: make([]byte, tunReadArena)}}, nil
}
