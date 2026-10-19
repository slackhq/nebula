//go:build !ios && !e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Darwin has no route metrics, the routing table holds one unscoped route per prefix. When another interface already
// routes an unsafe_route's prefix, like the lan we started on, theirs stays and ours is added once theirs is removed.
// Our own route removed by someone else, with nothing in its place, was removed on purpose and stays gone until a reload
// or until another interface takes the prefix, after which ours follows theirs like any other.

const (
	// routeRetryDelay is how long the system routing table must be quiet before we judge who holds a prefix. configd
	// replaces a route by deleting and adding, looking in between would find the prefix free
	routeRetryDelay = time.Second

	// routeSweepInterval bounds how long a freed unsafe_route can go unnoticed. The routing socket drops messages that
	// don't fit its receive buffer without telling the reader, and detaching an interface deletes its routes without
	// a message for each
	routeSweepInterval = time.Minute

	// routeSocketRcvBuf is well past the 8KiB default, which a burst of neighbor routes expiring can fill
	routeSocketRcvBuf = 1 << 20
)

type routeStateKind int

const (
	routeUnknown routeStateKind = iota
	// routeInstalled is our route holding the prefix
	routeInstalled
	// routeYielded is another interface holding the prefix, ours is added once it lets go
	routeYielded
	// routeRemoved is our route deleted by someone else with nothing in its place, it is left alone until a reload or
	// another interface takes the prefix
	routeRemoved
	// routeFailed is adding our route failing for some other reason, it is retried
	routeFailed
)

type routeState struct {
	kind routeStateKind
	// holder is the index of the interface holding the prefix when kind is routeYielded
	holder int
}

// installRoutes returns the routes we put in the system routing table, one per prefix
func installRoutes(routes []Route) []Route {
	seen := make(map[netip.Prefix]struct{}, len(routes))
	var out []Route
	for _, r := range routes {
		if len(r.Via) == 0 || !r.Install {
			// We don't allow route MTUs so only install routes with a via
			continue
		}
		p := r.Cidr.Masked()
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, r)
	}
	return out
}

// addRoutes puts every unsafe_route in the system routing table, including ones someone deleted, unless another
// interface holds its prefix. It runs on start and on every reload.
func (t *tun) addRoutes(logErrors bool, rl *config.Reload) error {
	// The route tree is still ours, the system routing table is not
	if t.hostOwned {
		return nil
	}

	t.routesMu.Lock()
	defer t.routesMu.Unlock()

	// Activate hasn't run yet, it will install the routes
	linkAddr := t.linkAddr.Load()
	if linkAddr == nil || t.closed {
		return nil
	}

	var msgs []netroute.Message
	var msgsErr error
	fetched := false
	states := make(map[netip.Prefix]routeState)
	for _, r := range installRoutes(*t.Routes.Load()) {
		p := r.Cidr.Masked()
		prev := t.routeStates[p]

		err := addRoute(p, linkAddr)
		if err == nil {
			t.l.Info("Added route", "route", r)
			states[p] = routeState{kind: routeInstalled}
			continue
		}

		if !errors.Is(err, unix.EEXIST) {
			retErr := util.NewContextualError("Failed to add route", map[string]any{"route": r}, err)
			if !logErrors {
				return retErr
			}
			retErr.Log(t.l)
			rl.Failed()
			states[p] = routeState{kind: routeFailed}
			continue
		}

		// Every route we added already exists on a reload, only warn about someone else's
		if !fetched {
			msgs, msgsErr = fetchRoutes()
			fetched = true
		}
		if msgsErr != nil {
			t.l.Warn("unable to add unsafe_route, a route already exists but its interface could not be determined", "route", r.Cidr, "error", msgsErr)
			states[p] = prev
			continue
		}

		switch holder := routeInterfaceIn(msgs, p); holder {
		case linkAddr.Index:
			states[p] = routeState{kind: routeInstalled}
		case 0:
			// Removed since the add, the watcher will see to it
			states[p] = prev
		default:
			if prev.kind != routeYielded || prev.holder != holder {
				t.l.Warn("unable to add unsafe_route, the destination is already routed through another interface, it will be added once that route is removed", "route", r.Cidr, "interface", interfaceName(holder))
			}
			states[p] = routeState{kind: routeYielded, holder: holder}
		}
	}

	t.routeStates = states
	return nil
}

func (t *tun) removeRoutes(routes []Route, rl *config.Reload) error {
	if t.hostOwned {
		return nil
	}

	t.routesMu.Lock()
	defer t.routesMu.Unlock()

	linkAddr := t.linkAddr.Load()
	if linkAddr == nil || t.closed {
		return nil
	}

	// The kernel deletes a route by its prefix alone, whichever interface holds it. Only delete the ones that are ours
	msgs, err := fetchRoutes()
	if err != nil {
		var left []netip.Prefix
		for _, r := range installRoutes(routes) {
			left = append(left, r.Cidr)
		}
		return fmt.Errorf("failed to read the system routing table, leaving routes %v installed: %w", left, err)
	}

	for _, r := range installRoutes(routes) {
		p := r.Cidr.Masked()
		// Whatever happens next, the prefix is no longer one we know about
		delete(t.routeStates, p)
		if routeInterfaceIn(msgs, p) != linkAddr.Index {
			continue
		}

		err = delRoute(p, linkAddr)
		if errors.Is(err, unix.ESRCH) {
			// Already gone, which is what we wanted
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

// reconcileRoutes brings the unsafe_routes in line with who holds their prefix now. It is quiet unless something
// changed since it last looked, it runs every routeSweepEvery.
func (t *tun) reconcileRoutes() {
	t.routesMu.Lock()
	defer t.routesMu.Unlock()

	linkAddr := t.linkAddr.Load()
	if linkAddr == nil || t.closed {
		return
	}

	msgs, err := fetchRoutes()
	if err != nil {
		t.l.Error("Failed to read the system routing table", "error", err)
		return
	}

	states := make(map[netip.Prefix]routeState)
	for _, r := range installRoutes(*t.Routes.Load()) {
		p := r.Cidr.Masked()
		prev := t.routeStates[p]

		holder := routeInterfaceIn(msgs, p)
		switch {
		case holder == linkAddr.Index:
			states[p] = routeState{kind: routeInstalled}

		case holder != 0:
			// Another interface taking a prefix we left alone puts ours back in line behind theirs
			if prev.kind != routeYielded || prev.holder != holder {
				t.l.Info("unsafe_route is routed through another interface, it will be added back when that route is removed", "route", r.Cidr, "interface", interfaceName(holder))
			}
			states[p] = routeState{kind: routeYielded, holder: holder}

		case prev.kind == routeInstalled:
			t.l.Warn("unsafe_route was removed outside nebula, leaving it until a reload or another interface takes its destination", "route", r.Cidr)
			states[p] = routeState{kind: routeRemoved}

		case prev.kind == routeRemoved:
			states[p] = prev

		default:
			err := addRoute(p, linkAddr)
			switch {
			case err == nil:
				if prev.kind == routeYielded {
					t.l.Info("unsafe_route's destination is free again, added it", "route", r)
				} else {
					t.l.Info("Added route", "route", r)
				}
				states[p] = routeState{kind: routeInstalled}
			case errors.Is(err, unix.EEXIST):
				// Taken since the fetch, the next look will see by whom
				states[p] = prev
			default:
				if prev.kind != routeFailed {
					util.NewContextualError("Failed to add route", map[string]any{"route": r}, err).Log(t.l)
				}
				states[p] = routeState{kind: routeFailed}
			}
		}
	}
	t.routeStates = states
}

// startRouteWatch starts reconciling the unsafe_routes, every routeSweepEvery and, when watch isn't nil, once the
// routing table settles after anything that may have freed a prefix
func (t *tun) startRouteWatch(watch *os.File) {
	t.routesMu.Lock()
	defer t.routesMu.Unlock()
	if t.closed {
		if watch != nil {
			_ = watch.Close()
		}
		return
	}

	t.routeSweep = time.AfterFunc(t.routeSweepEvery, t.sweepRoutes)
	if watch != nil {
		t.routeWatch = watch
		go t.watchRoutes(watch)
	}
}

func (t *tun) sweepRoutes() {
	// A table still changing gets reconciled once it settles
	if time.Since(time.Unix(0, t.lastRouteEvent.Load())) >= routeRetryDelay {
		t.reconcileRoutes()
	}

	t.routesMu.Lock()
	defer t.routesMu.Unlock()
	if !t.closed {
		t.routeSweep.Reset(t.routeSweepEvery)
	}
}

func openRouteSocket() (*os.File, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("unable to create AF_ROUTE socket: %w", err)
	}
	// Fewer drops, the sweep catches the rest
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, routeSocketRcvBuf)
	// Non-blocking puts it on the poller, so Close interrupts a Read
	if err = unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to set the AF_ROUTE socket to non-blocking mode: %w", err)
	}
	return os.NewFile(uintptr(fd), "route"), nil
}

// watchRoutes reconciles the unsafe_routes once the routing table has been quiet for routeRetryDelay after a message
// that may have freed a prefix. A table that keeps changing is reconciled every routeSweepEvery regardless.
func (t *tun) watchRoutes(f *os.File) {
	var reconciled atomic.Int64
	settle := time.AfterFunc(time.Hour, func() {
		reconciled.Store(time.Now().UnixNano())
		t.reconcileRoutes()
	})
	settle.Stop()
	defer settle.Stop()

	var burst time.Time
	b := make([]byte, os.Getpagesize())
	for {
		n, err := f.Read(b)
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				t.l.Error("Stopped watching the system routing table, unsafe_routes held by another interface are only retried every minute", "error", err)
			}
			return
		}

		if !routesMayBeFreed(b[:n], *t.Routes.Load()) {
			continue
		}

		now := time.Now()
		t.lastRouteEvent.Store(now.UnixNano())
		if burst.IsZero() || reconciled.Load() >= burst.UnixNano() {
			burst = now
		}
		settle.Reset(max(0, min(routeRetryDelay, time.Until(burst.Add(t.routeSweepEvery)))))
	}
}

// routesMayBeFreed reports whether b, one routing socket message, may have freed a prefix one of routes installs. That's
// a route for it removed, or an interface that lost an address or changed state, since detaching an interface deletes
// its routes without a message of their own. The header is read directly, x/net/route skips the RTM_IFINFO the socket
// sends, which has no interface address, and misreads the unpadded sockaddrs in messages the kernel makes itself.
func routesMayBeFreed(b []byte, routes []Route) bool {
	if len(b) < 4 {
		return false
	}
	switch int(b[3]) {
	case unix.RTM_IFINFO, unix.RTM_DELADDR:
		return true
	case unix.RTM_DELETE:
	default:
		return false
	}

	if len(b) < unix.SizeofRtMsghdr {
		return false
	}
	hdr := (*unix.RtMsghdr)(unsafe.Pointer(&b[0]))
	// A failed request is reported too, and a scoped route never held the prefix
	if hdr.Errno != 0 || hdr.Flags&unix.RTF_IFSCOPE != 0 {
		return false
	}

	if hdr.Pid == 0 {
		// The kernel's own, which x/net/route can't parse. Neighbors coming and going are host routes, anything else
		// could be holding a prefix
		return hdr.Flags&(unix.RTF_HOST|unix.RTF_LLINFO) == 0
	}

	// Replies to a request carry the requester's padded sockaddrs
	msgs, err := netroute.ParseRIB(unix.NET_RT_DUMP, b)
	if err != nil || len(msgs) != 1 {
		return false
	}
	m, ok := msgs[0].(*netroute.RouteMessage)
	if !ok || len(m.Addrs) <= unix.RTAX_NETMASK {
		return false
	}
	p, ok := routePrefix(m.Addrs[unix.RTAX_DST], m.Addrs[unix.RTAX_NETMASK])
	if !ok {
		return false
	}
	for _, r := range installRoutes(routes) {
		if r.Cidr.Masked() == p {
			return true
		}
	}
	return false
}

// interfaceName is the name of the interface with index i, for logs
func interfaceName(i int) string {
	if ifc, err := net.InterfaceByIndex(i); err == nil {
		return ifc.Name
	}
	return strconv.Itoa(i)
}
