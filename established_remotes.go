package nebula

import (
	"net/netip"
	"sync"

	"github.com/slackhq/nebula/udp"
)

// establishedRemotes tells the udp conns that implement udp.EstablishedPeerConn which addresses are the current
// direct remote of at least one established tunnel. A hostinfo holds a reference on its remote while it is in the
// main hostmap, and SetRemote moves the reference; a relayed tunnel has no direct remote and holds none.
type establishedRemotes struct {
	mu    sync.Mutex
	conns []udp.EstablishedPeerConn
	refs  map[netip.AddrPort]int
}

// newEstablishedRemotes returns nil when no conn wants to know, which every method accepts.
func newEstablishedRemotes(conns []udp.Conn) *establishedRemotes {
	var pc []udp.EstablishedPeerConn
	for _, c := range conns {
		if p, ok := c.(udp.EstablishedPeerConn); ok {
			pc = append(pc, p)
		}
	}
	if len(pc) == 0 {
		return nil
	}
	return &establishedRemotes{conns: pc, refs: map[netip.AddrPort]int{}}
}

// add makes hostinfo hold a reference on its remote, as it joins the main hostmap. A hostinfo holds references in
// one establishedRemotes at a time, so an add while it is in another is ignored.
func (e *establishedRemotes) add(hostinfo *HostInfo) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !hostinfo.establishedIn.CompareAndSwap(nil, e) && hostinfo.establishedIn.Load() != e {
		return
	}
	e.syncLocked(hostinfo)
}

// remove drops hostinfo's reference, as it leaves the main hostmap.
func (e *establishedRemotes) remove(hostinfo *HostInfo) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if hostinfo.establishedIn.CompareAndSwap(e, nil) {
		e.syncLocked(hostinfo)
	}
}

// syncLocked moves hostinfo's reference to the remote it should hold now: its current remote while it is
// established, none otherwise. Reading both under mu makes the last call win however add, remove and SetRemote
// interleave. Only the establishedRemotes that hostinfo is in, or has just left, may call it, since
// hostinfo.establishedRemote is a reference in that one's refs.
func (e *establishedRemotes) syncLocked(hostinfo *HostInfo) {
	var want netip.AddrPort
	if hostinfo.establishedIn.Load() == e {
		want = hostinfo.GetRemote()
	}
	held := hostinfo.establishedRemote
	if want == held {
		return
	}
	if held.IsValid() {
		e.refs[held]--
		if e.refs[held] == 0 {
			delete(e.refs, held)
			for _, c := range e.conns {
				c.SetEstablishedPeer(held, false)
			}
		}
	}
	if want.IsValid() {
		e.refs[want]++
		if e.refs[want] == 1 {
			for _, c := range e.conns {
				c.SetEstablishedPeer(want, true)
			}
		}
	}
	hostinfo.establishedRemote = want
}
