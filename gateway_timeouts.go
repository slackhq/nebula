package nebula

import (
	"net/netip"
	"sync"
	"time"
)

// gatewayTimeouts remembers when a handshake with each gateway of a multi-gateway route last timed out.
//
// A packet whose flow hashes to a gateway without a tunnel waits for that gateway's handshake instead of going to
// another gateway. Sending it elsewhere would split the flow: once the handshake completes, the rest of the flow goes
// to the gateway it hashes to, which has never seen it and, for TCP to a backend, resets it. Only a gateway whose
// handshake timed out recently is passed over, and while it is, a flow that hashes to it goes to another gateway.
//
// That leaves two cases where a flow is still split, because the hash alone decides where a flow goes:
//   - A flow that started on another gateway while its own was passed over goes back to its own once a handshake with
//     it completes, and is reset there.
//   - That includes a flow started after a passed over gateway has recovered but before we know: its first packet
//     goes to another gateway and starts the handshake that tells us, so the window is one handshake.
//
// Only the routing path adds entries, for gateways of multi-gateway routes, so this holds one entry per such gateway
// however many other hosts we handshake with.
type gatewayTimeouts struct {
	sync.RWMutex
	m map[netip.Addr]time.Time
}

func newGatewayTimeouts() *gatewayTimeouts {
	return &gatewayTimeouts{m: map[netip.Addr]time.Time{}}
}

// recentlyTimedOut reports whether a handshake with gateway timed out within window, and starts tracking gateway if
// it was not already.
func (g *gatewayTimeouts) recentlyTimedOut(gateway netip.Addr, window time.Duration) bool {
	g.RLock()
	t, ok := g.m[gateway]
	g.RUnlock()

	if !ok {
		g.Lock()
		if _, ok := g.m[gateway]; !ok {
			g.m[gateway] = time.Time{}
		}
		g.Unlock()
		return false
	}

	return !t.IsZero() && time.Since(t) < window
}

// timedOut records a handshake timeout for addr if it is a tracked gateway.
func (g *gatewayTimeouts) timedOut(addr netip.Addr) {
	g.Lock()
	if _, ok := g.m[addr]; ok {
		g.m[addr] = time.Now()
	}
	g.Unlock()
}

// completed forgets the last timeout of any tracked gateway in addrs, which now have a tunnel.
func (g *gatewayTimeouts) completed(addrs []netip.Addr) {
	g.RLock()
	found := false
	for _, addr := range addrs {
		if t, ok := g.m[addr]; ok && !t.IsZero() {
			found = true
			break
		}
	}
	g.RUnlock()

	if !found {
		return
	}

	g.Lock()
	for _, addr := range addrs {
		if _, ok := g.m[addr]; ok {
			g.m[addr] = time.Time{}
		}
	}
	g.Unlock()
}
