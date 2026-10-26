package nebula

import (
	"net/netip"
	"sync"
)

// downGateways remembers which gateways of multi-gateway routes are down: a handshake with them timed out and none
// has completed since.
//
// A packet whose flow hashes to a gateway without a tunnel waits for that gateway's handshake instead of going to
// another gateway. Sending it elsewhere would split the flow: once the handshake completes, the rest of the flow goes
// to the gateway it hashes to, which has never seen it and, for TCP to a backend, resets it. Only a down gateway is
// passed over, and while it is, a flow that hashes to it goes to another gateway. Handshakes with it are retried as
// those packets arrive, and the first one to complete marks it up.
//
// That leaves two cases where a flow is still split, because the hash alone decides where a flow goes:
//   - A flow that started on another gateway while its own was down goes back to its own once a handshake with it
//     completes, and is reset there.
//   - That includes a flow started after a down gateway has recovered but before we know: its first packet goes to
//     another gateway and starts the handshake that tells us, so the window is one handshake.
//
// Only the routing path adds entries, for gateways of multi-gateway routes, so this holds one entry per such gateway
// however many other hosts we handshake with.
type downGateways struct {
	sync.RWMutex
	m map[netip.Addr]bool
}

func newDownGateways() *downGateways {
	return &downGateways{m: map[netip.Addr]bool{}}
}

// isDown reports whether gateway is down, and starts tracking gateway if it was not already.
func (g *downGateways) isDown(gateway netip.Addr) bool {
	g.RLock()
	down, ok := g.m[gateway]
	g.RUnlock()

	if !ok {
		g.Lock()
		if _, ok := g.m[gateway]; !ok {
			g.m[gateway] = false
		}
		g.Unlock()
	}

	return down
}

// timedOut marks addr down if it is a tracked gateway.
func (g *downGateways) timedOut(addr netip.Addr) {
	g.Lock()
	if _, ok := g.m[addr]; ok {
		g.m[addr] = true
	}
	g.Unlock()
}

// completed marks any tracked gateway in addrs, which now have a tunnel, up.
func (g *downGateways) completed(addrs []netip.Addr) {
	g.RLock()
	found := false
	for _, addr := range addrs {
		if g.m[addr] {
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
			g.m[addr] = false
		}
	}
	g.Unlock()
}
