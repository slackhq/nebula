//go:build e2e_testing

package e2e

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/udp"
)

// TestDualStackRoamToV4Only measures how long a laptop's tunnels take to come back after it moves from a dual stack
// network, where its tunnels formed over IPv6, to one with no IPv6 service at all: the office to hotel wifi. Every
// peer still has an IPv4 address the laptop can reach, so nothing about the move should strand a tunnel.
//
// It is a measurement, not a pass/fail assertion, and it runs on the production connection manager timers.
//
//	go test -tags e2e_testing -v -run TestDualStackRoamToV4Only ./e2e/
func TestDualStackRoamToV4Only(t *testing.T) {
	for _, tc := range []dualStackRoamCase{
		{name: "both send", meSends: true, themSends: true},
		{name: "both send, rebind", meSends: true, themSends: true, rebind: true},
		{name: "both send, two tunnels", meSends: true, themSends: true, simultaneous: true},
		{name: "laptop sends", meSends: true},
		{name: "peer sends", themSends: true},
		{name: "peer sends, rebind", themSends: true, rebind: true},
		{name: "peer sends, lh over v4", themSends: true, lhOverV4: true},
		{name: "peer sends, punchy", themSends: true, punchy: true},
		{name: "peer sends, punchy all", themSends: true, punchy: true, punchAll: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fwd, rev := measureDualStackRoam(t, tc)
			t.Logf("RESULT %-24s laptop->peer %-9v peer->laptop %-9v", tc.name, fmtRecovery(fwd), fmtRecovery(rev))
		})
	}
}

type dualStackRoamCase struct {
	name string
	// meSends and themSends say who keeps traffic flowing after the move
	meSends, themSends bool
	// rebind fires RebindUDPServer on the move, as the darwin network change monitor would
	rebind bool
	// lhOverV4 forms the lighthouse tunnel over IPv4 at the office, so the move does not break it
	lhOverV4 bool
	// simultaneous has both sides initiate at once at the office, which can leave each side a different primary
	// tunnel for the other
	simultaneous bool
	// punchy turns on punchy.punch everywhere, punchAll adds punchy.target_all_remotes
	punchy, punchAll bool
}

func fmtRecovery(d time.Duration) string {
	if d == 0 {
		return "never"
	}
	return d.Round(time.Millisecond).String()
}

type dualStackNode struct {
	c       *nebula.Control
	vpnAddr netip.Addr
	v4, v6  netip.AddrPort
	adv     atomic.Pointer[[]netip.Addr]
}

// move puts the node on a new network, advertising only what it can be reached on there
func (n *dualStackNode) move(v4, v6 netip.AddrPort) {
	n.v4, n.v6 = v4, v6
	n.c.SetDualStackUDPAddrs(v4, v6)
	var adv []netip.Addr
	for _, a := range []netip.AddrPort{v4, v6} {
		if a.IsValid() {
			adv = append(adv, a.Addr())
		}
	}
	n.adv.Store(&adv)
}

func newDualStackNode(ca cert.Certificate, caKey []byte, name, vpnNet string, v4, v6 netip.AddrPort, overrides m) *dualStackNode {
	c, vpnNets, _, _ := newSimpleServerWithUdp(cert.Version2, ca, caKey, name, vpnNet, v4, overrides)
	n := &dualStackNode{c: c, vpnAddr: vpnNets[0].Addr()}
	n.move(v4, v6)
	c.SetLocalAddrsFn(func(*nebula.LocalAllowList) []netip.Addr {
		return *n.adv.Load()
	})
	return n
}

// measureDualStackRoam returns how long after the move the first packet made it laptop->peer and peer->laptop, zero
// for a direction that never recovered.
func measureDualStackRoam(t *testing.T, tc dualStackRoamCase) (time.Duration, time.Duration) {
	t.Helper()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	ap := netip.MustParseAddrPort
	lhV4, lhV6 := ap("10.0.0.1:4242"), ap("[fd00::1]:4242")
	lh := newDualStackNode(ca, caKey, "lh", "10.128.0.1/24", lhV4, lhV6, m{
		"lighthouse": m{"am_lighthouse": true},
	})

	// Production timers rather than the 2s the harness defaults to, this is about how long a real laptop waits
	peerCfg := m{
		"lighthouse": m{
			"hosts":    []any{lh.vpnAddr.String()},
			"interval": 10,
		},
		"static_host_map": m{
			lh.vpnAddr.String(): []any{lhV4.String(), lhV6.String()},
		},
		"timers": m{
			"connection_alive_interval": 5,
			"pending_deletion_interval": 10,
		},
		"punchy": m{
			"punch":              tc.punchy,
			"target_all_remotes": tc.punchAll,
		},
	}

	me := newDualStackNode(ca, caKey, "me", "10.128.0.2/24", ap("10.0.0.2:4242"), ap("[fd00::2]:4242"), peerCfg)
	them := newDualStackNode(ca, caKey, "them", "10.128.0.3/24", ap("10.0.0.3:4242"), ap("[fd00::3]:4242"), peerCfg)

	r := router.NewR(t, lh.c, me.c, them.c)
	r.CancelFlowLogs()
	for _, n := range []*dualStackNode{lh, me, them} {
		r.AddRoute(n.v6.Addr(), n.v6.Port(), n.c)
	}
	defer func() {
		lh.c.Stop()
		me.c.Stop()
		them.c.Stop()
	}()

	lh.c.Start()
	me.c.Start()
	them.c.Start()

	// At the office IPv6 wins every race, so everything forms over it. The lighthouse tunnel optionally does not,
	// for a static_host_map that only lists the lighthouse's IPv4 address.
	officeV6 := func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		lhTraffic := p.To == lhV4 || p.To == lhV6 || p.From == lhV4 || p.From == lhV6
		if p.To.Addr().Is4() == (tc.lhOverV4 && lhTraffic) {
			return router.KeepRouting
		}
		return router.Drop
	}
	r.RouteForAllExitFuncOrTimeout(time.Second, officeV6)

	// One side at a time, so both sides hold the same single tunnel, unless the case wants them racing
	me.c.InjectTunPacket(BuildTunUDPPacket(them.vpnAddr, 80, me.vpnAddr, 80, []byte("establish")))
	if !tc.simultaneous {
		r.RouteForAllExitFuncOrTimeout(time.Second, officeV6)
	}
	them.c.InjectTunPacket(BuildTunUDPPacket(me.vpnAddr, 80, them.vpnAddr, 80, []byte("establish")))
	r.RouteForAllExitFuncOrTimeout(time.Second, officeV6)
	if tc.simultaneous && me.c.GetHostmapIndexCount() < 3 {
		// A tunnel to the lighthouse and two to the peer, or the race did not happen
		t.Logf("simultaneous handshakes settled on a single tunnel this run")
	}
	drainTun(me.c)
	drainTun(them.c)

	for _, want := range []struct {
		name    string
		c       *nebula.Control
		vpnAddr netip.Addr
		v6      bool
	}{
		{"laptop->peer", me.c, them.vpnAddr, true},
		{"peer->laptop", them.c, me.vpnAddr, true},
		{"laptop->lh", me.c, lh.vpnAddr, !tc.lhOverV4},
	} {
		hi := want.c.GetHostInfoByVpnAddr(want.vpnAddr, false)
		if hi == nil {
			t.Fatalf("%s: no tunnel at the office", want.name)
		}
		if hi.CurrentRemote.Addr().Is6() != want.v6 {
			t.Fatalf("%s: tunnel formed over %v, the scenario wants v6=%v", want.name, hi.CurrentRemote, want.v6)
		}
	}

	// Hotel wifi: a new NAT'd IPv4 address and no IPv6 at all. The office addresses are gone, nothing reaches them.
	officeV4, officeV6Addr := me.v4, me.v6
	hotel := ap("10.0.0.99:4242")
	me.move(hotel, netip.AddrPort{})
	r.AddRoute(hotel.Addr(), hotel.Port(), me.c)

	start := time.Now()
	if tc.rebind {
		me.c.RebindUDPServer()
	}

	var fwd, rev atomic.Int64
	stop := make(chan struct{})
	defer close(stop)
	watchTun(them.c, stop, start, &fwd)
	watchTun(me.c, stop, start, &rev)

	go func() {
		tick := time.NewTicker(time.Millisecond * 200)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if tc.meSends {
					me.c.InjectTunPacket(BuildTunUDPPacket(them.vpnAddr, 80, me.vpnAddr, 80, []byte("retry")))
				}
				if tc.themSends {
					them.c.InjectTunPacket(BuildTunUDPPacket(me.vpnAddr, 80, them.vpnAddr, 80, []byte("retry")))
				}
			}
		}
	}()

	// When only one side has traffic, the other direction recovering is a bonus we still report but do not wait for
	done := func() bool {
		return (!tc.meSends || fwd.Load() != 0) && (!tc.themSends || rev.Load() != 0)
	}
	r.RouteForAllExitFuncOrTimeout(time.Second*90, func(p *udp.Packet, _ *nebula.Control) router.ExitType {
		if p.To == officeV4 || p.To == officeV6Addr {
			return router.Drop
		}
		if done() {
			return router.ExitNow
		}
		return router.KeepRouting
	})

	return time.Duration(fwd.Load()), time.Duration(rev.Load())
}

func drainTun(c *nebula.Control) {
	for {
		select {
		case <-c.GetTunTxChan():
		default:
			return
		}
	}
}

// watchTun records how long after start the first packet came out of c's tun, and keeps the tun drained after
func watchTun(c *nebula.Control, stop chan struct{}, start time.Time, first *atomic.Int64) {
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-c.GetTunTxChan():
				first.CompareAndSwap(0, int64(time.Since(start)))
			}
		}
	}()
}
