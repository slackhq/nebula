package nebula

import (
	"context"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
)

const (
	holepunchTickDuration  = 250 * time.Millisecond
	holepunchWheelDuration = 60 * time.Second
)

// holepunchJob is one scheduled item on the holepunch timer wheel.
//   - target valid -> send a UDP punch to target. vpnAddr, if set, is the peer's vpn addr carried for log context.
//   - target invalid, vpnAddr valid -> send an encrypted test packet to vpnAddr (a "punchback").
type holepunchJob struct {
	target  netip.AddrPort
	vpnAddr netip.Addr
}

// lighthouseChecker is the slice of LightHouse that Punchy actually needs.
// Defined here so Punchy doesn't take a *LightHouse dependency (LightHouse
// already holds a *Punchy, and the bidirectional pointer reference is awkward
// even within the same package). Tests can also substitute a fake.
type lighthouseChecker interface {
	IsAnyLighthouseAddr(vpnAddrs []netip.Addr) bool
}

type Punchy struct {
	punch           atomic.Bool
	respond         atomic.Bool
	delay           atomic.Int64
	respondDelay    atomic.Int64
	punchEverything atomic.Bool

	holepunchTimer    *LockingTimerWheel[holepunchJob]
	punchConn         udp.Conn
	metricHolepunchTx metrics.Counter
	metricPunchyTx    metrics.Counter

	// Wired by Start, before any SendPunch* path can run.
	ifce EncWriter
	hm   *HostMap
	lh   lighthouseChecker

	l *slog.Logger
}

func NewPunchyFromConfig(l *slog.Logger, c *config.C, punchConn udp.Conn) *Punchy {
	p := &Punchy{
		l:              l,
		punchConn:      punchConn,
		holepunchTimer: NewLockingTimerWheel[holepunchJob](holepunchTickDuration, holepunchWheelDuration),
		metricPunchyTx: metrics.GetOrRegisterCounter("messages.tx.punchy", nil),
	}

	if c.GetBool("stats.lighthouse_metrics", false) {
		p.metricHolepunchTx = metrics.GetOrRegisterCounter("messages.tx.holepunch", nil)
	} else {
		p.metricHolepunchTx = metrics.NilCounter{}
	}

	p.reload(c, true)
	c.RegisterReloadCallback(func(c *config.C) {
		p.reload(c, false)
	})

	return p
}

func (p *Punchy) reload(c *config.C, initial bool) {
	if initial || c.HasChanged("punchy.punch") || c.HasChanged("punchy") {
		var yes bool
		if c.IsSet("punchy.punch") {
			yes = c.GetBool("punchy.punch", false)
		} else {
			// Deprecated fallback
			yes = c.GetBool("punchy", false)
		}

		old := p.punch.Swap(yes)
		switch {
		case initial && yes:
			p.l.Info("punchy enabled")
		case initial:
			p.l.Info("punchy disabled")
		case old != yes:
			p.l.Info("punchy.punch changed", "punch", yes)
		}
	}

	if initial || c.HasChanged("punchy.respond") || c.HasChanged("punch_back") {
		var yes bool
		if c.IsSet("punchy.respond") {
			yes = c.GetBool("punchy.respond", false)
		} else {
			// Deprecated fallback
			yes = c.GetBool("punch_back", false)
		}

		old := p.respond.Swap(yes)
		if !initial && old != yes {
			p.l.Info("punchy.respond changed", "respond", yes)
		}
	}

	//NOTE: this will not apply to any in progress operations, only the next one
	if initial || c.HasChanged("punchy.delay") {
		newDelay := int64(c.GetDuration("punchy.delay", time.Second))
		old := p.delay.Swap(newDelay)
		if !initial && old != newDelay {
			p.l.Info("punchy.delay changed", "delay", time.Duration(newDelay))
		}
	}

	if initial || c.HasChanged("punchy.target_all_remotes") {
		yes := c.GetBool("punchy.target_all_remotes", false)
		old := p.punchEverything.Swap(yes)
		if !initial && old != yes {
			p.l.Info("punchy.target_all_remotes changed", "target_all_remotes", yes)
		}
	}

	if initial || c.HasChanged("punchy.respond_delay") {
		newDelay := int64(c.GetDuration("punchy.respond_delay", 5*time.Second))
		old := p.respondDelay.Swap(newDelay)
		if !initial && old != newDelay {
			p.l.Info("punchy.respond_delay changed", "respond_delay", time.Duration(newDelay))
		}
	}
}

// Schedule queues a punch packet to target, to be sent after the configured delay.
// vpnAddr is the peer's vpn addr, carried through for log context when the packet actually fires.
// No-op if target is not a valid AddrPort. Safe to call from any goroutine.
func (p *Punchy) Schedule(target netip.AddrPort, vpnAddr netip.Addr) {
	if !target.IsValid() {
		return
	}
	p.holepunchTimer.Add(holepunchJob{target: target, vpnAddr: vpnAddr}, time.Duration(p.delay.Load()))
}

// ScheduleRespond queues a punchback test packet to vpnAddr after the configured respond delay,
// gated on punchy.respond. No-op when respond is disabled.
func (p *Punchy) ScheduleRespond(vpnAddr netip.Addr) {
	if !p.respond.Load() {
		return
	}
	p.holepunchTimer.Add(holepunchJob{vpnAddr: vpnAddr}, time.Duration(p.respondDelay.Load()))
}

// SendPunch sends an immediate keepalive punch for an idle hostinfo.
// The configured punchy.target_all_remotes mode picks the targets. Gated on punchy.punch and the lighthouse-skip rule
// (lighthouses don't get keepalive punches because the regular update interval keeps their NAT state warm).
func (p *Punchy) SendPunch(hostinfo *HostInfo) {
	if !p.punch.Load() {
		return
	}
	if p.lh.IsAnyLighthouseAddr(hostinfo.vpnAddrs) {
		return
	}

	if p.punchEverything.Load() {
		p.sendPunchToAllRemotes(hostinfo)
	} else if hostinfo.remote.IsValid() {
		p.metricPunchyTx.Inc(1)
		p.punchConn.WriteTo([]byte{1}, hostinfo.remote)
	}
}

// SendPunchToAll punches every known remote for hostinfo, but only when punchy.target_all_remotes is enabled.
// The connection manager calls this during outbound-only traffic: the outbound traffic itself keeps the primary's
// NAT state warm, but non-primary remotes need separate refresh, so we fan out to all of them (the redundant
// primary punch is harmless). Gated on punchy.punch and the lighthouse-skip rule.
func (p *Punchy) SendPunchToAll(hostinfo *HostInfo) {
	if !p.punchEverything.Load() {
		return
	}
	if !p.punch.Load() {
		return
	}
	if p.lh.IsAnyLighthouseAddr(hostinfo.vpnAddrs) {
		return
	}
	p.sendPunchToAllRemotes(hostinfo)
}

func (p *Punchy) sendPunchToAllRemotes(hostinfo *HostInfo) {
	hostinfo.remotes.ForEach(p.hm.GetPreferredRanges(), func(addr netip.AddrPort, preferred bool) {
		p.metricPunchyTx.Inc(1)
		p.punchConn.WriteTo([]byte{1}, addr)
	})
}

// Start wires the runtime dependencies and runs a single goroutine that drains the holepunch timer wheel.
// Must be called after the interface is up. Exits when ctx is cancelled.
func (p *Punchy) Start(ctx context.Context, ifce EncWriter, hm *HostMap, lh lighthouseChecker) {
	p.ifce = ifce
	p.hm = hm
	p.lh = lh

	go func() {
		clockSource := time.NewTicker(holepunchTickDuration)
		defer clockSource.Stop()

		nb := make([]byte, 12, 12)
		out := make([]byte, mtu)
		empty := []byte{0}

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-clockSource.C:
				p.holepunchTimer.Advance(now)
				for {
					job, has := p.holepunchTimer.Purge()
					if !has {
						break
					}
					switch {
					case job.target.IsValid():
						if p.l.Enabled(context.Background(), slog.LevelDebug) {
							p.l.Debug("Punching", "target", job.target, "vpnAddr", job.vpnAddr)
						}
						p.metricHolepunchTx.Inc(1)
						p.punchConn.WriteTo(empty, job.target)
					case job.vpnAddr.IsValid():
						// A nebula test packet to the host trying to contact us. In the case of a double nat or other
						// difficult scenario, this may help establish a tunnel.
						if p.l.Enabled(context.Background(), slog.LevelDebug) {
							p.l.Debug("Sending a nebula test packet", "vpnAddr", job.vpnAddr)
						}
						p.ifce.SendMessageToVpnAddr(header.Test, header.TestRequest, job.vpnAddr, []byte(""), nb, out)
					}
				}
			}
		}
	}()
}
