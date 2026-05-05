package nebula

import (
	"context"
	"encoding/binary"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay"
)

// PMTUD PoC: discover the path MTU per-tunnel via authenticated probes that ride
// the existing crypto session. We follow RFC 8899 PLPMTUD: a binary search
// between a known-good floor and a configured ceiling, with N consecutive probe
// losses at a size treated as "doesn't fit." Confirmed PMTU is pushed to the
// overlay device, which on Linux installs a per-host route with the discovered
// MTU. The kernel then surfaces EMSGSIZE / PTB to apps writing to the tun.
//
// Probe payload format (request):
//
//	[magic uint32 BE][probeID uint32 BE][padding 0x00...]
//
// Reply is a small ack with the same magic and probeID and no padding. We do not
// verify the reverse-path MTU; only the forward direction matters for the
// receiver's MTU on the inside.

const (
	pmtudMagic uint32 = 0x504D5544 // 'P' 'M' 'U' 'D'
	pmtudFloor        = 1280       // IPv6 minimum payload, also a safe internet MTU floor

	// pmtudConverged is the bytes-tolerance for stopping the search.
	pmtudConverged = 8

	// pmtudMaxLoss matches RFC 8899 MAX_PROBES (default 3).
	pmtudMaxLoss = 3

	// pmtudProbeInterval is the time between probe ticks during the search phase.
	// Once a peer converges the wheel stops ticking it; re-validation is driven
	// by connection_manager via MaybeProbeAsTest at its natural test cadence.
	pmtudProbeInterval = 500 * time.Millisecond

	// pmtudWheelMax is the wheel's maximum supported scheduling duration. We
	// only ever schedule at pmtudProbeInterval today, but the wheel needs a
	// max greater than its tick to allocate its slot ring sensibly.
	pmtudWheelMax = 5 * time.Second

	// pmtudOverheadPessimistic assumes IPv6 underlay + relay framing:
	//   IPv6(40) + UDP(8) + outer nebula(16) + outer AEAD tag(16)
	// + inner nebula(16) + inner AEAD tag(16) = 112 bytes.
	// TODO: track underlay address family and per-peer relay state on the HostInfo
	// so the manager can use the actual overhead for that tunnel and recover the
	// 32 bytes we pessimistically give up on direct IPv6 paths and the 52 bytes on
	// direct IPv4 paths.
	pmtudOverheadPessimistic = 112

	// pmtudUnsupportedAfter is the number of consecutive lost probes (across any
	// sizes) without ever receiving a reply that we treat as evidence the peer
	// does not understand the MTUDProbeRequest subtype (i.e. it's running an
	// older nebula). After this many failures with everReplied=false we mark the
	// peer pmtud-unsupported and stop scheduling probes. K is small enough that
	// it fires before the binary search would naturally converge to floor (which
	// would otherwise be ~30 wasted probes), but large enough to absorb a few
	// transient probe losses on a path that's just starting to settle.
	pmtudUnsupportedAfter = 5
)

// pmtudPeer tracks the binary-search state for one tunnel.
type pmtudPeer struct {
	mu       sync.Mutex
	addr     netip.Addr
	localIdx uint32

	// low is the largest outer IP packet size we have a confirmed ack for.
	// high is the smallest size we believe fails (the search ceiling to start).
	low, high int

	// inFlightSize is the outer IP packet size of the probe currently awaiting
	// an ack. 0 means no probe in flight.
	inFlightSize int
	// inFlightID matches the probeID echoed in the reply.
	inFlightID uint32
	// losses counts consecutive failures at inFlightSize.
	losses int

	// firstProbe is true until we have sent the first probe of a search. The
	// first probe targets the ceiling directly (RFC 8899 permits this Search
	// Algorithm choice); operators who set tun.max_mtu typically have a path
	// that supports it, so we converge in one probe in the common case.
	firstProbe bool
	// everReplied is true once we have ever received any MTUDProbeReply from
	// this peer. Combined with consecutiveFailures, this lets us detect peers
	// that don't understand the new subtype and stop probing them.
	everReplied bool
	// consecutiveFailures counts probes lost without an intervening reply.
	// Resets to 0 on any successful reply.
	consecutiveFailures int
	// unsupported is set true once we conclude the peer doesn't speak PMTUD.
	// The manager skips probes for unsupported peers.
	unsupported bool

	// converged means we have a confirmed PMTU and are in the slow re-validation phase.
	converged bool
	// applied is the inner MTU we last pushed to the overlay device (0 if never).
	applied int
}

func (p *pmtudPeer) overhead() int {
	// TODO: branch on actual underlay family + relay state for this peer.
	return pmtudOverheadPessimistic
}

func (p *pmtudPeer) midpoint() int {
	return (p.low + p.high) / 2
}

type pmtudManager struct {
	intf   *Interface
	device overlay.Device

	// peers is keyed by HostInfo.localIndexId.
	peers sync.Map // map[uint32]*pmtudPeer

	wheel *LockingTimerWheel[uint32]

	// floor is the always-safe inner MTU (= tun.mtu). Per-peer routes start here
	// on tunnel-up so unprobed traffic is always small enough to fit. Stored as
	// atomic int64 so reload can update it without coordinating with the readers
	// in tick/HandleReply/OnTunnelUp.
	floor atomic.Int64
	// ceiling is the search ceiling expressed as an outer IP packet size, derived
	// from tun.max_mtu (which is the kernel's device MTU on the tun) plus our
	// pessimistic overhead. PMTUD will not probe larger than this.
	ceiling atomic.Int64

	enabled atomic.Bool

	l *slog.Logger
}

func newPMTUDManagerFromConfig(l *slog.Logger, c *config.C, device overlay.Device) *pmtudManager {
	m := &pmtudManager{
		device: device,
		wheel:  NewLockingTimerWheel[uint32](pmtudProbeInterval, pmtudWheelMax),
		l:      l,
	}
	c.RegisterReloadCallback(func(c *config.C) { m.reload(c, false) })
	m.reload(c, true)
	return m
}

// reload applies tun.mtu / tun.max_mtu changes to the manager. On the initial
// call (during construction) it just snapshots state; on a live reload it also
// transitions in-flight peers to match the new bounds: clearing per-peer routes
// when newly disabled, seeding peers from the hostmap and flipping DF on
// outside sockets when newly enabled, and rebounding existing searches in
// place when only the ceiling moved.
func (m *pmtudManager) reload(c *config.C, initial bool) {
	if !initial && !c.HasChanged("tun.mtu") && !c.HasChanged("tun.max_mtu") {
		return
	}

	floor := c.GetInt("tun.mtu", overlay.DefaultMTU)
	maxMTU := c.GetInt("tun.max_mtu", 0)

	enable := maxMTU > floor && m.device.SupportsPerPeerMTU()
	var ceiling int
	if enable {
		ceiling = maxMTU + pmtudOverheadPessimistic
	}

	if initial {
		m.floor.Store(int64(floor))
		m.ceiling.Store(int64(ceiling))
		m.enabled.Store(enable)
		switch {
		case enable:
			m.l.Info("pmtud enabled", "floor", floor, "ceiling", ceiling, "tun.max_mtu", maxMTU)
		case maxMTU > floor:
			m.l.Warn("pmtud disabled: this platform does not yet support per-peer MTU routes",
				"tun.max_mtu", maxMTU)
		}
		return
	}

	wasEnabled := m.enabled.Load()
	m.floor.Store(int64(floor))
	m.ceiling.Store(int64(ceiling))
	m.enabled.Store(enable)

	switch {
	case wasEnabled && !enable:
		m.disableLive(floor, maxMTU)
	case !wasEnabled && enable:
		m.enableLive(floor, ceiling, maxMTU)
	case wasEnabled && enable:
		m.reboundLive(floor, ceiling, maxMTU)
	}
}

// disableLive clears per-peer routes and drops all peer state. We do not
// disable DF on the outside sockets; once on, it stays on for the life of the
// process. Operators flipping pmtud off live get correct routing behavior; if
// they want the historical no-DF behavior back they need to restart.
func (m *pmtudManager) disableLive(floor, maxMTU int) {
	m.peers.Range(func(k, v any) bool {
		p := v.(*pmtudPeer)
		p.mu.Lock()
		applied := p.applied
		addr := p.addr
		p.applied = 0
		p.mu.Unlock()
		if applied != 0 {
			if err := m.device.SetPeerMTU(addr, 0); err != nil {
				m.l.Warn("pmtud: failed to clear per-peer mtu on disable", "addr", addr, "error", err)
			}
		}
		m.peers.Delete(k)
		return true
	})
	m.l.Info("pmtud disabled (tun.max_mtu <= tun.mtu)", "tun.mtu", floor, "tun.max_mtu", maxMTU)
}

// enableLive flips DF on every outside socket. We don't pre-seed existing
// tunnels here; connection_manager's normal test cadence will eventually call
// MaybeProbeAsTest for each peer, which seeds on miss and lets the wheel pick
// up the search from there. New tunnels established after this point still
// take the OnTunnelUp fast path.
func (m *pmtudManager) enableLive(floor, ceiling, maxMTU int) {
	m.enableDF()
	m.l.Info("pmtud enabled", "floor", floor, "ceiling", ceiling, "tun.max_mtu", maxMTU)
}

// reboundLive resets each peer's search state to the new bounds. Peers whose
// confirmed PMTU still fits under the new ceiling keep their applied route in
// place during the new search; peers whose confirmed PMTU exceeds the new
// ceiling get cleared back to floor and re-search from scratch. The unsupported
// flag is preserved because peer software version doesn't change on reload.
func (m *pmtudManager) reboundLive(floor, ceiling, maxMTU int) {
	overhead := pmtudOverheadPessimistic
	m.peers.Range(func(k, v any) bool {
		p := v.(*pmtudPeer)
		p.mu.Lock()
		if p.applied > 0 && p.applied+overhead > ceiling {
			if err := m.device.SetPeerMTU(p.addr, 0); err != nil {
				m.l.Warn("pmtud: failed to clear per-peer mtu on rebound", "addr", p.addr, "error", err)
			} else {
				p.applied = 0
			}
		}
		p.low = floor + overhead
		p.high = ceiling
		p.inFlightSize = 0
		p.inFlightID = 0
		p.losses = 0
		p.firstProbe = !p.unsupported
		p.converged = false
		idx := p.localIdx
		unsupported := p.unsupported
		p.mu.Unlock()
		if !unsupported {
			m.wheel.Add(idx, pmtudProbeInterval)
		}
		return true
	})
	m.l.Info("pmtud reloaded", "floor", floor, "ceiling", ceiling, "tun.max_mtu", maxMTU)
}

// enableDF asks every outside socket to set the don't-fragment bit on outbound
// packets. Idempotent: safe to call from both Start (initial enable) and from a
// live reload that flips pmtud on.
func (m *pmtudManager) enableDF() {
	for i, w := range m.intf.writers {
		if err := w.EnablePathMTUDiscovery(); err != nil {
			m.l.Warn("pmtud: failed to enable path mtu discovery on outside socket; pmtud will not work correctly",
				"writer", i, "error", err)
		}
	}
}

// Start runs the probe scheduler until ctx is done. The loop runs even when PMTUD
// is disabled at startup so a hot reload can turn it on without restarting nebula.
//
// When PMTUD is enabled at startup we ask each outside socket to enable
// path-MTU discovery (DF on every send). This is intentionally gated on the
// feature being on so that operators who haven't opted in keep the historical
// behavior where the kernel may fragment outbound nebula UDP packets. A live
// reload from disabled to enabled will also flip DF on via enableLive; the
// reverse direction does not turn DF off, so flipping pmtud back off live
// keeps DF on until restart.
func (m *pmtudManager) Start(ctx context.Context) {
	if m.enabled.Load() {
		m.enableDF()
	}

	ticker := time.NewTicker(m.wheel.t.tickDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.wheel.Advance(now)
			for {
				idx, has := m.wheel.Purge()
				if !has {
					break
				}
				m.tick(idx)
			}
		}
	}
}

// OnTunnelUp is called when a HostInfo becomes traffic-watched. The kernel
// already routes packets to this peer through the per-vpn-network route (mtu =
// tun.mtu), so the floor is in effect implicitly. We just kick off the search
// here; HandleReply will install a per-host /32 (or /128) route once a larger
// size is confirmed.
func (m *pmtudManager) OnTunnelUp(hi *HostInfo) {
	if !m.enabled.Load() {
		return
	}
	m.seedPeer(hi)
}

// seedPeer is the shared body of OnTunnelUp and the live-reload enable path.
// LoadOrStore protects against double-seeding the same localIndexId from a
// race between OnTunnelUp and a reload-driven hostmap walk.
func (m *pmtudManager) seedPeer(hi *HostInfo) {
	if hi == nil || len(hi.vpnAddrs) == 0 {
		return
	}
	floor := int(m.floor.Load())
	ceiling := int(m.ceiling.Load())
	p := &pmtudPeer{
		addr:       hi.vpnAddrs[0],
		localIdx:   hi.localIndexId,
		low:        floor + pmtudOverheadPessimistic,
		high:       ceiling,
		firstProbe: true,
	}
	if _, loaded := m.peers.LoadOrStore(hi.localIndexId, p); loaded {
		return
	}
	m.wheel.Add(hi.localIndexId, pmtudProbeInterval)
}

// OnTunnelDown is called when a HostInfo is being torn down. Removes any per-host
// MTU override so the device default applies again.
func (m *pmtudManager) OnTunnelDown(hi *HostInfo) {
	if hi == nil {
		return
	}
	v, ok := m.peers.LoadAndDelete(hi.localIndexId)
	if !ok {
		return
	}
	p := v.(*pmtudPeer)
	p.mu.Lock()
	applied := p.applied
	addr := p.addr
	p.applied = 0
	p.mu.Unlock()
	if applied != 0 {
		if err := m.device.SetPeerMTU(addr, 0); err != nil {
			m.l.Warn("pmtud: failed to clear per-peer mtu", "addr", addr, "error", err)
		}
	}
}

// OnRoam is called when a HostInfo's remote underlay address changes. The path
// MTU may now be different; drop the per-host route so the kernel falls back to
// the per-vpn-network route (mtu = tun.mtu floor), then restart the search.
// We do not reset the unsupported flag: peer software version doesn't change on
// roam, so once we've decided a peer doesn't speak PMTUD we stay decided.
func (m *pmtudManager) OnRoam(hi *HostInfo) {
	if !m.enabled.Load() || hi == nil {
		return
	}
	v, ok := m.peers.Load(hi.localIndexId)
	if !ok {
		return
	}
	p := v.(*pmtudPeer)
	p.mu.Lock()
	if p.unsupported {
		p.mu.Unlock()
		return
	}
	p.low = int(m.floor.Load()) + pmtudOverheadPessimistic
	p.high = int(m.ceiling.Load())
	p.inFlightSize = 0
	p.inFlightID = 0
	p.losses = 0
	p.consecutiveFailures = 0
	p.firstProbe = true
	p.converged = false
	if p.applied != 0 {
		if err := m.device.SetPeerMTU(p.addr, 0); err != nil {
			m.l.Warn("pmtud: failed to clear per-peer mtu on roam", "addr", p.addr, "error", err)
		} else {
			p.applied = 0
		}
	}
	p.mu.Unlock()
	m.wheel.Add(hi.localIndexId, pmtudProbeInterval)
}

// MaybeProbeAsTest is called by connection_manager when it would otherwise send
// a TestRequest because a tunnel has gone silent. If we have a confirmed PMTU
// for this peer that's larger than the floor, we send a probe at that size
// instead. The reply confirms both liveness (consumed by connection_manager via
// the existing inbound traffic accounting fallthrough in outside.go) and that
// the confirmed PMTU still fits (consumed by HandleReply here). One synthetic
// packet does the work of two.
//
// Returns true if a probe was sent. False means the caller should send a
// regular TestRequest at the floor.
//
// On probe failure, connection_manager's existing pendingDeletion timeout will
// tear the tunnel down. Heavy hammer, but correct: a re-handshake re-runs PMTUD
// discovery against the now-shrunken path. A future EMSGSIZE-capture followup
// can replace this with a soft-drop-and-research flow.
func (m *pmtudManager) MaybeProbeAsTest(hi *HostInfo) bool {
	if !m.enabled.Load() || hi == nil {
		return false
	}
	v, ok := m.peers.Load(hi.localIndexId)
	if !ok {
		// Tunnel pre-dates the manager being aware of it (e.g. pmtud was just
		// enabled live, or AddTrafficWatch fired before this call). Seed the
		// peer so the wheel picks up the search; let connection_manager send
		// its regular TestRequest this cycle.
		m.seedPeer(hi)
		return false
	}
	p := v.(*pmtudPeer)
	p.mu.Lock()
	if p.unsupported || p.applied == 0 {
		p.mu.Unlock()
		return false
	}
	overhead := p.overhead()
	size := p.applied + overhead
	id := rand.Uint32()
	p.inFlightSize = size
	p.inFlightID = id
	p.mu.Unlock()

	m.sendProbe(hi, size, id, overhead)
	return true
}

// HandleReply consumes an MTUDProbeReply payload from the receive path.
func (m *pmtudManager) HandleReply(localIdx uint32, payload []byte) {
	if !m.enabled.Load() {
		return
	}
	if len(payload) < 8 {
		return
	}
	if binary.BigEndian.Uint32(payload[0:4]) != pmtudMagic {
		return
	}
	id := binary.BigEndian.Uint32(payload[4:8])

	v, ok := m.peers.Load(localIdx)
	if !ok {
		return
	}
	p := v.(*pmtudPeer)
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.inFlightSize == 0 || p.inFlightID != id {
		return
	}

	confirmed := p.inFlightSize
	p.low = confirmed
	p.inFlightSize = 0
	p.losses = 0
	p.everReplied = true
	p.consecutiveFailures = 0

	innerMTU := confirmed - p.overhead()
	// Only install a /32 override when it would actually raise the MTU above the
	// per-vpn-network floor route. If the discovered MTU is <= floor, the /24
	// already covers it; installing a /32 at floor would just create roam churn.
	if innerMTU > int(m.floor.Load()) && p.applied != innerMTU {
		if err := m.device.SetPeerMTU(p.addr, innerMTU); err != nil {
			m.l.Warn("pmtud: failed to apply per-peer mtu", "addr", p.addr, "innerMTU", innerMTU, "error", err)
		} else {
			m.l.Info("pmtud probe confirmed",
				"addr", p.addr,
				"outerMTU", confirmed,
				"innerMTU", innerMTU,
				"low", p.low,
				"high", p.high,
			)
			p.applied = innerMTU
		}
	}

	if p.high-p.low <= pmtudConverged {
		p.converged = true
	} else {
		p.converged = false
	}
}

// tick handles one wheel firing for a single peer.
func (m *pmtudManager) tick(localIdx uint32) {
	v, ok := m.peers.Load(localIdx)
	if !ok {
		return
	}
	p := v.(*pmtudPeer)
	p.mu.Lock()

	if p.unsupported {
		p.mu.Unlock()
		return
	}

	// If a probe was outstanding, this tick is the loss timeout.
	if p.inFlightSize != 0 {
		p.losses++
		p.consecutiveFailures++
		if p.losses >= pmtudMaxLoss {
			p.high = p.inFlightSize
			p.inFlightSize = 0
			p.losses = 0
			if p.high-p.low <= pmtudConverged {
				p.converged = true
			}
		}
	}

	// If we've never gotten a reply from this peer and we've burned through our
	// failure budget, conclude the peer doesn't understand the MTUDProbeRequest
	// subtype and stop scheduling probes for it.
	if !p.everReplied && p.consecutiveFailures >= pmtudUnsupportedAfter {
		p.unsupported = true
		addr := p.addr
		p.mu.Unlock()
		m.l.Info("pmtud: peer not responding to probes, marking unsupported",
			"addr", addr, "failures", pmtudUnsupportedAfter)
		return
	}

	hi := m.intf.hostMap.QueryIndex(localIdx)
	if hi == nil {
		p.mu.Unlock()
		m.peers.Delete(localIdx)
		return
	}

	// Once a peer converges, the wheel stops scheduling for it. Re-validation
	// (and the resulting black hole detection) is driven by connection_manager
	// via MaybeProbeAsTest at its natural test cadence, so a converged peer
	// has nothing for the wheel to do until OnRoam or a tunnel down/up cycle
	// triggers a fresh search.
	if p.converged {
		p.mu.Unlock()
		return
	}

	ceiling := int(m.ceiling.Load())
	var size int
	switch {
	case p.firstProbe:
		// Probe the ceiling directly. If the path supports it (the common case
		// when an operator has explicitly configured tun.max_mtu), we converge
		// in one round trip. If it fails, the standard binary search resumes
		// on the next tick from the (low, ceiling) bounds.
		size = ceiling
		p.firstProbe = false
	case p.losses > 0 && p.inFlightSize != 0:
		size = p.inFlightSize
	default:
		size = p.midpoint()
	}
	if size < pmtudFloor {
		size = pmtudFloor
	}
	if size > ceiling {
		size = ceiling
	}

	id := rand.Uint32()
	p.inFlightSize = size
	p.inFlightID = id
	overhead := p.overhead()
	p.mu.Unlock()

	m.sendProbe(hi, size, id, overhead)
	m.wheel.Add(localIdx, pmtudProbeInterval)
}

// sendProbe builds an MTUDProbeRequest payload that will produce an outer IP
// packet of approximately `outerSize` bytes, then sends it.
func (m *pmtudManager) sendProbe(hi *HostInfo, outerSize int, id uint32, overhead int) {
	payloadLen := outerSize - overhead
	if payloadLen < 8 {
		payloadLen = 8
	}
	p := make([]byte, payloadLen)
	binary.BigEndian.PutUint32(p[0:4], pmtudMagic)
	binary.BigEndian.PutUint32(p[4:8], id)
	// remaining bytes are zero-padding

	nb := make([]byte, 12)
	out := make([]byte, outerSize+128) // headroom for header/tag/relay framing
	m.intf.SendMessageToHostInfo(header.Test, header.MTUDProbeRequest, hi, p, nb, out)
}
