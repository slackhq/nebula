package nebula

import (
	"context"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
)

// Multiport lanes give one tunnel several underlay 5-tuples, so its traffic
// spreads over ECMP paths, NIC receive queues and per-flow policers instead of
// funnelling through a single flow. Each inside flow picks a lane by hashing its
// own 5-tuple, so the spread doesn't depend on how a kernel steers tun queues
// (see txQueue).
//
// A lane is not a second tunnel: it is an extra session on the same HostInfo.
// Noise leaves us with A.eKey == B.dKey, so both sides expand the same two keys
// with the same per-lane label and land on a matched pair without exchanging
// anything. A lane therefore costs no handshake, has no half-established state,
// and dies exactly when its base tunnel does. Which lane a packet belongs to
// travels in the nebula header, inside the AEAD's associated data.
//
// Lane 0 is the base tunnel itself: HostInfo.ConnectionState, socket 0, and the
// peer's real remote address, and it carries its share of flows like any other.
// Lane s > 0 egresses writers[s] (bound to
// listen.port+s) toward the peer's advertised port range. Receiving on a lane
// needs no permission — the keys are derivable the moment the base handshake
// completes — but sending on one needs proof the new 5-tuple actually works,
// since nothing else would notice a middlebox quietly dropping it. So a lane
// stays down until a probe on it is acked, and falls back to the base tunnel the
// moment it stops being acked.
//
// Both directions are pay-per-use. A lane session is derived on the first packet
// that needs it, because how many lanes exist is partly the peer's call: it
// advertises how many it sends on, and we have to be able to receive all of
// them. Deriving them all up front would let a peer advertising the maximum cost
// us a replay window and two cipher states per lane, per tunnel, for lanes it
// may never send on.

const (
	// laneKeyInfo is the HKDF label prefix for lane key expansion. Changing it
	// means older builds derive different keys and drop our lane traffic; the
	// base tunnel would keep working, so the failure would be a silent loss of
	// lanes rather than of connectivity.
	laneKeyInfo = "nebula multiport lane v1"

	// laneRetryBase and laneRetryMax bound the backoff between probes of a lane
	// that will not come up, so a peer whose lane ports are firewalled costs one
	// packet a minute rather than one per traffic tick.
	laneRetryBase = 5 * time.Second
	laneRetryMax  = 60 * time.Second

	// laneMaxFails caps the failure counter; the backoff saturates well before.
	laneMaxFails = 8

	// laneProbeTimeout is how long a probe may go unacked before it counts as a
	// failure. It is shorter than the connection manager's check interval on
	// purpose: an outstanding probe is judged on the next tick either way, and a
	// longer timeout would only delay that by a whole tick.
	laneProbeTimeout = 2 * time.Second

	// laneKeepalive is how often a lane that is up re-proves its path. Traffic
	// on a lane is not evidence the lane works — that is the whole reason lanes
	// need probing — so a lane that silently breaks is only caught here.
	laneKeepalive = 30 * time.Second
)

// laneSet holds a peer's lane sessions and the state deciding which lanes may
// carry traffic. It is built when the base handshake completes and never
// resized, so the slices and their lengths are immutable; mu guards the fields
// under it, and sessions/txAddr/demand are atomics read by the data plane
// without it.
type laneSet struct {
	// sessions[s] holds lane s's session once something has needed it, and nil
	// until then. sessions[0] is never populated: lane 0 is the base tunnel's own
	// ConnectionState. The length is immutable, so the data plane bounds-checks
	// and loads with no locking.
	sessions []atomic.Pointer[ConnectionState]

	// material is what a lane session is derived from, kept because sessions are
	// derived lazily and the handshake result is long gone by then.
	material laneMaterial

	// txAddr[s] holds lane s's remote address while the lane is proven usable
	// and nil otherwise. This single atomic is both the TX gate and the
	// destination, so a routine that loads non-nil has everything it needs.
	// Sized txLanes: lanes above that never send.
	txAddr []atomic.Pointer[netip.AddrPort]

	// demand[s] is raised at creation, and again by the TX path whenever a flow
	// hashes onto lane s while it is down. Probing is demand-driven, so a peer we
	// never send to costs nothing beyond its base tunnel no matter how many lanes
	// are configured, and a lane that keeps failing is only retried while
	// something still wants it. Sized txLanes.
	demand []atomic.Bool

	// txLanes is how many lanes we may send on — our lane count clamped to the
	// ports the peer bound — and so the modulus a flow's hash is reduced by.
	// Lanes from txLanes up can only receive, which is how a peer with more
	// routines than us still spreads its own traffic.
	// Immutable, and the length of every TX-side slice here.
	txLanes int

	mu sync.Mutex

	// peerPortCount and peerBasePort are the peer's advertised port range and
	// portOffset is this pair's rotation within it: lane s targets
	// peerBasePort + ((s + portOffset) % peerPortCount).
	peerPortCount uint16
	peerBasePort  uint16
	portOffset    uint16

	// laneBias rotates the flow hash before it picks a lane, so the two sides of
	// a flow land on lanes that are each other's partner rather than at
	// independent points in the range. See newLaneSet.
	laneBias uint16

	// peerAddr is the address the current lane targets were built from. The
	// peer's lane ports have no derivable relationship to a new NAT mapping, so
	// a roam invalidates every lane rather than moving it.
	peerAddr netip.Addr

	// probe[s] is lane s's probe and backoff state. Sized txLanes.
	probe []laneProbeState
}

// laneMaterial is everything a lane session is derived from. The two base keys
// are the same secret the base tunnel's own cipher states already hold — the
// noiseutil.CipherState interface just doesn't hand them back, so a lane set
// keeps its own copy rather than a reference to the session.
type laneMaterial struct {
	eKey, dKey [32]byte
	cipher     noise.CipherFunc
	myCert     cert.Certificate
	peerCert   *cert.CachedCertificate
	initiator  bool
}

type laneProbeState struct {
	// gen is the generation of the last probe sent, echoed in the ack so a late
	// ack cannot promote a lane on the strength of a superseded probe.
	gen uint8

	// fails is the consecutive failure count driving retryAt.
	fails uint8

	// sentAt is when the outstanding probe went out, zero when none is pending.
	sentAt time.Time

	// target is where the outstanding probe went, promoted to txAddr on ack.
	target netip.AddrPort

	// lastAck is when the lane was last confirmed usable, driving the keepalive.
	lastAck time.Time

	// retryAt is the earliest we may probe this lane again.
	retryAt time.Time
}

// newLaneSet sets up the lanes for a freshly completed base handshake. It
// returns nil when the pair has no lane beyond the base tunnel, which is the
// normal answer for a peer running without multiport. No session is derived
// here; each is derived on the first packet that needs it.
func newLaneSet(r *handshake.Result, myLanes int, myAddr, peerAddr netip.Addr) *laneSet {
	// PeerPortCount and PeerBasePort are already bounded to uint16 by the
	// handshake payload parser. A zero port count is a peer that did not
	// advertise multiport at all, so there is no lane to be had in either
	// direction.
	peerPorts := uint16(r.PeerPortCount)
	if peerPorts == 0 {
		return nil
	}

	// Sessions have to cover both directions: we send on our lanes and receive
	// on the peer's, and one derived session serves both ends of a lane index.
	// Only the session table is sized by the peer's advertised count; the TX-side
	// state is sized by what we will actually send on.
	n := min(max(myLanes, int(r.PeerTxLanes)), header.MaxLane+1)
	if n < 2 {
		return nil
	}
	txLanes := min(myLanes, int(peerPorts), n)

	offset := lanePortOffset(myAddr, peerAddr, peerPorts)

	// A flow picks its lane from a hash both sides compute identically, so with
	// the ranges lined up the two directions of a flow would pick the same lane
	// index — and lane s targets the peer's lane (s + portOffset), not lane s. The
	// high-addressed side rotates its choice by the low side's offset, which is
	// its own negated, so the two directions land on partner lanes and their
	// 4-tuples are exact reverses: each side's traffic then arrives through the
	// conntrack entry the other's probe opened. With mismatched ranges there are
	// no partner lanes to find, so don't pretend: hash straight.
	bias := uint16(0)
	if txLanes == int(peerPorts) && peerAddr.Less(myAddr) {
		bias = (peerPorts - offset) % peerPorts
	}

	ls := &laneSet{
		sessions: make([]atomic.Pointer[ConnectionState], n),
		material: laneMaterial{
			eKey:      r.EKey.UnsafeKey(),
			dKey:      r.DKey.UnsafeKey(),
			cipher:    r.Cipher,
			myCert:    r.MyCert,
			peerCert:  r.RemoteCert,
			initiator: r.Initiator,
		},
		txAddr:        make([]atomic.Pointer[netip.AddrPort], txLanes),
		demand:        make([]atomic.Bool, txLanes),
		probe:         make([]laneProbeState, txLanes),
		txLanes:       txLanes,
		peerPortCount: peerPorts,
		peerBasePort:  uint16(r.PeerBasePort),
		portOffset:    offset,
		laneBias:      bias,
	}

	// Every lane starts out demanded, so the first traffic tick on this tunnel
	// probes all of them at once instead of waiting for a flow to hash onto each.
	// Lanes have to be up *before* the flows are, not after: the peer writes a
	// flow's inbound packets to the tun queue matching the socket they arrived on,
	// and the kernel remembers that for as long as the flow stays busy. A flow that
	// starts while the lanes are still down therefore gets pinned to queue 0 on
	// both hosts for its whole life. This costs one probe per lane on any tunnel
	// with traffic; an idle tunnel is never ticked, so it still costs nothing.
	for s := 1; s < txLanes; s++ {
		ls.demand[s].Store(true)
	}
	return ls
}

// laneLogAttr summarizes what a tunnel negotiated, for the handshake log lines.
// It is an empty attr, which slog drops, on a node not running multiport. A peer
// that negotiated no lanes still logs, with zeros: "we offered and got nothing"
// is exactly what you want to see when you expected lanes and have none.
func laneLogAttr(myLanes int, ls *laneSet) slog.Attr {
	if myLanes == 0 {
		return slog.Attr{}
	}
	if ls == nil {
		return slog.Any("lanes", m{"tx": 0, "sessions": 0})
	}
	// Every field read here is immutable once the set is built.
	return slog.Any("lanes", m{
		"tx":           ls.txLanes,
		"sessions":     len(ls.sessions),
		"peerBasePort": ls.peerBasePort,
		"peerPorts":    ls.peerPortCount,
		"portOffset":   ls.portOffset,
	})
}

// emitLaneStats reports how many lanes are carrying traffic and how many tunnels
// have any. Both are counted by walking the hostmap, because a counter kept at
// promotion and demotion would drift upward forever: a tunnel torn down while its
// lanes are up never demotes them. Only a node running multiport pays for the
// walk.
func (f *Interface) emitLaneStats(up, tunnels metrics.Gauge) {
	var nUp, nTunnels int64
	f.hostMap.ForEachIndex(func(hostinfo *HostInfo) {
		ls := hostinfo.lanes
		if ls == nil {
			return
		}
		nTunnels++
		for s := 1; s < ls.txLanes; s++ {
			if ls.txAddr[s].Load() != nil {
				nUp++
			}
		}
	})
	up.Update(nUp)
	tunnels.Update(nTunnels)
}

// lanePortOffset returns the rotation applied to this pair's lane target ports,
// in [0, peerPortCount). Without it every low-routine peer would aim its few
// lanes at a big peer's first few ports, concentrating the big peer's receive
// work on a couple of sockets; the hash spreads pairs across the whole range.
//
// Both sides hash the same sorted vpn-address pair and the higher address
// negates the result, so when port counts match the two sides' rotations
// cancel: our lane s's 4-tuple stays the reverse of the peer's lane s, and each
// side's probe opens the conntrack entry the other's arrives through. (The one
// lane a nonzero rotation lands on the peer's base port has no partner lane;
// behind a port-restricted NAT it may never come up, and its routine rides the
// base tunnel — the standard lane fallback.)
func lanePortOffset(myAddr, peerAddr netip.Addr, peerPortCount uint16) uint16 {
	if peerPortCount == 0 {
		return 0
	}
	lo, hi := myAddr, peerAddr
	if hi.Less(lo) {
		lo, hi = hi, lo
	}
	h := fnv.New32a()
	b := lo.As16()
	h.Write(b[:])
	b = hi.As16()
	h.Write(b[:])
	o := uint16(h.Sum32() % uint32(peerPortCount))
	if myAddr == hi {
		o = (peerPortCount - o) % peerPortCount
	}
	return o
}

// laneSession returns the session to decrypt a lane s packet with, deriving one
// if this is the first packet to claim that lane. A nil session with no error
// means this tunnel has no lane s at all.
//
// cached reports whether the session was already in the table. A fresh one is
// deliberately left out of it: anyone who can spoof this tunnel's local index
// can name any lane, and installing on sight would let them make us hold a
// replay window and two cipher states per lane without authenticating anything.
// The caller must install with installSession once the packet decrypts, which is
// the first moment the lane is known to be real.
func (i *HostInfo) laneSession(s uint8) (ci *ConnectionState, cached bool, err error) {
	ls := i.lanes
	if ls == nil || s == 0 || int(s) >= len(ls.sessions) {
		return nil, false, nil
	}

	if cs := ls.sessions[s].Load(); cs != nil {
		return cs, true, nil
	}

	cs, err := newLaneConnectionState(&ls.material, s)
	if err != nil {
		return nil, false, err
	}
	return cs, false, nil
}

// installSession publishes a session derived by laneSession, so the next packet
// on the lane doesn't have to derive it again. cs must have already decrypted the
// packet at messageCounter.
//
// Two routines can race on a lane's first packet and derive a session each. The
// loser's is dropped, and with it the replay-window entry for the packet it just
// accepted, so hand that counter to the session that survives — the keys are
// identical, so it is the same window in every respect that matters.
func (ls *laneSet) installSession(l *slog.Logger, s uint8, cs *ConnectionState, messageCounter uint64) {
	if ls.sessions[s].CompareAndSwap(nil, cs) {
		return
	}
	ls.sessions[s].Load().noteSeen(l, messageCounter)
}

// session returns lane s's session for our own use, deriving and installing it
// if it doesn't exist yet. Unlike the RX path this needs no proof the lane is
// real: we only ask for lanes we chose to send on. s must be a lane this set
// covers.
func (ls *laneSet) session(s int) (*ConnectionState, error) {
	if cs := ls.sessions[s].Load(); cs != nil {
		return cs, nil
	}

	cs, err := newLaneConnectionState(&ls.material, uint8(s))
	if err != nil {
		return nil, err
	}

	if !ls.sessions[s].CompareAndSwap(nil, cs) {
		return ls.sessions[s].Load(), nil
	}
	return cs, nil
}

// maxMessageCounter returns the highest counter across the base session and
// every lane session. Data rides the lanes, so the base counter alone would
// never reach the rehandshake or exhaustion thresholds and the lane keys would
// be used past their data-volume margin. Rolling the base tunnel replaces the
// lane keys with it, since lanes are derived from it.
func (i *HostInfo) maxMessageCounter() uint64 {
	if i.ConnectionState == nil {
		return 0
	}
	c := i.ConnectionState.messageCounter.Load()
	if ls := i.lanes; ls != nil {
		for s := range ls.sessions {
			cs := ls.sessions[s].Load()
			if cs == nil {
				// Never derived, so it has never sent anything either.
				continue
			}
			if lc := cs.messageCounter.Load(); lc > c {
				c = lc
			}
		}
	}
	return c
}

// txLane returns the session and destination for lane s, or a nil session when
// the lane is down and the caller must use the base tunnel. A miss raises
// demand, which is what gets a down lane probed again, so we pay for a lane
// exactly where real traffic wanted one. Callers on the data plane come through
// txLaneForFlow.
func (ls *laneSet) txLane(s int) (*ConnectionState, netip.AddrPort) {
	if ls == nil || s <= 0 || s >= ls.txLanes {
		return nil, netip.AddrPort{}
	}

	if addr := ls.txAddr[s].Load(); addr != nil {
		// The lane is only up because a probe was acked on it, and that probe
		// derived the session, so this load cannot miss. Fall back rather than
		// derive here anyway: this is the hot path and a nil is not worth an HKDF.
		if cs := ls.sessions[s].Load(); cs != nil {
			return cs, *addr
		}
		return nil, netip.AddrPort{}
	}

	// Load-guarded so the common case of a lane that will not come up is a
	// plain read and cannot ping-pong the cache line these flags share.
	if !ls.demand[s].Load() {
		ls.demand[s].Store(true)
	}
	return nil, netip.AddrPort{}
}

// txLaneForFlow picks the lane a flow rides and returns it with its session and
// destination, or lane 0 and a nil session when the flow belongs on the base
// tunnel — either because the hash landed on lane 0 or because the lane it
// landed on is down.
//
// The lane comes from the flow rather than from the sending routine so that lane
// use doesn't depend on how the kernel steers tun queues; see txQueue. It is a
// pure function of the 5-tuple, so a flow stays on one lane for its life: no
// per-packet reordering, and one lane's replay window sees one set of flows.
func (ls *laneSet) txLaneForFlow(p *firewall.Packet) (int, *ConnectionState, netip.AddrPort) {
	if ls == nil || ls.txLanes < 2 {
		return 0, nil, netip.AddrPort{}
	}

	s := int((laneFlowHash(p) + uint32(ls.laneBias)) % uint32(ls.txLanes))
	if s == 0 {
		// Lane 0 is the base tunnel, and a full share of flows belongs on it.
		return 0, nil, netip.AddrPort{}
	}

	cs, addr := ls.txLane(s)
	return s, cs, addr
}

// laneFlowHash hashes a 5-tuple to the same value from either end of the flow,
// which is what lets both peers pick partner lanes for it (see laneBias). FNV-1a
// by hand rather than through hash/fnv: this runs per packet, and the interface
// there would escape the addresses to the heap.
func laneFlowHash(p *firewall.Packet) uint32 {
	// Order the two endpoints so the direction of travel cannot change the hash.
	aAddr, aPort := p.LocalAddr, p.LocalPort
	bAddr, bPort := p.RemoteAddr, p.RemotePort
	if bAddr.Less(aAddr) || (aAddr == bAddr && bPort < aPort) {
		aAddr, aPort, bAddr, bPort = bAddr, bPort, aAddr, aPort
	}

	const prime = 16777619
	h := uint32(2166136261)
	x, y := aAddr.As16(), bAddr.As16()
	for i := range x {
		h = (h ^ uint32(x[i])) * prime
		h = (h ^ uint32(y[i])) * prime
	}
	for _, b := range [5]byte{byte(aPort >> 8), byte(aPort), byte(bPort >> 8), byte(bPort), p.Protocol} {
		h = (h ^ uint32(b)) * prime
	}
	return h
}

// laneTargetPortLocked returns the peer port lane s aims at. Only meaningful
// when peerPortCount is nonzero, which txLanes > 0 guarantees.
func (ls *laneSet) laneTargetPortLocked(s int) uint16 {
	return ls.peerBasePort + uint16((s+int(ls.portOffset))%int(ls.peerPortCount))
}

// laneRetryDelay is the backoff after fails consecutive probe failures.
func laneRetryDelay(fails uint8) time.Duration {
	d := laneRetryBase << min(fails, 4)
	if d > laneRetryMax {
		d = laneRetryMax
	}
	return d
}

// noteAck records an acked probe for lane s, promoting the lane if it was down.
// gen must match the outstanding probe. Reports whether the lane was promoted.
func (ls *laneSet) noteAck(s int, gen uint8, now time.Time) bool {
	if s <= 0 || s >= len(ls.probe) {
		return false
	}

	ls.mu.Lock()
	defer ls.mu.Unlock()

	p := &ls.probe[s]
	if p.sentAt.IsZero() || p.gen != gen {
		// No probe outstanding, or an ack for a probe we have already given up
		// on. Either way it says nothing about the lane's current path.
		return false
	}

	p.sentAt = time.Time{}
	p.lastAck = now
	p.fails = 0
	p.retryAt = time.Time{}

	if ls.txAddr[s].Load() != nil {
		// Keepalive for a lane already up.
		return false
	}

	target := p.target
	ls.txAddr[s].Store(&target)
	return true
}

// probeLanes runs one lane maintenance pass for a peer: it demotes lanes whose
// probe went unanswered, re-proves lanes that have been up a while without one,
// and probes down lanes the data plane asked for. Driven by the connection
// manager's per-tunnel traffic tick, which only fires for a live tunnel — the
// same condition that produces lane demand in the first place.
func (f *Interface) probeLanes(hostinfo *HostInfo, now time.Time, nb, out []byte) {
	ls := hostinfo.lanes
	if ls == nil || ls.txLanes < 2 {
		return
	}

	remote := hostinfo.GetRemote()

	ls.mu.Lock()
	defer ls.mu.Unlock()

	if !remote.IsValid() {
		// Relayed, or otherwise without a direct path. Lanes are direct-only,
		// so drop them all; a later tick rebuilds if a direct path returns.
		ls.resetLocked()
		return
	}

	if ls.peerAddr != remote.Addr() {
		if ls.peerAddr.IsValid() {
			// A roam is a new path, not a failure: forget the lanes built on
			// the old one and let demand re-probe from a clean backoff. On the
			// first pass there is nothing built yet, so just record the address.
			ls.resetLocked()
		}
		ls.peerAddr = remote.Addr()
	}

	for s := 1; s < ls.txLanes; s++ {
		p := &ls.probe[s]
		up := ls.txAddr[s].Load() != nil

		if !p.sentAt.IsZero() {
			if now.Sub(p.sentAt) < laneProbeTimeout {
				continue
			}

			// An aged-out probe is a failure whether it was bringing the lane
			// up or keeping it up.
			p.sentAt = time.Time{}
			p.fails = min(p.fails+1, laneMaxFails)
			p.retryAt = now.Add(laneRetryDelay(p.fails))
			if up {
				ls.txAddr[s].Store(nil)
				hostinfo.logger(f.l).Info("Multiport lane demoted, probe unanswered", "lane", s)
			}
			continue
		}

		if up {
			if now.Sub(p.lastAck) < laneKeepalive {
				continue
			}
		} else if now.Before(p.retryAt) || !ls.demand[s].Swap(false) {
			continue
		}

		p.gen++
		p.target = netip.AddrPortFrom(remote.Addr(), ls.laneTargetPortLocked(s))
		if f.sendLaneProbe(hostinfo, s, p.gen, p.target, nb, out) {
			p.sentAt = now
		} else {
			p.fails = min(p.fails+1, laneMaxFails)
			p.retryAt = now.Add(laneRetryDelay(p.fails))
		}
	}
}

// resetLocked takes every lane down and clears its probe state, without
// counting it as a failure.
//
// Demand is deliberately left standing: it records that a routine has real
// traffic for this peer, which a roam or a relay detour does not change. Keeping
// it re-probes the lanes that were actually carrying data as soon as a path
// exists again, while a lane whose routine has gone quiet stays down.
func (ls *laneSet) resetLocked() {
	for s := 1; s < len(ls.probe); s++ {
		ls.txAddr[s].Store(nil)
		ls.probe[s] = laneProbeState{}
	}
}

// sendLaneProbe sends a probe on lane s to addr from writers[s]. The probe is an
// ordinary Test packet encrypted with the lane's session, so an ack proves the
// whole lane: our source port reached the peer, its reply reached us, and the
// keys we derived for this lane match the ones it derived. Reports whether the
// probe made it onto the wire.
func (f *Interface) sendLaneProbe(hostinfo *HostInfo, s int, gen uint8, addr netip.AddrPort, nb, out []byte) bool {
	// The first probe on a lane is what derives its session.
	ci, err := hostinfo.lanes.session(s)
	if err != nil {
		hostinfo.logger(f.l).Error("Failed to derive multiport lane session", "error", err, "lane", s)
		return false
	}
	if ci == nil || ci.eKey == nil {
		return false
	}

	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Lock()
	}
	c, ok := ci.NextMessageCounter()
	if !ok {
		if noiseutil.EncryptLockNeeded {
			ci.writeLock.Unlock()
		}
		f.dropExhausted(hostinfo, c, "Dropping multiport lane probe, lane message counter is exhausted")
		return false
	}

	b := header.EncodeLane(out[:0], header.Version, header.Test, header.LaneProbe, hostinfo.remoteIndexId, c, uint8(s))
	b, err = ci.eKey.EncryptDanger(b, b, []byte{uint8(s), gen}, c, nb)
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Unlock()
	}
	if err != nil {
		hostinfo.logger(f.l).Error("Failed to encrypt multiport lane probe", "error", err, "lane", s)
		return false
	}

	f.messageMetrics.Tx(header.Test, header.LaneProbe, 1)
	if err := f.writers[s].WriteTo(b, addr); err != nil {
		hostinfo.logger(f.l).Error("Failed to send multiport lane probe", "error", err, "lane", s, "udpAddr", addr)
		return false
	}

	if f.l.Enabled(context.Background(), slog.LevelDebug) {
		hostinfo.logger(f.l).Debug("Multiport lane probe sent", "lane", s, "gen", gen, "udpAddr", addr)
	}
	return true
}

// handleLaneProbe answers a peer's lane probe. The ack rides the base tunnel on
// purpose: a probe proves the peer's lane s works in its send direction, and
// answering on our own lane s would make the result depend on a second path
// that may be broken independently.
func (f *Interface) handleLaneProbe(hostinfo *HostInfo, lane uint8, payload []byte, rxc *rxContext) {
	if lane == 0 || len(payload) < 2 {
		return
	}

	// Echo the header's lane rather than the payload's, so a peer cannot get us
	// to vouch for a lane it did not actually probe.
	f.send(header.Test, header.LaneProbeAck, hostinfo.ConnectionState, hostinfo,
		[]byte{lane, payload[1]}, rxc.nb, rxc.scratch[:0])
}

// handleLaneProbeAck promotes the lane a peer just acked.
func (f *Interface) handleLaneProbeAck(hostinfo *HostInfo, payload []byte) {
	ls := hostinfo.lanes
	if ls == nil || len(payload) < 2 {
		return
	}

	if ls.noteAck(int(payload[0]), payload[1], time.Now()) {
		hostinfo.logger(f.l).Info("Multiport lane up", "lane", payload[0])
	}
}
