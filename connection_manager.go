package nebula

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/pq"
)

type trafficDecision int

const (
	doNothing      trafficDecision = 0
	deleteTunnel   trafficDecision = 1 // delete the hostinfo on our side, do not notify the remote
	closeTunnel    trafficDecision = 2 // delete the hostinfo and notify the remote
	swapPrimary    trafficDecision = 3
	migrateRelays  trafficDecision = 4
	tryRehandshake trafficDecision = 5
	sendTestPacket trafficDecision = 6
)

type connectionManager struct {
	// relayUsed holds which relay localIndexs are in use
	relayUsed     map[uint32]struct{}
	relayUsedLock *sync.RWMutex

	hostMap      *HostMap
	trafficTimer *LockingTimerWheel[uint32]
	intf         *Interface
	punchy       *Punchy

	// Configuration settings
	checkInterval           time.Duration
	pendingDeletionInterval time.Duration
	inactivityTimeout       atomic.Int64
	dropInactive            atomic.Bool

	l *slog.Logger
}

func newConnectionManagerFromConfig(l *slog.Logger, c *config.C, hm *HostMap, p *Punchy) *connectionManager {
	cm := &connectionManager{
		hostMap:       hm,
		l:             l,
		punchy:        p,
		relayUsed:     make(map[uint32]struct{}),
		relayUsedLock: &sync.RWMutex{},
	}

	cm.reload(c, true)
	c.RegisterReloadCallback(func(c *config.C) {
		cm.reload(c, false)
	})

	return cm
}

func (cm *connectionManager) reload(c *config.C, initial bool) {
	if initial {
		cm.checkInterval = time.Duration(c.GetInt("timers.connection_alive_interval", 5)) * time.Second
		cm.pendingDeletionInterval = time.Duration(c.GetInt("timers.pending_deletion_interval", 10)) * time.Second

		// We want at least a minimum resolution of 500ms per tick so that we can hit these intervals
		// pretty close to their configured duration.
		// The inactivity duration is checked each time a hostinfo ticks through so we don't need the wheel to contain it.
		minDuration := min(time.Millisecond*500, cm.checkInterval, cm.pendingDeletionInterval)
		maxDuration := max(cm.checkInterval, cm.pendingDeletionInterval)
		cm.trafficTimer = NewLockingTimerWheel[uint32](minDuration, maxDuration)
	}

	if initial || c.HasChanged("tunnels.inactivity_timeout") {
		old := cm.getInactivityTimeout()
		cm.inactivityTimeout.Store((int64)(c.GetDuration("tunnels.inactivity_timeout", 10*time.Minute)))
		if !initial {
			cm.l.Info("Inactivity timeout has changed",
				"oldDuration", old,
				"newDuration", cm.getInactivityTimeout(),
			)
		}
	}

	if initial || c.HasChanged("tunnels.drop_inactive") {
		old := cm.dropInactive.Load()
		cm.dropInactive.Store(c.GetBool("tunnels.drop_inactive", false))
		if !initial {
			cm.l.Info("Drop inactive setting has changed",
				"oldBool", old,
				"newBool", cm.dropInactive.Load(),
			)
		}
	}
}

func (cm *connectionManager) getInactivityTimeout() time.Duration {
	return (time.Duration)(cm.inactivityTimeout.Load())
}

func (cm *connectionManager) In(h *HostInfo) {
	h.in.Store(true)
}

func (cm *connectionManager) Out(h *HostInfo) {
	h.out.Store(true)
}

func (cm *connectionManager) RelayUsed(localIndex uint32) {
	cm.relayUsedLock.RLock()
	// If this already exists, return
	if _, ok := cm.relayUsed[localIndex]; ok {
		cm.relayUsedLock.RUnlock()
		return
	}
	cm.relayUsedLock.RUnlock()
	cm.relayUsedLock.Lock()
	cm.relayUsed[localIndex] = struct{}{}
	cm.relayUsedLock.Unlock()
}

// getAndResetTrafficCheck returns if there was any inbound or outbound traffic within the last tick and
// resets the state for this local index
func (cm *connectionManager) getAndResetTrafficCheck(h *HostInfo, now time.Time) (bool, bool) {
	in := h.in.Swap(false)
	out := h.out.Swap(false)
	if in || out {
		h.lastUsed = now
	}
	return in, out
}

func (cm *connectionManager) Start(ctx context.Context) {
	clockSource := time.NewTicker(cm.trafficTimer.t.tickDuration)
	defer clockSource.Stop()

	// pqRotation fires whenever the active PQ Provider believes its
	// material may have changed (file rotation, socket update, etc.).
	// We coalesce these into hostmap walks that re-evaluate each
	// peer's desired subtype and trigger upgrade rekeys without
	// waiting for the next traffic tick.
	//
	// Subscribe to the PKI's stable rotation channel, NOT the
	// underlying provider's Subscribe(): the underlying provider is
	// replaced on every config reload, so a direct Subscribe()
	// would silently stop receiving events after the first reload.
	// PKI.PQRotation() returns a process-lifetime-stable channel
	// that the PKI internally re-binds to whichever composed
	// provider is currently installed.
	pqRotation := cm.intf.pki.PQRotation()

	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	for {
		select {
		case <-ctx.Done():
			return

		case now := <-clockSource.C:
			cm.trafficTimer.Advance(now)
			for {
				localIndex, has := cm.trafficTimer.Purge()
				if !has {
					break
				}

				cm.doTrafficCheck(localIndex, p, nb, out, now)
			}

		case _, ok := <-pqRotation:
			if !ok {
				// Provider closed; stop listening but keep ticking.
				pqRotation = nil
				continue
			}
			cm.onPQRotation()
		}
	}
}

// pqRekeyMinInterval bounds how often a single peer can be re-handshaked
// in response to PSK rotation events. A typical PQ-PSK provider's default
// rekey interval is ~120s; at 90s here we trigger a refresh on every rotation while
// preventing a misbehaving provider (or coalesced notify burst) from
// pinning the handshake_manager with back-to-back rekeys.
const pqRekeyMinInterval = 90 * time.Second

// pqRequiredCloseThreshold is the hysteresis gate for ModeRequired
// teardown. When the PQ policy refuses to re-handshake a peer (PSK
// absent in required/enforce mode), the ConnectionManager does NOT tear
// the tunnel down on the first miss — a single missed FileProvider
// rescan or a transient provider blip should not blackout a working
// tunnel. The tunnel is only closed once the policy has refused on this
// many consecutive traffic-check ticks. With the default
// timers.connection_alive_interval of 5s, three misses is ~15s of
// sustained PSK absence before teardown. The counter resets to zero the
// moment the policy is satisfied again.
const pqRequiredCloseThreshold = 3

// metricPQTunnelClosedPolicy counts tunnels torn down by the
// ConnectionManager because the PQ policy refused to keep them up
// (ModeRequired with the peer's PSK absent past the hysteresis gate).
// Registered lazily on the default registry to match nebula's existing
// go-metrics convention; lives in the nebula package (not pq) because
// the teardown decision and the HostInfo it acts on are nebula-internal.
const metricPQTunnelClosedPolicy = "pq.tunnel_closed_policy"

// onPQRotation is invoked when the PQ Provider reports new PSK
// material. We walk the main hostmap and ask the policy whether each
// peer now wants a different subtype than the one currently in force.
//
// Two cases trigger a re-handshake:
//
//  1. Upgrade (NoPSK → PerPeer): the peer's PSK just became available,
//     promote the tunnel from IXPSK0 to IXPSK2 without waiting for the
//     next traffic-check tick.
//
//  2. Steady-state refresh (PerPeer → PerPeer): the tunnel is already
//     IXPSK2 but the PSK material backing it rotated. Re-handshake so
//     the new PSK is mixed into a fresh noise state and derived into
//     new eKey/dKey. Without this branch, the provider's periodic rekey
//     never reaches nebula's traffic encryption; the symmetric keys
//     stay fixed from the original handshake until something else
//     forces a re-handshake (cert change, etc.). Gated per-peer by
//     pqRekeyMinInterval to bound churn.
func (cm *connectionManager) onPQRotation() {
	policy := cm.intf.pki.PQPolicy()
	cm.hostMap.RLock()
	hosts := make([]*HostInfo, 0, len(cm.hostMap.Hosts))
	for _, h := range cm.hostMap.Hosts {
		hosts = append(hosts, h)
	}
	cm.hostMap.RUnlock()

	nowNanos := uint64(time.Now().UnixNano())
	for _, h := range hosts {
		if h.ConnectionState == nil {
			continue
		}
		peerCrt := h.ConnectionState.peerCert
		if peerCrt == nil {
			continue
		}
		current := pq.SubtypeNoPSK
		if h.ConnectionState.subtype == header.HandshakeIXPSK2 {
			current = pq.SubtypePerPeer
		}
		desired, err := policy.InitiatorSubtype(pq.PeerInfo{
			StaticPubKey: peerCrt.Certificate.PublicKey(),
			Fingerprint:  peerCrt.Fingerprint,
			Groups:       peerCrt.Certificate.Groups(),
		})
		if err != nil {
			// Policy refuses to handshake; let the next traffic-check
			// tick close the tunnel via tryRehandshake's policy gate.
			continue
		}
		if desired == pq.SubtypePerPeer && current != pq.SubtypePerPeer {
			cm.l.Info("Re-handshaking with remote",
				"vpnAddrs", h.vpnAddrs,
				"reason", "PQ material rotated; upgrading to IXPSK2",
			)
			cm.intf.handshakeManager.StartHandshake(h.vpnAddrs[0], nil)
			continue
		}
		if desired == pq.SubtypePerPeer && current == pq.SubtypePerPeer {
			// lastHandshakeTime is remote-reported unix nanos at handshake
			// completion (anti-replay anchor). Close enough to "wall time
			// of last handshake" given normal NTP-bounded skew. A zero
			// value (handshake in progress) is treated as recent and
			// suppresses the trigger. A remote clock ahead of ours would
			// underflow the uint64 subtraction and defeat the throttle
			// (rekey on every rotation event), so treat future timestamps
			// as "recent" too — the throttle then errs toward suppression,
			// never toward a rekey storm.
			if h.lastHandshakeTime == 0 || nowNanos < h.lastHandshakeTime ||
				nowNanos-h.lastHandshakeTime < uint64(pqRekeyMinInterval) {
				continue
			}
			cm.l.Info("Re-handshaking with remote",
				"vpnAddrs", h.vpnAddrs,
				"reason", "PQ PSK rotated; refreshing derived keys",
			)
			cm.intf.handshakeManager.StartHandshake(h.vpnAddrs[0], nil)
		}
	}
}

func (cm *connectionManager) doTrafficCheck(localIndex uint32, p, nb, out []byte, now time.Time) {
	decision, hostinfo, primary := cm.makeTrafficDecision(localIndex, now)

	switch decision {
	case deleteTunnel:
		if cm.hostMap.DeleteHostInfo(hostinfo) {
			// Only clearing the lighthouse cache if this is the last hostinfo for this vpn ip in the hostmap
			cm.intf.lightHouse.DeleteVpnAddrs(hostinfo.vpnAddrs)
		}

	case closeTunnel:
		cm.intf.sendCloseTunnel(hostinfo)
		cm.intf.closeTunnel(hostinfo)

	case swapPrimary:
		cm.swapPrimary(hostinfo, primary)

	case migrateRelays:
		cm.migrateRelayUsed(hostinfo, primary)

	case tryRehandshake:
		cm.tryRehandshake(hostinfo)

	case sendTestPacket:
		cm.intf.SendMessageToHostInfo(header.Test, header.TestRequest, hostinfo, p, nb, out)
	}

	cm.resetRelayTrafficCheck(hostinfo)
}

func (cm *connectionManager) resetRelayTrafficCheck(hostinfo *HostInfo) {
	if hostinfo != nil {
		cm.relayUsedLock.Lock()
		defer cm.relayUsedLock.Unlock()
		// No need to migrate any relays, delete usage info now.
		for _, idx := range hostinfo.relayState.CopyRelayForIdxs() {
			delete(cm.relayUsed, idx)
		}
	}
}

func (cm *connectionManager) migrateRelayUsed(oldhostinfo, newhostinfo *HostInfo) {
	relayFor := oldhostinfo.relayState.CopyAllRelayFor()

	for _, r := range relayFor {
		existing, ok := newhostinfo.relayState.QueryRelayForByIp(r.PeerAddr)

		var index uint32
		var relayFrom netip.Addr
		var relayTo netip.Addr
		switch {
		case ok:
			switch existing.State {
			case Established, PeerRequested, Disestablished:
				// This relay already exists in newhostinfo, then do nothing.
				continue
			case Requested:
				// The relay exists in a Requested state; re-send the request
				index = existing.LocalIndex
				switch r.Type {
				case TerminalType:
					relayFrom = cm.intf.myVpnAddrs[0]
					relayTo = existing.PeerAddr
				case ForwardingType:
					relayFrom = existing.PeerAddr
					relayTo = newhostinfo.vpnAddrs[0]
				default:
					// should never happen
					panic(fmt.Sprintf("Migrating unknown relay type: %v", r.Type))
				}
			}
		case !ok:
			cm.relayUsedLock.RLock()
			if _, relayUsed := cm.relayUsed[r.LocalIndex]; !relayUsed {
				// The relay hasn't been used; don't migrate it.
				cm.relayUsedLock.RUnlock()
				continue
			}
			cm.relayUsedLock.RUnlock()
			// The relay doesn't exist at all; create some relay state and send the request.
			var err error
			index, err = AddRelay(cm.l, newhostinfo, cm.hostMap, r.PeerAddr, nil, r.Type, Requested)
			if err != nil {
				cm.l.Error("failed to migrate relay to new hostinfo", "error", err)
				continue
			}
			switch r.Type {
			case TerminalType:
				relayFrom = cm.intf.myVpnAddrs[0]
				relayTo = r.PeerAddr
			case ForwardingType:
				relayFrom = r.PeerAddr
				relayTo = newhostinfo.vpnAddrs[0]
			default:
				// should never happen
				panic(fmt.Sprintf("Migrating unknown relay type: %v", r.Type))
			}
		}

		// Send a CreateRelayRequest to the peer.
		req := NebulaControl{
			Type:                NebulaControl_CreateRelayRequest,
			InitiatorRelayIndex: index,
		}

		switch newhostinfo.GetCert().Certificate.Version() {
		case cert.Version1:
			if !relayFrom.Is4() {
				cm.l.Error("can not migrate v1 relay with a v6 network because the relay is not running a current nebula version")
				continue
			}

			if !relayTo.Is4() {
				cm.l.Error("can not migrate v1 relay with a v6 remote network because the relay is not running a current nebula version")
				continue
			}

			b := relayFrom.As4()
			req.OldRelayFromAddr = binary.BigEndian.Uint32(b[:])
			b = relayTo.As4()
			req.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
		case cert.Version2:
			req.RelayFromAddr = netAddrToProtoAddr(relayFrom)
			req.RelayToAddr = netAddrToProtoAddr(relayTo)
		default:
			newhostinfo.logger(cm.l).Error("Unknown certificate version found while attempting to migrate relay")
			continue
		}

		msg, err := req.Marshal()
		if err != nil {
			cm.l.Error("failed to marshal Control message to migrate relay", "error", err)
		} else {
			cm.intf.SendMessageToHostInfo(header.Control, 0, newhostinfo, msg, make([]byte, 12), make([]byte, mtu))
			cm.l.Info("send CreateRelayRequest",
				"relayFrom", req.RelayFromAddr,
				"relayTo", req.RelayToAddr,
				"initiatorRelayIndex", req.InitiatorRelayIndex,
				"responderRelayIndex", req.ResponderRelayIndex,
				"vpnAddrs", newhostinfo.vpnAddrs,
			)
		}
	}
}

func (cm *connectionManager) makeTrafficDecision(localIndex uint32, now time.Time) (trafficDecision, *HostInfo, *HostInfo) {
	// Read lock the main hostmap to order decisions based on tunnels being the primary tunnel
	cm.hostMap.RLock()
	defer cm.hostMap.RUnlock()

	hostinfo := cm.hostMap.Indexes[localIndex]
	if hostinfo == nil {
		cm.l.Debug("Not found in hostmap", "localIndex", localIndex)
		return doNothing, nil, nil
	}

	if cm.isInvalidCertificate(now, hostinfo) {
		return closeTunnel, hostinfo, nil
	}

	primary := cm.hostMap.Hosts[hostinfo.vpnAddrs[0]]
	mainHostInfo := true
	if primary != nil && primary != hostinfo {
		mainHostInfo = false
	}

	// Check for traffic on this hostinfo
	inTraffic, outTraffic := cm.getAndResetTrafficCheck(hostinfo, now)

	// A hostinfo is determined alive if there is incoming traffic
	if inTraffic {
		decision := doNothing
		if cm.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(cm.l).Debug("Tunnel status",
				"tunnelCheck", m{"state": "alive", "method": "passive"},
			)
		}
		hostinfo.pendingDeletion.Store(false)

		if mainHostInfo {
			decision = tryRehandshake
		} else {
			if cm.shouldSwapPrimary(hostinfo) {
				decision = swapPrimary
			} else {
				// migrate the relays to the primary, if in use.
				decision = migrateRelays
			}
		}

		cm.trafficTimer.Add(hostinfo.localIndexId, cm.checkInterval)

		if !outTraffic {
			// Send a punch packet to keep the NAT state alive
			cm.punchy.SendPunch(hostinfo)
		}

		return decision, hostinfo, primary
	}

	if hostinfo.pendingDeletion.Load() {
		// We have already sent a test packet and nothing was returned, this hostinfo is dead
		hostinfo.logger(cm.l).Info("Tunnel status",
			"tunnelCheck", m{"state": "dead", "method": "active"},
		)

		return deleteTunnel, hostinfo, nil
	}

	decision := doNothing
	if hostinfo != nil && hostinfo.ConnectionState != nil && mainHostInfo {
		if !outTraffic {
			inactiveFor, isInactive := cm.isInactive(hostinfo, now)
			if isInactive {
				// Tunnel is inactive, tear it down
				hostinfo.logger(cm.l).Info("Dropping tunnel due to inactivity",
					"inactiveDuration", inactiveFor,
					"primary", mainHostInfo,
				)

				return closeTunnel, hostinfo, primary
			}

			// If we aren't sending or receiving traffic then its an unused tunnel and we don't to test the tunnel.
			// Just maintain NAT state if configured to do so.
			cm.punchy.SendPunch(hostinfo)
			cm.trafficTimer.Add(hostinfo.localIndexId, cm.checkInterval)
			return doNothing, nil, nil
		}

		// We aren't receiving traffic but we are sending it. The outbound
		// traffic itself refreshes the primary remote's NAT state; this
		// fans out to non-primary remotes, but only if target_all_remotes
		// is configured.
		cm.punchy.SendPunchToAll(hostinfo)

		if cm.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(cm.l).Debug("Tunnel status",
				"tunnelCheck", m{"state": "testing", "method": "active"},
			)
		}

		// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
		decision = sendTestPacket

	} else {
		if cm.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(cm.l).Debug("Hostinfo sadness")
		}
	}

	hostinfo.pendingDeletion.Store(true)
	cm.trafficTimer.Add(hostinfo.localIndexId, cm.pendingDeletionInterval)
	return decision, hostinfo, nil
}

func (cm *connectionManager) isInactive(hostinfo *HostInfo, now time.Time) (time.Duration, bool) {
	if cm.dropInactive.Load() == false {
		// We aren't configured to drop inactive tunnels
		return 0, false
	}

	inactiveDuration := now.Sub(hostinfo.lastUsed)
	if inactiveDuration < cm.getInactivityTimeout() {
		// It's not considered inactive
		return inactiveDuration, false
	}

	// The tunnel is inactive
	return inactiveDuration, true
}

func (cm *connectionManager) shouldSwapPrimary(current *HostInfo) bool {
	// The primary tunnel is the most recent handshake to complete locally and should work entirely fine.
	// If we are here then we have multiple tunnels for a host pair and neither side believes the same tunnel is primary.
	// Let's sort this out.

	// Only one side should swap because if both swap then we may never resolve to a single tunnel.
	// vpn addr is static across all tunnels for this host pair so lets
	// use that to determine if we should consider swapping.
	if current.vpnAddrs[0].Compare(cm.intf.myVpnAddrs[0]) < 0 {
		// Their primary vpn addr is less than mine. Do not swap.
		return false
	}

	crt := cm.intf.pki.getCertState().getCertificate(current.ConnectionState.myCert.Version())
	if crt == nil {
		//my cert was reloaded away. We should definitely swap from this tunnel
		return true
	}
	// If this tunnel is using the latest certificate then we should swap it to primary for a bit and see if things
	// settle down.
	return bytes.Equal(current.ConnectionState.myCert.Signature(), crt.Signature())
}

func (cm *connectionManager) swapPrimary(current, primary *HostInfo) {
	cm.hostMap.Lock()
	// Make sure the primary is still the same after the write lock. This avoids a race with a rehandshake.
	if cm.hostMap.Hosts[current.vpnAddrs[0]] == primary {
		cm.hostMap.unlockedMakePrimary(current)
	}
	cm.hostMap.Unlock()
}

// isInvalidCertificate decides if we should destroy a tunnel.
// returns true if pki.disconnect_invalid is true and the certificate is no longer valid.
// Blocklisted certificates will skip the pki.disconnect_invalid check and return true.
func (cm *connectionManager) isInvalidCertificate(now time.Time, hostinfo *HostInfo) bool {
	remoteCert := hostinfo.GetCert()
	if remoteCert == nil {
		return false //don't tear down tunnels for handshakes in progress
	}

	caPool := cm.intf.pki.GetCAPool()
	err := caPool.VerifyCachedCertificate(now, remoteCert)
	if err == nil {
		return false //cert is still valid! yay!
	} else if err == cert.ErrBlockListed { //avoiding errors.Is for speed
		// Block listed certificates should always be disconnected
		hostinfo.logger(cm.l).Info("Remote certificate is blocked, tearing down the tunnel",
			"error", err,
			"fingerprint", remoteCert.Fingerprint,
		)
		return true
	} else if cm.intf.disconnectInvalid.Load() {
		hostinfo.logger(cm.l).Info("Remote certificate is no longer valid, tearing down the tunnel",
			"error", err,
			"fingerprint", remoteCert.Fingerprint,
		)
		return true
	} else {
		//if we reach here, the cert is no longer valid, but we're configured to keep tunnels from now-invalid certs open
		return false
	}
}

func (cm *connectionManager) tryRehandshake(hostinfo *HostInfo) {
	cs := cm.intf.pki.getCertState()
	curCrt := hostinfo.ConnectionState.myCert
	curCrtVersion := curCrt.Version()
	myCrt := cs.getCertificate(curCrtVersion)
	if myCrt == nil {
		cm.l.Info("Re-handshaking with remote",
			"vpnAddrs", hostinfo.vpnAddrs,
			"version", curCrtVersion,
			"reason", "local certificate removed",
		)
		cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
		return
	}
	peerCrt := hostinfo.ConnectionState.peerCert
	if peerCrt != nil && curCrtVersion < peerCrt.Certificate.Version() {
		// if our certificate version is less than theirs, and we have a matching version available, rehandshake?
		if cs.getCertificate(peerCrt.Certificate.Version()) != nil {
			cm.l.Info("Re-handshaking with remote",
				"vpnAddrs", hostinfo.vpnAddrs,
				"version", curCrtVersion,
				"peerVersion", peerCrt.Certificate.Version(),
				"reason", "local certificate version lower than peer, attempting to correct",
			)
			cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], func(hh *HandshakeHostInfo) {
				hh.initiatingVersionOverride = peerCrt.Certificate.Version()
			})
			return
		}
	}
	if !bytes.Equal(curCrt.Signature(), myCrt.Signature()) {
		cm.l.Info("Re-handshaking with remote",
			"vpnAddrs", hostinfo.vpnAddrs,
			"reason", "local certificate is not current",
		)

		cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
		return
	}
	if curCrtVersion < cs.initiatingVersion {
		cm.l.Info("Re-handshaking with remote",
			"vpnAddrs", hostinfo.vpnAddrs,
			"reason", "current cert version < pki.initiatingVersion",
		)

		cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
		return
	}

	// PQ policy check: ask the active policy whether the peer's current
	// state is acceptable. This is opportunistic encryption and must
	// stay backwards compatible, so PSK loss is handled per the
	// degradation principle:
	//
	//   - ModeOpportunistic: never returns an error. If a peer's PSK
	//     disappears we degrade DOWN to IXPSK0 (re-handshake without the
	//     PSK) and KEEP the tunnel — loudly (Warn + metric). We never
	//     tear an opportunistic tunnel down on PSK loss.
	//   - ModeRequired: the policy returns ErrPolicyDenied when the PSK
	//     is absent. Tearing down is the operator's explicit choice, but
	//     we gate it behind pqRequiredCloseThreshold consecutive misses
	//     so a transient provider blip (one missed rescan) can't blackout
	//     a working tunnel. On the actual close we emit a Warn + bump the
	//     pq.tunnel_closed_policy metric.
	if peerCrt != nil {
		pi := pq.PeerInfo{
			StaticPubKey: peerCrt.Certificate.PublicKey(),
			Fingerprint:  peerCrt.Fingerprint,
			Groups:       peerCrt.Certificate.Groups(),
		}
		desired, err := cm.intf.pki.PQPolicy().InitiatorSubtype(pi)
		if err != nil {
			// Required/enforce mode with the PSK absent. Hysteresis-gate
			// the teardown: only close once the policy has refused on
			// pqRequiredCloseThreshold consecutive checks.
			hostinfo.pqPolicyMisses++
			if hostinfo.pqPolicyMisses < pqRequiredCloseThreshold {
				cm.l.Warn("PQ policy refuses re-handshake (required mode, PSK absent); holding tunnel pending hysteresis",
					"vpnAddrs", hostinfo.vpnAddrs,
					"error", err,
					"consecutiveMisses", hostinfo.pqPolicyMisses,
					"closeThreshold", pqRequiredCloseThreshold,
				)
				return
			}
			cm.l.Warn("Closing tunnel (PQ policy refuses re-handshake, required mode, PSK absent past hysteresis)",
				"vpnAddrs", hostinfo.vpnAddrs,
				"error", err,
				"consecutiveMisses", hostinfo.pqPolicyMisses,
			)
			metrics.GetOrRegisterCounter(metricPQTunnelClosedPolicy, nil).Inc(1)
			cm.intf.sendCloseTunnel(hostinfo)
			cm.intf.closeTunnel(hostinfo)
			return
		}
		// Policy is satisfied (or opportunistically tolerant): clear any
		// accrued required-mode miss count.
		hostinfo.pqPolicyMisses = 0

		current := pq.SubtypeNoPSK
		if hostinfo.ConnectionState.subtype == header.HandshakeIXPSK2 {
			current = pq.SubtypePerPeer
		}
		if desired == pq.SubtypePerPeer && current != pq.SubtypePerPeer {
			cm.l.Info("Re-handshaking with remote",
				"vpnAddrs", hostinfo.vpnAddrs,
				"reason", "upgrading to IXPSK2 (PQ policy)",
			)
			cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
			return
		}
		if desired == pq.SubtypeNoPSK && current == pq.SubtypePerPeer {
			// Opportunistic PSK loss: the peer's PSK disappeared while we
			// were running IXPSK2. DEGRADE to IXPSK0 by re-handshaking
			// without the PSK — keep connectivity rather than tearing the
			// tunnel down or running indefinitely on now-orphaned IXPSK2
			// keys. Surfaced loudly so the downgrade is observable.
			cm.l.Warn("Re-handshaking with remote (degrading IXPSK2 -> IXPSK0)",
				"vpnAddrs", hostinfo.vpnAddrs,
				"reason", "PQ PSK no longer available for peer; opportunistic downgrade",
			)
			cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
			return
		}
	}
}
