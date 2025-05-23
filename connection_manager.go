package nebula

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
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

	metricsTxPunchy metrics.Counter

	l *logrus.Logger
}

func newConnectionManagerFromConfig(l *logrus.Logger, c *config.C, hm *HostMap, p *Punchy) *connectionManager {
	cm := &connectionManager{
		hostMap:         hm,
		l:               l,
		punchy:          p,
		relayUsed:       make(map[uint32]struct{}),
		relayUsedLock:   &sync.RWMutex{},
		metricsTxPunchy: metrics.GetOrRegisterCounter("messages.tx.punchy", nil),
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
			cm.l.WithField("oldDuration", old).
				WithField("newDuration", cm.getInactivityTimeout()).
				Info("Inactivity timeout has changed")
		}
	}

	if initial || c.HasChanged("tunnels.drop_inactive") {
		old := cm.dropInactive.Load()
		cm.dropInactive.Store(c.GetBool("tunnels.drop_inactive", false))
		if !initial {
			cm.l.WithField("oldBool", old).
				WithField("newBool", cm.dropInactive.Load()).
				Info("Drop inactive setting has changed")
		}
	}
}

func (cm *connectionManager) getInactivityTimeout() time.Duration {
	return (time.Duration)(cm.inactivityTimeout.Load())
}

func (cm *connectionManager) In(h *HostInfo) {
	if h.in.Swap(true) == false {
		cm.updateLastCommunication(h)
	}
}

func (cm *connectionManager) Out(h *HostInfo) {
	if h.out.Swap(true) == false {
		cm.updateLastCommunication(h)
	}
}

func (cm *connectionManager) updateLastCommunication(h *HostInfo) {
	now := time.Now()
	h.lastComms.Store(&now)
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
func (cm *connectionManager) getAndResetTrafficCheck(h *HostInfo) (bool, bool) {
	in := h.in.Swap(false)
	out := h.out.Swap(false)
	return in, out
}

// AddTrafficWatch must be called for every new HostInfo.
// We will continue to monitor the HostInfo until the tunnel is dropped.
func (cm *connectionManager) AddTrafficWatch(h *HostInfo) {
	if h.out.Swap(true) == false {
		cm.trafficTimer.Add(h.localIndexId, cm.checkInterval)
	}
}

func (cm *connectionManager) Start(ctx context.Context) {
	clockSource := time.NewTicker(cm.trafficTimer.t.tickDuration)
	defer clockSource.Stop()

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
		}
	}
}

func (cm *connectionManager) doTrafficCheck(localIndex uint32, p, nb, out []byte, now time.Time) {
	decision, hostinfo, primary := cm.makeTrafficDecision(localIndex, now)

	switch decision {
	case deleteTunnel:
		if cm.hostMap.DeleteHostInfo(hostinfo) {
			// Only clearing the lighthouse cache if this is the last hostinfo for this vpn ip in the hostmap
			cm.intf.lightHouse.DeleteVpnIp(hostinfo.vpnIp)
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
		existing, ok := newhostinfo.relayState.QueryRelayForByIp(r.PeerIp)

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
				// The relayed connection exists in a Requested state; re-send the request
				index = existing.LocalIndex
				switch r.Type {
				case TerminalType:
					relayFrom = cm.intf.myVpnNet.Addr()
					relayTo = existing.PeerIp
				case ForwardingType:
					relayFrom = existing.PeerIp
					relayTo = newhostinfo.vpnIp
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
			index, err = AddRelay(cm.l, newhostinfo, cm.hostMap, r.PeerIp, nil, r.Type, Requested)
			if err != nil {
				cm.l.WithError(err).Error("failed to migrate relay to new hostinfo")
				continue
			}
			switch r.Type {
			case TerminalType:
				relayFrom = cm.intf.myVpnNet.Addr()
				relayTo = r.PeerIp
			case ForwardingType:
				relayFrom = r.PeerIp
				relayTo = newhostinfo.vpnIp
			default:
				// should never happen
				panic(fmt.Sprintf("Migrating unknown relay type: %v", r.Type))
			}
		}

		//TODO: IPV6-WORK
		relayFromB := relayFrom.As4()
		relayToB := relayTo.As4()

		// Send a CreateRelayRequest to the peer.
		req := NebulaControl{
			Type:                NebulaControl_CreateRelayRequest,
			InitiatorRelayIndex: index,
			RelayFromIp:         binary.BigEndian.Uint32(relayFromB[:]),
			RelayToIp:           binary.BigEndian.Uint32(relayToB[:]),
		}
		msg, err := req.Marshal()
		if err != nil {
			cm.l.WithError(err).Error("failed to marshal Control message to migrate relay")
		} else {
			cm.intf.SendMessageToHostInfo(header.Control, 0, newhostinfo, msg, make([]byte, 12), make([]byte, mtu))
			cm.l.WithFields(logrus.Fields{
				"relayFrom":           req.RelayFromIp,
				"relayTo":             req.RelayToIp,
				"initiatorRelayIndex": req.InitiatorRelayIndex,
				"responderRelayIndex": req.ResponderRelayIndex,
				"vpnIp":               newhostinfo.vpnIp}).
				Info("send CreateRelayRequest")
		}
	}
}

func (cm *connectionManager) makeTrafficDecision(localIndex uint32, now time.Time) (trafficDecision, *HostInfo, *HostInfo) {
	// Read lock the main hostmap to order decisions based on tunnels being the primary tunnel
	cm.hostMap.RLock()
	defer cm.hostMap.RUnlock()

	hostinfo := cm.hostMap.Indexes[localIndex]
	if hostinfo == nil {
		cm.l.WithField("localIndex", localIndex).Debugln("Not found in hostmap")
		return doNothing, nil, nil
	}

	if cm.isInvalidCertificate(now, hostinfo) {
		return closeTunnel, hostinfo, nil
	}

	primary := cm.hostMap.Hosts[hostinfo.vpnIp]
	mainHostInfo := true
	if primary != nil && primary != hostinfo {
		mainHostInfo = false
	}

	// Check for traffic on this hostinfo
	inTraffic, outTraffic := cm.getAndResetTrafficCheck(hostinfo)

	// A hostinfo is determined alive if there is incoming traffic
	if inTraffic {
		decision := doNothing
		if cm.l.Level >= logrus.DebugLevel {
			hostinfo.logger(cm.l).
				WithField("tunnelCheck", m{"state": "alive", "method": "passive"}).
				Debug("Tunnel status")
		}
		hostinfo.pendingDeletion.Store(false)

		if mainHostInfo {
			decision = tryRehandshake

		} else {
			if cm.shouldSwapPrimary(hostinfo, primary) {
				decision = swapPrimary
			} else {
				// migrate the relays to the primary, if in use.
				decision = migrateRelays
			}
		}

		cm.trafficTimer.Add(hostinfo.localIndexId, cm.checkInterval)

		if !outTraffic {
			// Send a punch packet to keep the NAT state alive
			cm.sendPunch(hostinfo)
		}

		return decision, hostinfo, primary
	}

	if hostinfo.pendingDeletion.Load() {
		// We have already sent a test packet and nothing was returned, this hostinfo is dead
		hostinfo.logger(cm.l).
			WithField("tunnelCheck", m{"state": "dead", "method": "active"}).
			Info("Tunnel status")

		return deleteTunnel, hostinfo, nil
	}

	decision := doNothing
	if hostinfo != nil && hostinfo.ConnectionState != nil && mainHostInfo {
		if !outTraffic {
			inactiveFor, isInactive := cm.isInactive(hostinfo, now)
			if isInactive {
				// Tunnel is inactive, tear it down
				hostinfo.logger(cm.l).
					WithField("inactiveDuration", inactiveFor).
					WithField("primary", mainHostInfo).
					Info("Dropping tunnel due to inactivity")

				return closeTunnel, hostinfo, primary
			}

			// If we aren't sending or receiving traffic then its an unused tunnel and we don't to test the tunnel.
			// Just maintain NAT state if configured to do so.
			cm.sendPunch(hostinfo)
			cm.trafficTimer.Add(hostinfo.localIndexId, cm.checkInterval)
			return doNothing, nil, nil
		}

		if cm.punchy.GetTargetEverything() {
			// This is similar to the old punchy behavior with a slight optimization.
			// We aren't receiving traffic but we are sending it, punch on all known
			// ips in case we need to re-prime NAT state
			cm.sendPunch(hostinfo)
		}

		if cm.l.Level >= logrus.DebugLevel {
			hostinfo.logger(cm.l).
				WithField("tunnelCheck", m{"state": "testing", "method": "active"}).
				Debug("Tunnel status")
		}

		// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
		decision = sendTestPacket

	} else {
		if cm.l.Level >= logrus.DebugLevel {
			hostinfo.logger(cm.l).Debugf("Hostinfo sadness")
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

	lastComm := hostinfo.lastComms.Load()
	if lastComm == nil {
		// Strangely we don't have any last communication time recorded
		return 0, false
	}

	inactiveDuration := now.Sub(*lastComm)
	if inactiveDuration < cm.getInactivityTimeout() {
		// It's not considered inactive
		return inactiveDuration, false
	}

	// The tunnel is inactive
	return inactiveDuration, true
}

func (cm *connectionManager) shouldSwapPrimary(current, primary *HostInfo) bool {
	// The primary tunnel is the most recent handshake to complete locally and should work entirely fine.
	// If we are here then we have multiple tunnels for a host pair and neither side believes the same tunnel is primary.
	// Let's sort this out.

	if current.vpnIp.Compare(cm.intf.myVpnNet.Addr()) < 0 {
		// Only one side should flip primary because if both flip then we may never resolve to a single tunnel.
		// vpn ip is static across all tunnels for this host pair so lets use that to determine who is flipping.
		// The remotes vpn ip is lower than mine. I will not flip.
		return false
	}

	certState := cm.intf.pki.GetCertState()
	return bytes.Equal(current.ConnectionState.myCert.Signature, certState.Certificate.Signature)
}

func (cm *connectionManager) swapPrimary(current, primary *HostInfo) {
	cm.hostMap.Lock()
	// Make sure the primary is still the same after the write lock. This avoids a race with a rehandshake.
	if cm.hostMap.Hosts[current.vpnIp] == primary {
		cm.hostMap.unlockedMakePrimary(current)
	}
	cm.hostMap.Unlock()
}

// isInvalidCertificate will check if we should destroy a tunnel if pki.disconnect_invalid is true and
// the certificate is no longer valid. Block listed certificates will skip the pki.disconnect_invalid
// check and return true.
func (cm *connectionManager) isInvalidCertificate(now time.Time, hostinfo *HostInfo) bool {
	remoteCert := hostinfo.GetCert()
	if remoteCert == nil {
		return false
	}

	valid, err := remoteCert.VerifyWithCache(now, cm.intf.pki.GetCAPool())
	if valid {
		return false
	}

	if !cm.intf.disconnectInvalid.Load() && err != cert.ErrBlockListed {
		// Block listed certificates should always be disconnected
		return false
	}

	fingerprint, _ := remoteCert.Sha256Sum()
	hostinfo.logger(cm.l).WithError(err).
		WithField("fingerprint", fingerprint).
		Info("Remote certificate is no longer valid, tearing down the tunnel")

	return true
}

func (cm *connectionManager) sendPunch(hostinfo *HostInfo) {
	if !cm.punchy.GetPunch() {
		// Punching is disabled
		return
	}

	if cm.intf.lightHouse.IsLighthouseIP(hostinfo.vpnIp) {
		// Do not punch to lighthouses, we assume our lighthouse update interval is good enough.
		// In the event the update interval is not sufficient to maintain NAT state then a publicly available lighthouse
		// would lose the ability to notify us and punchy.respond would become unreliable.
		return
	}

	if cm.punchy.GetTargetEverything() {
		hostinfo.remotes.ForEach(cm.hostMap.GetPreferredRanges(), func(addr netip.AddrPort, preferred bool) {
			cm.metricsTxPunchy.Inc(1)
			cm.intf.outside.WriteTo([]byte{1}, addr)
		})

	} else if hostinfo.remote.IsValid() {
		cm.metricsTxPunchy.Inc(1)
		cm.intf.outside.WriteTo([]byte{1}, hostinfo.remote)
	}
}

func (cm *connectionManager) tryRehandshake(hostinfo *HostInfo) {
	certState := cm.intf.pki.GetCertState()
	if bytes.Equal(hostinfo.ConnectionState.myCert.Signature, certState.Certificate.Signature) {
		return
	}

	cm.l.WithField("vpnIp", hostinfo.vpnIp).
		WithField("reason", "local certificate is not current").
		Info("Re-handshaking with remote")

	cm.intf.handshakeManager.StartHandshake(hostinfo.vpnIp, nil)
}
