package nebula

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
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

// LastCommunication tracks when we last communicated with a host
type LastCommunication struct {
	timestamp time.Time
	vpnIp     netip.Addr // To help with logging
}

type connectionManager struct {
	in     map[uint32]struct{}
	inLock *sync.RWMutex

	out     map[uint32]struct{}
	outLock *sync.RWMutex

	// relayUsed holds which relay localIndexs are in use
	relayUsed     map[uint32]struct{}
	relayUsedLock *sync.RWMutex

	// Track last communication with hosts
	lastCommMap       map[uint32]*LastCommunication
	lastCommLock      *sync.RWMutex
	inactivityTimer   *LockingTimerWheel[uint32]
	inactivityTimeout time.Duration

	hostMap                 *HostMap
	trafficTimer            *LockingTimerWheel[uint32]
	intf                    *Interface
	pendingDeletion         map[uint32]struct{}
	punchy                  *Punchy
	checkInterval           time.Duration
	pendingDeletionInterval time.Duration
	metricsTxPunchy         metrics.Counter

	l *logrus.Logger
}

func newConnectionManager(ctx context.Context, l *logrus.Logger, intf *Interface, checkInterval, pendingDeletionInterval time.Duration, punchy *Punchy) *connectionManager {
	var max time.Duration
	if checkInterval < pendingDeletionInterval {
		max = pendingDeletionInterval
	} else {
		max = checkInterval
	}

	nc := &connectionManager{
		hostMap:                 intf.hostMap,
		in:                      make(map[uint32]struct{}),
		inLock:                  &sync.RWMutex{},
		out:                     make(map[uint32]struct{}),
		outLock:                 &sync.RWMutex{},
		relayUsed:               make(map[uint32]struct{}),
		relayUsedLock:           &sync.RWMutex{},
		lastCommMap:             make(map[uint32]*LastCommunication),
		lastCommLock:            &sync.RWMutex{},
		inactivityTimeout:       1 * time.Minute, // Default inactivity timeout: 10 minutes
		trafficTimer:            NewLockingTimerWheel[uint32](time.Millisecond*500, max),
		intf:                    intf,
		pendingDeletion:         make(map[uint32]struct{}),
		checkInterval:           checkInterval,
		pendingDeletionInterval: pendingDeletionInterval,
		punchy:                  punchy,
		metricsTxPunchy:         metrics.GetOrRegisterCounter("messages.tx.punchy", nil),
		l:                       l,
	}

	// Initialize the inactivity timer wheel - make wheel duration slightly longer than the timeout
	nc.inactivityTimer = NewLockingTimerWheel[uint32](time.Minute, nc.inactivityTimeout+time.Minute)

	nc.Start(ctx)
	return nc
}

func (n *connectionManager) updateLastCommunication(localIndex uint32) {
	// Get host info to record VPN IP for better logging
	hostInfo := n.hostMap.QueryIndex(localIndex)
	if hostInfo == nil {
		return
	}

	now := time.Now()
	n.lastCommLock.Lock()
	lastComm, exists := n.lastCommMap[localIndex]
	if !exists {
		// First time we've seen this host
		lastComm = &LastCommunication{
			timestamp: now,
			vpnIp:     hostInfo.vpnIp,
		}
		n.lastCommMap[localIndex] = lastComm
	} else {
		// Update existing record
		lastComm.timestamp = now
	}
	n.lastCommLock.Unlock()

	// Reset the inactivity timer for this host
	n.inactivityTimer.m.Lock()
	n.inactivityTimer.t.Add(localIndex, n.inactivityTimeout)
	n.inactivityTimer.m.Unlock()
}

func (n *connectionManager) In(localIndex uint32) {
	n.inLock.RLock()
	// If this already exists, return
	if _, ok := n.in[localIndex]; ok {
		n.inLock.RUnlock()
		return
	}
	n.inLock.RUnlock()
	n.inLock.Lock()
	n.in[localIndex] = struct{}{}
	n.inLock.Unlock()

	// Update last communication time
	n.updateLastCommunication(localIndex)
}

func (n *connectionManager) Out(localIndex uint32) {
	n.outLock.RLock()
	// If this already exists, return
	if _, ok := n.out[localIndex]; ok {
		n.outLock.RUnlock()
		return
	}
	n.outLock.RUnlock()
	n.outLock.Lock()
	n.out[localIndex] = struct{}{}
	n.outLock.Unlock()

	// Update last communication time
	n.updateLastCommunication(localIndex)
}

func (n *connectionManager) RelayUsed(localIndex uint32) {
	n.relayUsedLock.RLock()
	// If this already exists, return
	if _, ok := n.relayUsed[localIndex]; ok {
		n.relayUsedLock.RUnlock()
		return
	}
	n.relayUsedLock.RUnlock()
	n.relayUsedLock.Lock()
	n.relayUsed[localIndex] = struct{}{}
	n.relayUsedLock.Unlock()
}

// getAndResetTrafficCheck returns if there was any inbound or outbound traffic within the last tick and
// resets the state for this local index
func (n *connectionManager) getAndResetTrafficCheck(localIndex uint32) (bool, bool) {
	n.inLock.Lock()
	n.outLock.Lock()
	_, in := n.in[localIndex]
	_, out := n.out[localIndex]
	delete(n.in, localIndex)
	delete(n.out, localIndex)
	n.inLock.Unlock()
	n.outLock.Unlock()
	return in, out
}

func (n *connectionManager) AddTrafficWatch(localIndex uint32) {
	// Use a write lock directly because it should be incredibly rare that we are ever already tracking this index
	n.outLock.Lock()
	if _, ok := n.out[localIndex]; ok {
		n.outLock.Unlock()
		return
	}
	n.out[localIndex] = struct{}{}
	n.trafficTimer.Add(localIndex, n.checkInterval)
	n.outLock.Unlock()
}

// checkInactiveTunnels checks for tunnels that have been inactive for too long and drops them
func (n *connectionManager) checkInactiveTunnels() {
	now := time.Now()

	// First, advance the timer wheel to the current time
	n.inactivityTimer.m.Lock()
	n.inactivityTimer.t.Advance(now)
	n.inactivityTimer.m.Unlock()

	// Check for expired timers (inactive connections)
	for {
		// Get the next expired tunnel
		n.inactivityTimer.m.Lock()
		localIndex, ok := n.inactivityTimer.t.Purge()
		n.inactivityTimer.m.Unlock()

		if !ok {
			// No more expired timers
			break
		}

		n.lastCommLock.RLock()
		lastComm, exists := n.lastCommMap[localIndex]
		n.lastCommLock.RUnlock()

		if !exists {
			// No last communication record, odd but skip
			continue
		}

		// Calculate inactivity duration
		inactiveDuration := now.Sub(lastComm.timestamp)

		// Check if we've exceeded the inactivity timeout
		if inactiveDuration >= n.inactivityTimeout {
			// Get the host info (if it still exists)
			hostInfo := n.hostMap.QueryIndex(localIndex)
			if hostInfo == nil {
				// Host info is gone, remove from our tracking map
				n.lastCommLock.Lock()
				delete(n.lastCommMap, localIndex)
				n.lastCommLock.Unlock()
				continue
			}

			// Log the inactivity and drop the tunnel
			n.l.WithField("vpnIp", lastComm.vpnIp).
				WithField("localIndex", localIndex).
				WithField("inactiveDuration", inactiveDuration).
				WithField("timeout", n.inactivityTimeout).
				Info("Dropping tunnel due to inactivity")

			// Close the tunnel using the existing mechanism
			n.intf.closeTunnel(hostInfo)

			// Clean up our tracking map
			n.lastCommLock.Lock()
			delete(n.lastCommMap, localIndex)
			n.lastCommLock.Unlock()
		} else {
			// Re-add to the timer wheel with the remaining time
			remainingTime := n.inactivityTimeout - inactiveDuration
			n.inactivityTimer.m.Lock()
			n.inactivityTimer.t.Add(localIndex, remainingTime)
			n.inactivityTimer.m.Unlock()
		}
	}
}

// CleanupDeletedHostInfos removes entries from our lastCommMap for hosts that no longer exist
func (n *connectionManager) CleanupDeletedHostInfos() {
	n.lastCommLock.Lock()
	defer n.lastCommLock.Unlock()

	// Find indexes to delete
	var toDelete []uint32
	for localIndex := range n.lastCommMap {
		if n.hostMap.QueryIndex(localIndex) == nil {
			toDelete = append(toDelete, localIndex)
		}
	}

	// Delete them
	for _, localIndex := range toDelete {
		delete(n.lastCommMap, localIndex)
	}

	if len(toDelete) > 0 && n.l.Level >= logrus.DebugLevel {
		n.l.WithField("count", len(toDelete)).Debug("Cleaned up deleted host entries from lastCommMap")
	}
}

// ReloadConfig updates the connection manager configuration
func (n *connectionManager) ReloadConfig(c *config.C) {
	// Get the inactivity timeout from config
	inactivityTimeout := c.GetDuration("timers.inactivity_timeout", 10*time.Minute)

	// Only update if different
	if inactivityTimeout != n.inactivityTimeout {
		n.l.WithField("old", n.inactivityTimeout).
			WithField("new", inactivityTimeout).
			Info("Updating inactivity timeout")

		n.inactivityTimeout = inactivityTimeout

		// Recreate the inactivity timer wheel with the new timeout
		n.inactivityTimer = NewLockingTimerWheel[uint32](time.Minute, n.inactivityTimeout+time.Minute)

		// Re-add all existing hosts to the new timer wheel
		n.lastCommLock.RLock()
		for localIndex, lastComm := range n.lastCommMap {
			// Calculate remaining time based on last communication
			now := time.Now()
			elapsed := now.Sub(lastComm.timestamp)

			// If the elapsed time exceeds the new timeout, this will be caught
			// in the next inactivity check. Otherwise, add with remaining time.
			if elapsed < n.inactivityTimeout {
				remainingTime := n.inactivityTimeout - elapsed
				n.inactivityTimer.m.Lock()
				n.inactivityTimer.t.Add(localIndex, remainingTime)
				n.inactivityTimer.m.Unlock()
			}
		}
		n.lastCommLock.RUnlock()
	}
}

func (n *connectionManager) Start(ctx context.Context) {
	go n.Run(ctx)
}

func (n *connectionManager) Run(ctx context.Context) {
	//TODO: this tick should be based on the min wheel tick? Check firewall
	clockSource := time.NewTicker(500 * time.Millisecond)
	defer clockSource.Stop()

	// Create ticker for inactivity checks (every minute)
	inactivityTicker := time.NewTicker(time.Minute)
	defer inactivityTicker.Stop()

	// Create ticker for cleanup (every 5 minutes)
	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()

	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	for {
		select {
		case <-ctx.Done():
			return

		case now := <-clockSource.C:
			n.trafficTimer.Advance(now)
			for {
				localIndex, has := n.trafficTimer.Purge()
				if !has {
					break
				}

				n.doTrafficCheck(localIndex, p, nb, out, now)
			}

		case <-inactivityTicker.C:
			// Check for inactive tunnels
			n.checkInactiveTunnels()

		case <-cleanupTicker.C:
			// Periodically clean up deleted hosts
			n.CleanupDeletedHostInfos()
		}
	}
}

func (n *connectionManager) doTrafficCheck(localIndex uint32, p, nb, out []byte, now time.Time) {
	decision, hostinfo, primary := n.makeTrafficDecision(localIndex, now)

	switch decision {
	case deleteTunnel:
		if n.hostMap.DeleteHostInfo(hostinfo) {
			// Only clearing the lighthouse cache if this is the last hostinfo for this vpn ip in the hostmap
			n.intf.lightHouse.DeleteVpnIp(hostinfo.vpnIp)
		}

	case closeTunnel:
		n.intf.sendCloseTunnel(hostinfo)
		n.intf.closeTunnel(hostinfo)

	case swapPrimary:
		n.swapPrimary(hostinfo, primary)

	case migrateRelays:
		n.migrateRelayUsed(hostinfo, primary)

	case tryRehandshake:
		n.tryRehandshake(hostinfo)

	case sendTestPacket:
		n.intf.SendMessageToHostInfo(header.Test, header.TestRequest, hostinfo, p, nb, out)
	}

	n.resetRelayTrafficCheck(hostinfo)
}

func (n *connectionManager) resetRelayTrafficCheck(hostinfo *HostInfo) {
	if hostinfo != nil {
		n.relayUsedLock.Lock()
		defer n.relayUsedLock.Unlock()
		// No need to migrate any relays, delete usage info now.
		for _, idx := range hostinfo.relayState.CopyRelayForIdxs() {
			delete(n.relayUsed, idx)
		}
	}
}

func (n *connectionManager) migrateRelayUsed(oldhostinfo, newhostinfo *HostInfo) {
	relayFor := oldhostinfo.relayState.CopyAllRelayFor()

	for _, r := range relayFor {
		existing, ok := newhostinfo.relayState.QueryRelayForByIp(r.PeerIp)

		var index uint32
		var relayFrom netip.Addr
		var relayTo netip.Addr
		switch {
		case ok && existing.State == Established:
			// This relay already exists in newhostinfo, then do nothing.
			continue
		case ok && existing.State == Requested:
			// The relay exists in a Requested state; re-send the request
			index = existing.LocalIndex
			switch r.Type {
			case TerminalType:
				relayFrom = n.intf.myVpnNet.Addr()
				relayTo = existing.PeerIp
			case ForwardingType:
				relayFrom = existing.PeerIp
				relayTo = newhostinfo.vpnIp
			default:
				// should never happen
			}
		case !ok:
			n.relayUsedLock.RLock()
			if _, relayUsed := n.relayUsed[r.LocalIndex]; !relayUsed {
				// The relay hasn't been used; don't migrate it.
				n.relayUsedLock.RUnlock()
				continue
			}
			n.relayUsedLock.RUnlock()
			// The relay doesn't exist at all; create some relay state and send the request.
			var err error
			index, err = AddRelay(n.l, newhostinfo, n.hostMap, r.PeerIp, nil, r.Type, Requested)
			if err != nil {
				n.l.WithError(err).Error("failed to migrate relay to new hostinfo")
				continue
			}
			switch r.Type {
			case TerminalType:
				relayFrom = n.intf.myVpnNet.Addr()
				relayTo = r.PeerIp
			case ForwardingType:
				relayFrom = r.PeerIp
				relayTo = newhostinfo.vpnIp
			default:
				// should never happen
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
			n.l.WithError(err).Error("failed to marshal Control message to migrate relay")
		} else {
			n.intf.SendMessageToHostInfo(header.Control, 0, newhostinfo, msg, make([]byte, 12), make([]byte, mtu))
			n.l.WithFields(logrus.Fields{
				"relayFrom":           req.RelayFromIp,
				"relayTo":             req.RelayToIp,
				"initiatorRelayIndex": req.InitiatorRelayIndex,
				"responderRelayIndex": req.ResponderRelayIndex,
				"vpnIp":               newhostinfo.vpnIp}).
				Info("send CreateRelayRequest")
		}
	}
}

func (n *connectionManager) makeTrafficDecision(localIndex uint32, now time.Time) (trafficDecision, *HostInfo, *HostInfo) {
	n.hostMap.RLock()
	defer n.hostMap.RUnlock()

	hostinfo := n.hostMap.Indexes[localIndex]
	if hostinfo == nil {
		n.l.WithField("localIndex", localIndex).Debugf("Not found in hostmap")
		delete(n.pendingDeletion, localIndex)
		return doNothing, nil, nil
	}

	if n.isInvalidCertificate(now, hostinfo) {
		delete(n.pendingDeletion, hostinfo.localIndexId)
		return closeTunnel, hostinfo, nil
	}

	primary := n.hostMap.Hosts[hostinfo.vpnIp]
	mainHostInfo := true
	if primary != nil && primary != hostinfo {
		mainHostInfo = false
	}

	// Check for traffic on this hostinfo
	inTraffic, outTraffic := n.getAndResetTrafficCheck(localIndex)

	// A hostinfo is determined alive if there is incoming traffic
	if inTraffic {
		decision := doNothing
		if n.l.Level >= logrus.DebugLevel {
			hostinfo.logger(n.l).
				WithField("tunnelCheck", m{"state": "alive", "method": "passive"}).
				Debug("Tunnel status")
		}
		delete(n.pendingDeletion, hostinfo.localIndexId)

		if mainHostInfo {
			decision = tryRehandshake

		} else {
			if n.shouldSwapPrimary(hostinfo, primary) {
				decision = swapPrimary
			} else {
				// migrate the relays to the primary, if in use.
				decision = migrateRelays
			}
		}

		n.trafficTimer.Add(hostinfo.localIndexId, n.checkInterval)

		if !outTraffic {
			// Send a punch packet to keep the NAT state alive
			//n.sendPunch(hostinfo)
		}

		return decision, hostinfo, primary
	}

	if _, ok := n.pendingDeletion[hostinfo.localIndexId]; ok {
		// We have already sent a test packet and nothing was returned, this hostinfo is dead
		hostinfo.logger(n.l).
			WithField("tunnelCheck", m{"state": "dead", "method": "active"}).
			Info("Tunnel status")

		delete(n.pendingDeletion, hostinfo.localIndexId)
		return deleteTunnel, hostinfo, nil
	}

	decision := doNothing
	if hostinfo != nil && hostinfo.ConnectionState != nil && mainHostInfo {
		if !outTraffic {
			// If we aren't sending or receiving traffic then its an unused tunnel and we don't to test the tunnel.
			// Just maintain NAT state if configured to do so.
			//n.sendPunch(hostinfo)
			n.trafficTimer.Add(hostinfo.localIndexId, n.checkInterval)
			return doNothing, nil, nil

		}

		if n.punchy.GetTargetEverything() {
			// This is similar to the old punchy behavior with a slight optimization.
			// We aren't receiving traffic but we are sending it, punch on all known
			// ips in case we need to re-prime NAT state
			//n.sendPunch(hostinfo)
		}

		if n.l.Level >= logrus.DebugLevel {
			hostinfo.logger(n.l).
				WithField("tunnelCheck", m{"state": "testing", "method": "active"}).
				Debug("Tunnel status")
		}

		// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
		decision = sendTestPacket

	} else {
		if n.l.Level >= logrus.DebugLevel {
			hostinfo.logger(n.l).Debugf("Hostinfo sadness")
		}
	}

	n.pendingDeletion[hostinfo.localIndexId] = struct{}{}
	n.trafficTimer.Add(hostinfo.localIndexId, n.pendingDeletionInterval)
	return decision, hostinfo, nil
}

func (n *connectionManager) shouldSwapPrimary(current, primary *HostInfo) bool {
	// The primary tunnel is the most recent handshake to complete locally and should work entirely fine.
	// If we are here then we have multiple tunnels for a host pair and neither side believes the same tunnel is primary.
	// Let's sort this out.

	if current.vpnIp.Compare(n.intf.myVpnNet.Addr()) < 0 {
		// Only one side should flip primary because if both flip then we may never resolve to a single tunnel.
		// vpn ip is static across all tunnels for this host pair so lets use that to determine who is flipping.
		// The remotes vpn ip is lower than mine. I will not flip.
		return false
	}

	certState := n.intf.pki.GetCertState()
	return bytes.Equal(current.ConnectionState.myCert.Signature, certState.Certificate.Signature)
}

func (n *connectionManager) swapPrimary(current, primary *HostInfo) {
	n.hostMap.Lock()
	// Make sure the primary is still the same after the write lock. This avoids a race with a rehandshake.
	if n.hostMap.Hosts[current.vpnIp] == primary {
		n.hostMap.unlockedMakePrimary(current)
	}
	n.hostMap.Unlock()
}

// isInvalidCertificate will check if we should destroy a tunnel if pki.disconnect_invalid is true and
// the certificate is no longer valid. Block listed certificates will skip the pki.disconnect_invalid
// check and return true.
func (n *connectionManager) isInvalidCertificate(now time.Time, hostinfo *HostInfo) bool {
	remoteCert := hostinfo.GetCert()
	if remoteCert == nil {
		return false
	}

	valid, err := remoteCert.VerifyWithCache(now, n.intf.pki.GetCAPool())
	if valid {
		return false
	}

	if !n.intf.disconnectInvalid.Load() && err != cert.ErrBlockListed {
		// Block listed certificates should always be disconnected
		return false
	}

	fingerprint, _ := remoteCert.Sha256Sum()
	hostinfo.logger(n.l).WithError(err).
		WithField("fingerprint", fingerprint).
		Info("Remote certificate is no longer valid, tearing down the tunnel")

	return true
}

func (n *connectionManager) sendPunch(hostinfo *HostInfo) {
	if !n.punchy.GetPunch() {
		// Punching is disabled
		return
	}

	if n.punchy.GetTargetEverything() {
		hostinfo.remotes.ForEach(n.hostMap.GetPreferredRanges(), func(addr netip.AddrPort, preferred bool) {
			n.metricsTxPunchy.Inc(1)
			n.intf.outside.WriteTo([]byte{1}, addr)
		})

	} else if hostinfo.remote.IsValid() {
		n.metricsTxPunchy.Inc(1)
		n.intf.outside.WriteTo([]byte{1}, hostinfo.remote)
	}
}

func (n *connectionManager) tryRehandshake(hostinfo *HostInfo) {
	certState := n.intf.pki.GetCertState()
	if bytes.Equal(hostinfo.ConnectionState.myCert.Signature, certState.Certificate.Signature) {
		return
	}

	n.l.WithField("vpnIp", hostinfo.vpnIp).
		WithField("reason", "local certificate is not current").
		Info("Re-handshaking with remote")

	n.intf.handshakeManager.StartHandshake(hostinfo.vpnIp, nil)
}
