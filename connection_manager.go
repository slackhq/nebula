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
	in     map[uint32]struct{}
	inLock *sync.RWMutex

	out     map[uint32]struct{}
	outLock *sync.RWMutex

	// relayUsed holds which relay localIndexs are in use
	relayUsed     map[uint32]struct{}
	relayUsedLock *sync.RWMutex

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
		trafficTimer:            NewLockingTimerWheel[uint32](time.Millisecond*500, max),
		intf:                    intf,
		pendingDeletion:         make(map[uint32]struct{}),
		checkInterval:           checkInterval,
		pendingDeletionInterval: pendingDeletionInterval,
		punchy:                  punchy,
		metricsTxPunchy:         metrics.GetOrRegisterCounter("messages.tx.punchy", nil),
		l:                       l,
	}

	nc.Start(ctx)
	return nc
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

func (n *connectionManager) Start(ctx context.Context) {
	go n.Run(ctx)
}

func (n *connectionManager) Run(ctx context.Context) {
	//TODO: this tick should be based on the min wheel tick? Check firewall
	clockSource := time.NewTicker(500 * time.Millisecond)
	defer clockSource.Stop()

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
			n.sendPunch(hostinfo)
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
			n.sendPunch(hostinfo)
			n.trafficTimer.Add(hostinfo.localIndexId, n.checkInterval)
			return doNothing, nil, nil

		}

		if n.punchy.GetTargetEverything() {
			// This is similar to the old punchy behavior with a slight optimization.
			// We aren't receiving traffic but we are sending it, punch on all known
			// ips in case we need to re-prime NAT state
			n.sendPunch(hostinfo)
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
