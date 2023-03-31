package nebula

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
)

type connectionManager struct {
	in     map[uint32]struct{}
	inLock *sync.RWMutex

	out     map[uint32]struct{}
	outLock *sync.RWMutex

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
	n.Out(localIndex)
	n.trafficTimer.Add(localIndex, n.checkInterval)
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
	var unlockOnce sync.Once
	n.hostMap.RLock()
	//TODO: we can release the read lock sooner but would need to reorganize the code a bit to make it less difficult to understand
	defer unlockOnce.Do(n.hostMap.RUnlock)

	hostinfo := n.hostMap.Indexes[localIndex]
	if hostinfo == nil {
		n.l.WithField("localIndex", localIndex).Debugf("Not found in hostmap")
		delete(n.pendingDeletion, localIndex)
		return
	}

	if n.handleInvalidCertificate(now, hostinfo) {
		return
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
		if n.l.Level >= logrus.DebugLevel {
			hostinfo.logger(n.l).
				WithField("tunnelCheck", m{"state": "alive", "method": "passive"}).
				Debug("Tunnel status")
		}
		delete(n.pendingDeletion, hostinfo.localIndexId)

		if mainHostInfo {
			n.handleRehandshake(hostinfo)
		} else {
			n.handleMakePrimary(hostinfo, primary)
		}

		n.trafficTimer.Add(hostinfo.localIndexId, n.checkInterval)

		if !outTraffic {
			// Send a punch packet to keep the NAT state alive
			n.sendPunch(hostinfo)
		}

		return
	}

	if _, ok := n.pendingDeletion[hostinfo.localIndexId]; ok {
		// We have already sent a test packet and nothing was returned, this hostinfo is dead
		hostinfo.logger(n.l).
			WithField("tunnelCheck", m{"state": "dead", "method": "active"}).
			Info("Tunnel status")

		unlockOnce.Do(n.hostMap.RUnlock)
		n.hostMap.DeleteHostInfo(hostinfo)
		delete(n.pendingDeletion, hostinfo.localIndexId)
		return
	}

	hostinfo.logger(n.l).
		WithField("tunnelCheck", m{"state": "testing", "method": "active"}).
		Debug("Tunnel status")

	if hostinfo != nil && hostinfo.ConnectionState != nil && mainHostInfo {
		if !outTraffic {
			// If we aren't sending or receiving traffic then its an unused tunnel and we don't to test the tunnel.
			// Just maintain NAT state if configured to do so.
			n.sendPunch(hostinfo)
			n.trafficTimer.Add(hostinfo.localIndexId, n.checkInterval)
			return

		}

		if n.punchy.GetTargetEverything() {
			// This is similar to the old punchy behavior with a slight optimization.
			// We aren't receiving traffic but we are sending it, punch on all known
			// ips in case we need to re-prime NAT state
			n.sendPunch(hostinfo)
		}

		if n.intf.lightHouse.IsLighthouseIP(hostinfo.vpnIp) {
			// We are sending traffic to the lighthouse, let recv_error sort out any issues instead of testing the tunnel
			n.trafficTimer.Add(hostinfo.localIndexId, n.checkInterval)
			return
		}

		// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
		n.intf.sendMessageToVpnIp(header.Test, header.TestRequest, hostinfo, p, nb, out)

	} else {
		hostinfo.logger(n.l).Debugf("Hostinfo sadness")
	}

	n.pendingDeletion[hostinfo.localIndexId] = struct{}{}
	n.trafficTimer.Add(hostinfo.localIndexId, n.pendingDeletionInterval)
}

func (n *connectionManager) handleMakePrimary(current, primary *HostInfo) {
	// The primary tunnel is the most recent handshake to complete locally and should work entirely fine.
	// If we are here then we have multiple tunnels for a host pair and neither side believes the same tunnel is primary.
	// Let's sort this out.

	if current.vpnIp < n.intf.myVpnIp {
		// Only one side should flip primary because if both flip then we may never resolve to a single tunnel.
		// vpn ip is static across all tunnels for this host pair so lets use that to determine who is flipping.
		// The remotes vpn ip is lower than mine. I will not flip.
		return
	}

	certState := n.intf.certState.Load()
	if !bytes.Equal(current.ConnectionState.certState.certificate.Signature, certState.certificate.Signature) {
		// The current hostinfo is not using the latest local cert, no point in trying to promote it
		return
	}

	n.hostMap.RUnlock()
	n.hostMap.Lock()
	// Make sure the primary is still the same after the write lock. This avoids a race with a rehandshake.
	if n.hostMap.Hosts[current.vpnIp] == primary {
		n.hostMap.unlockedMakePrimary(current)
	}
	n.hostMap.Unlock()
	n.hostMap.RLock()
}

// handleInvalidCertificates will destroy a tunnel if pki.disconnect_invalid is true and the certificate is no longer valid
func (n *connectionManager) handleInvalidCertificate(now time.Time, hostinfo *HostInfo) bool {
	if !n.intf.disconnectInvalid {
		return false
	}

	remoteCert := hostinfo.GetCert()
	if remoteCert == nil {
		return false
	}

	valid, err := remoteCert.Verify(now, n.intf.caPool)
	if valid {
		return false
	}

	fingerprint, _ := remoteCert.Sha256Sum()
	hostinfo.logger(n.l).WithError(err).
		WithField("fingerprint", fingerprint).
		Info("Remote certificate is no longer valid, tearing down the tunnel")

	// Inform the remote and close the tunnel locally
	n.intf.sendCloseTunnel(hostinfo)
	n.intf.closeTunnel(hostinfo)
	delete(n.pendingDeletion, hostinfo.localIndexId)
	return true
}

func (n *connectionManager) sendPunch(hostinfo *HostInfo) {
	if !n.punchy.GetPunch() {
		// Punching is disabled
		return
	}

	if n.punchy.GetTargetEverything() {
		hostinfo.remotes.ForEach(n.hostMap.preferredRanges, func(addr *udp.Addr, preferred bool) {
			n.metricsTxPunchy.Inc(1)
			n.intf.outside.WriteTo([]byte{1}, addr)
		})

	} else if hostinfo.remote != nil {
		n.metricsTxPunchy.Inc(1)
		n.intf.outside.WriteTo([]byte{1}, hostinfo.remote)
	}
}

func (n *connectionManager) handleRehandshake(hostinfo *HostInfo) {
	certState := n.intf.certState.Load()
	if bytes.Equal(hostinfo.ConnectionState.certState.certificate.Signature, certState.certificate.Signature) {
		return
	}

	n.l.WithField("vpnIp", hostinfo.vpnIp).
		WithField("reason", "local certificate is not current").
		Info("Re-handshaking with remote")

	//TODO: this is copied from getOrHandshake to keep the extra checks out of the hot path, figure it out
	newHostinfo := n.intf.handshakeManager.AddVpnIp(hostinfo.vpnIp, n.intf.initHostInfo)
	if !newHostinfo.HandshakeReady {
		ixHandshakeStage0(n.intf, newHostinfo.vpnIp, newHostinfo)
	}

	//If this is a static host, we don't need to wait for the HostQueryReply
	//We can trigger the handshake right now
	if _, ok := n.intf.lightHouse.GetStaticHostList()[hostinfo.vpnIp]; ok {
		select {
		case n.intf.handshakeManager.trigger <- hostinfo.vpnIp:
		default:
		}
	}
}
