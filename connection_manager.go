package nebula

import (
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
	hostinfo, err := n.hostMap.QueryIndex(localIndex)
	if err != nil {
		n.l.WithField("localIndex", localIndex).Debugf("Not found in hostmap")
		delete(n.pendingDeletion, localIndex)
		return
	}

	if n.handleInvalidCertificate(now, hostinfo) {
		return
	}

	primary, _ := n.hostMap.QueryVpnIp(hostinfo.vpnIp)
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

		if !mainHostInfo {
			if hostinfo.vpnIp > n.intf.myVpnIp {
				// We are receiving traffic on the non primary hostinfo and we really just want 1 tunnel. Make
				// This the primary and prime the old primary hostinfo for testing
				n.hostMap.MakePrimary(hostinfo)
			}
		}

		n.trafficTimer.Add(hostinfo.localIndexId, n.checkInterval)

		if !outTraffic {
			// Send a punch packet to keep the NAT state alive
			n.sendPunch(hostinfo)
		}

		return
	}

	if n.intf.lightHouse.IsLighthouseIP(hostinfo.vpnIp) {
		// We are sending traffic to the lighthouse, let recv_error sort out any issues instead of testing the tunnel
		n.trafficTimer.Add(hostinfo.localIndexId, n.checkInterval)
		return
	}

	if _, ok := n.pendingDeletion[hostinfo.localIndexId]; ok {
		// We have already sent a test packet and nothing was returned, this hostinfo is dead
		hostinfo.logger(n.l).
			WithField("tunnelCheck", m{"state": "dead", "method": "active"}).
			Info("Tunnel status")

		n.hostMap.DeleteHostInfo(hostinfo)
		delete(n.pendingDeletion, hostinfo.localIndexId)
		return
	}

	hostinfo.logger(n.l).
		WithField("tunnelCheck", m{"state": "testing", "method": "active"}).
		Debug("Tunnel status")

	if hostinfo != nil && hostinfo.ConnectionState != nil && mainHostInfo {
		if n.punchy.GetTargetEverything() {
			// Maybe the remote is sending us packets but our NAT is blocking it and since we are configured to punch to all
			// known remotes, go ahead and do that AND send a test packet
			n.sendPunch(hostinfo)
		}

		// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
		n.intf.sendMessageToVpnIp(header.Test, header.TestRequest, hostinfo, p, nb, out)

	} else {
		hostinfo.logger(n.l).Debugf("Hostinfo sadness")
	}

	n.pendingDeletion[hostinfo.localIndexId] = struct{}{}
	n.trafficTimer.Add(hostinfo.localIndexId, n.pendingDeletionInterval)
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
