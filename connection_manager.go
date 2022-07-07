package nebula

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
)

// TODO: incount and outcount are intended as a shortcut to locking the mutexes for every single packet
// and something like every 10 packets we could lock, send 10, then unlock for a moment

type connectionManager struct {
	hostMap      *HostMap
	in           map[iputil.VpnIp]struct{}
	inLock       *sync.RWMutex
	inCount      int
	out          map[iputil.VpnIp]struct{}
	outLock      *sync.RWMutex
	outCount     int
	TrafficTimer *SystemTimerWheel
	intf         *Interface

	pendingDeletion      map[iputil.VpnIp]int
	pendingDeletionLock  *sync.RWMutex
	pendingDeletionTimer *SystemTimerWheel

	checkInterval           int
	pendingDeletionInterval int

	l *logrus.Logger
	// I wanted to call one matLock
}

func newConnectionManager(ctx context.Context, l *logrus.Logger, intf *Interface, checkInterval, pendingDeletionInterval int) *connectionManager {
	nc := &connectionManager{
		hostMap:                 intf.hostMap,
		in:                      make(map[iputil.VpnIp]struct{}),
		inLock:                  &sync.RWMutex{},
		inCount:                 0,
		out:                     make(map[iputil.VpnIp]struct{}),
		outLock:                 &sync.RWMutex{},
		outCount:                0,
		TrafficTimer:            NewSystemTimerWheel(time.Millisecond*500, time.Second*60),
		intf:                    intf,
		pendingDeletion:         make(map[iputil.VpnIp]int),
		pendingDeletionLock:     &sync.RWMutex{},
		pendingDeletionTimer:    NewSystemTimerWheel(time.Millisecond*500, time.Second*60),
		checkInterval:           checkInterval,
		pendingDeletionInterval: pendingDeletionInterval,
		l:                       l,
	}
	nc.Start(ctx)
	return nc
}

func (n *connectionManager) In(ip iputil.VpnIp) {
	n.inLock.RLock()
	// If this already exists, return
	if _, ok := n.in[ip]; ok {
		n.inLock.RUnlock()
		return
	}
	n.inLock.RUnlock()
	n.inLock.Lock()
	n.in[ip] = struct{}{}
	n.inLock.Unlock()
}

func (n *connectionManager) Out(ip iputil.VpnIp) {
	n.outLock.RLock()
	// If this already exists, return
	if _, ok := n.out[ip]; ok {
		n.outLock.RUnlock()
		return
	}
	n.outLock.RUnlock()
	n.outLock.Lock()
	// double check since we dropped the lock temporarily
	if _, ok := n.out[ip]; ok {
		n.outLock.Unlock()
		return
	}
	n.out[ip] = struct{}{}
	n.AddTrafficWatch(ip, n.checkInterval)
	n.outLock.Unlock()
}

func (n *connectionManager) CheckIn(vpnIp iputil.VpnIp) bool {
	n.inLock.RLock()
	if _, ok := n.in[vpnIp]; ok {
		n.inLock.RUnlock()
		return true
	}
	n.inLock.RUnlock()
	return false
}

func (n *connectionManager) ClearIP(ip iputil.VpnIp) {
	n.inLock.Lock()
	n.outLock.Lock()
	delete(n.in, ip)
	delete(n.out, ip)
	n.inLock.Unlock()
	n.outLock.Unlock()
}

func (n *connectionManager) ClearPendingDeletion(ip iputil.VpnIp) {
	n.pendingDeletionLock.Lock()
	delete(n.pendingDeletion, ip)
	n.pendingDeletionLock.Unlock()
}

func (n *connectionManager) AddPendingDeletion(ip iputil.VpnIp) {
	n.pendingDeletionLock.Lock()
	if _, ok := n.pendingDeletion[ip]; ok {
		n.pendingDeletion[ip] += 1
	} else {
		n.pendingDeletion[ip] = 0
	}
	n.pendingDeletionTimer.Add(ip, time.Second*time.Duration(n.pendingDeletionInterval))
	n.pendingDeletionLock.Unlock()
}

func (n *connectionManager) checkPendingDeletion(ip iputil.VpnIp) bool {
	n.pendingDeletionLock.RLock()
	if _, ok := n.pendingDeletion[ip]; ok {

		n.pendingDeletionLock.RUnlock()
		return true
	}
	n.pendingDeletionLock.RUnlock()
	return false
}

func (n *connectionManager) AddTrafficWatch(vpnIp iputil.VpnIp, seconds int) {
	n.TrafficTimer.Add(vpnIp, time.Second*time.Duration(seconds))
}

func (n *connectionManager) Start(ctx context.Context) {
	go n.Run(ctx)
}

func (n *connectionManager) Run(ctx context.Context) {
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
			n.HandleMonitorTick(now, p, nb, out)
			n.HandleDeletionTick(now)
		}
	}
}

func (n *connectionManager) HandleMonitorTick(now time.Time, p, nb, out []byte) {
	n.TrafficTimer.advance(now)
	for {
		ep := n.TrafficTimer.Purge()
		if ep == nil {
			break
		}

		vpnIp := ep.(iputil.VpnIp)

		// Check for traffic coming back in from this host.
		traf := n.CheckIn(vpnIp)

		hostinfo, err := n.hostMap.QueryVpnIp(vpnIp)
		if err != nil {
			n.l.Debugf("Not found in hostmap: %s", vpnIp)
			n.ClearIP(vpnIp)
			n.ClearPendingDeletion(vpnIp)
			continue
		}

		if n.handleInvalidCertificate(now, vpnIp, hostinfo) {
			continue
		}

		// If we saw an incoming packets from this ip and peer's certificate is not
		// expired, just ignore.
		if traf {
			if n.l.Level >= logrus.DebugLevel {
				n.l.WithField("vpnIp", vpnIp).
					WithField("tunnelCheck", m{"state": "alive", "method": "passive"}).
					Debug("Tunnel status")
			}
			n.ClearIP(vpnIp)
			n.ClearPendingDeletion(vpnIp)
			continue
		}

		hostinfo.logger(n.l).
			WithField("tunnelCheck", m{"state": "testing", "method": "active"}).
			Debug("Tunnel status")

		if hostinfo != nil && hostinfo.ConnectionState != nil {
			// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
			n.intf.SendMessageToVpnIp(header.Test, header.TestRequest, vpnIp, p, nb, out)

		} else {
			hostinfo.logger(n.l).Debugf("Hostinfo sadness: %s", vpnIp)
		}
		n.AddPendingDeletion(vpnIp)
	}

}

func (n *connectionManager) HandleDeletionTick(now time.Time) {
	n.pendingDeletionTimer.advance(now)
	for {
		ep := n.pendingDeletionTimer.Purge()
		if ep == nil {
			break
		}

		vpnIp := ep.(iputil.VpnIp)

		hostinfo, err := n.hostMap.QueryVpnIp(vpnIp)
		if err != nil {
			n.l.Debugf("Not found in hostmap: %s", vpnIp)
			n.ClearIP(vpnIp)
			n.ClearPendingDeletion(vpnIp)
			continue
		}

		if n.handleInvalidCertificate(now, vpnIp, hostinfo) {
			continue
		}

		// If we saw an incoming packets from this ip and peer's certificate is not
		// expired, just ignore.
		traf := n.CheckIn(vpnIp)
		if traf {
			n.l.WithField("vpnIp", vpnIp).
				WithField("tunnelCheck", m{"state": "alive", "method": "active"}).
				Debug("Tunnel status")

			n.ClearIP(vpnIp)
			n.ClearPendingDeletion(vpnIp)
			continue
		}

		// If it comes around on deletion wheel and hasn't resolved itself, delete
		if n.checkPendingDeletion(vpnIp) {
			cn := ""
			if hostinfo.ConnectionState != nil && hostinfo.ConnectionState.peerCert != nil {
				cn = hostinfo.ConnectionState.peerCert.Details.Name
			}
			hostinfo.logger(n.l).
				WithField("tunnelCheck", m{"state": "dead", "method": "active"}).
				WithField("certName", cn).
				Info("Tunnel status")

			n.ClearIP(vpnIp)
			n.ClearPendingDeletion(vpnIp)
			// TODO: This is only here to let tests work. Should do proper mocking
			if n.intf.lightHouse != nil {
				n.intf.lightHouse.DeleteVpnIp(vpnIp)
			}
			n.hostMap.DeleteHostInfo(hostinfo)
		} else {
			n.ClearIP(vpnIp)
			n.ClearPendingDeletion(vpnIp)
		}
	}
}

// handleInvalidCertificates will destroy a tunnel if pki.disconnect_invalid is true and the certificate is no longer valid
func (n *connectionManager) handleInvalidCertificate(now time.Time, vpnIp iputil.VpnIp, hostinfo *HostInfo) bool {
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
	n.l.WithField("vpnIp", vpnIp).WithError(err).
		WithField("certName", remoteCert.Details.Name).
		WithField("fingerprint", fingerprint).
		Info("Remote certificate is no longer valid, tearing down the tunnel")

	// Inform the remote and close the tunnel locally
	n.intf.sendCloseTunnel(hostinfo)
	n.intf.closeTunnel(hostinfo)

	n.ClearIP(vpnIp)
	n.ClearPendingDeletion(vpnIp)
	return true
}
