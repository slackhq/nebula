package nebula

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// TODO: incount and outcount are intended as a shortcut to locking the mutexes for every single packet
// and something like every 10 packets we could lock, send 10, then unlock for a moment

type connectionManager struct {
	hostMap      *HostMap
	in           map[uint32]struct{}
	inLock       *sync.RWMutex
	inCount      int
	out          map[uint32]struct{}
	outLock      *sync.RWMutex
	outCount     int
	TrafficTimer *SystemTimerWheel
	intf         *Interface

	pendingDeletion      map[uint32]int
	pendingDeletionLock  *sync.RWMutex
	pendingDeletionTimer *SystemTimerWheel

	checkInterval           int
	pendingDeletionInterval int

	l *logrus.Logger
	// I wanted to call one matLock
}

func newConnectionManager(l *logrus.Logger, intf *Interface, checkInterval, pendingDeletionInterval int) *connectionManager {
	nc := &connectionManager{
		hostMap:                 intf.hostMap,
		in:                      make(map[uint32]struct{}),
		inLock:                  &sync.RWMutex{},
		inCount:                 0,
		out:                     make(map[uint32]struct{}),
		outLock:                 &sync.RWMutex{},
		outCount:                0,
		TrafficTimer:            NewSystemTimerWheel(time.Millisecond*500, time.Second*60),
		intf:                    intf,
		pendingDeletion:         make(map[uint32]int),
		pendingDeletionLock:     &sync.RWMutex{},
		pendingDeletionTimer:    NewSystemTimerWheel(time.Millisecond*500, time.Second*60),
		checkInterval:           checkInterval,
		pendingDeletionInterval: pendingDeletionInterval,
		l:                       l,
	}
	nc.Start()
	return nc
}

func (n *connectionManager) In(ip uint32) {
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

func (n *connectionManager) Out(ip uint32) {
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

func (n *connectionManager) CheckIn(vpnIP uint32) bool {
	n.inLock.RLock()
	if _, ok := n.in[vpnIP]; ok {
		n.inLock.RUnlock()
		return true
	}
	n.inLock.RUnlock()
	return false
}

func (n *connectionManager) ClearIP(ip uint32) {
	n.inLock.Lock()
	n.outLock.Lock()
	delete(n.in, ip)
	delete(n.out, ip)
	n.inLock.Unlock()
	n.outLock.Unlock()
}

func (n *connectionManager) ClearPendingDeletion(ip uint32) {
	n.pendingDeletionLock.Lock()
	delete(n.pendingDeletion, ip)
	n.pendingDeletionLock.Unlock()
}

func (n *connectionManager) AddPendingDeletion(ip uint32) {
	n.pendingDeletionLock.Lock()
	if _, ok := n.pendingDeletion[ip]; ok {
		n.pendingDeletion[ip] += 1
	} else {
		n.pendingDeletion[ip] = 0
	}
	n.pendingDeletionTimer.Add(ip, time.Second*time.Duration(n.pendingDeletionInterval))
	n.pendingDeletionLock.Unlock()
}

func (n *connectionManager) checkPendingDeletion(ip uint32) bool {
	n.pendingDeletionLock.RLock()
	if _, ok := n.pendingDeletion[ip]; ok {

		n.pendingDeletionLock.RUnlock()
		return true
	}
	n.pendingDeletionLock.RUnlock()
	return false
}

func (n *connectionManager) AddTrafficWatch(vpnIP uint32, seconds int) {
	n.TrafficTimer.Add(vpnIP, time.Second*time.Duration(seconds))
}

func (n *connectionManager) Start() {
	go n.Run()
}

func (n *connectionManager) Run() {
	clockSource := time.Tick(500 * time.Millisecond)
	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	for now := range clockSource {
		n.HandleMonitorTick(now, p, nb, out)
		n.HandleDeletionTick(now)
	}
}

func (n *connectionManager) HandleMonitorTick(now time.Time, p, nb, out []byte) {
	n.TrafficTimer.advance(now)
	for {
		ep := n.TrafficTimer.Purge()
		if ep == nil {
			break
		}

		vpnIP := ep.(uint32)

		// Check for traffic coming back in from this host.
		traf := n.CheckIn(vpnIP)

		// If we saw incoming packets from this ip, just return
		if traf {
			if n.l.Level >= logrus.DebugLevel {
				n.l.WithField("vpnIp", IntIp(vpnIP)).
					WithField("tunnelCheck", m{"state": "alive", "method": "passive"}).
					Debug("Tunnel status")
			}
			n.ClearIP(vpnIP)
			n.ClearPendingDeletion(vpnIP)
			continue
		}

		// If we didn't we may need to probe or destroy the conn
		hostinfo, err := n.hostMap.QueryVpnIP(vpnIP)
		if err != nil {
			n.l.Debugf("Not found in hostmap: %s", IntIp(vpnIP))
			n.ClearIP(vpnIP)
			n.ClearPendingDeletion(vpnIP)
			continue
		}

		hostinfo.logger(n.l).
			WithField("tunnelCheck", m{"state": "testing", "method": "active"}).
			Debug("Tunnel status")

		if hostinfo != nil && hostinfo.ConnectionState != nil {
			// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
			n.intf.SendMessageToVpnIp(test, testRequest, vpnIP, p, nb, out)

		} else {
			hostinfo.logger(n.l).Debugf("Hostinfo sadness: %s", IntIp(vpnIP))
		}
		n.AddPendingDeletion(vpnIP)
	}

}

func (n *connectionManager) HandleDeletionTick(now time.Time) {
	n.pendingDeletionTimer.advance(now)
	for {
		ep := n.pendingDeletionTimer.Purge()
		if ep == nil {
			break
		}

		vpnIP := ep.(uint32)

		// If we saw incoming packets from this ip, just return
		traf := n.CheckIn(vpnIP)
		if traf {
			n.l.WithField("vpnIp", IntIp(vpnIP)).
				WithField("tunnelCheck", m{"state": "alive", "method": "active"}).
				Debug("Tunnel status")
			n.ClearIP(vpnIP)
			n.ClearPendingDeletion(vpnIP)
			continue
		}

		hostinfo, err := n.hostMap.QueryVpnIP(vpnIP)
		if err != nil {
			n.ClearIP(vpnIP)
			n.ClearPendingDeletion(vpnIP)
			n.l.Debugf("Not found in hostmap: %s", IntIp(vpnIP))
			continue
		}

		// If it comes around on deletion wheel and hasn't resolved itself, delete
		if n.checkPendingDeletion(vpnIP) {
			cn := ""
			if hostinfo.ConnectionState != nil && hostinfo.ConnectionState.peerCert != nil {
				cn = hostinfo.ConnectionState.peerCert.Details.Name
			}
			hostinfo.logger(n.l).
				WithField("tunnelCheck", m{"state": "dead", "method": "active"}).
				WithField("certName", cn).
				Info("Tunnel status")

			n.ClearIP(vpnIP)
			n.ClearPendingDeletion(vpnIP)
			// TODO: This is only here to let tests work. Should do proper mocking
			if n.intf.lightHouse != nil {
				n.intf.lightHouse.DeleteVpnIP(vpnIP)
			}
			n.hostMap.DeleteHostInfo(hostinfo)
		} else {
			n.ClearIP(vpnIP)
			n.ClearPendingDeletion(vpnIP)
		}
	}
}
