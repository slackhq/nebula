package nebula

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

const defaultPromoteEvery = 1000       // Count of packets sent before we try moving a tunnel to a preferred underlay ip address
const defaultReQueryEvery = 5000       // Count of packets sent before re-querying a hostinfo to the lighthouse
const defaultReQueryWait = time.Minute // Minimum amount of seconds to wait before re-querying a hostinfo the lighthouse. Evaluated every ReQueryEvery
const maxRecvError = 4

// RoamingSuppressSeconds is how long we should prevent roaming back to the previous IP.
// This helps prevent flapping due to packets already in flight
const RoamingSuppressSeconds = 2

type HostInfo struct {
	remote          netip.AddrPort
	remotes         *RemoteList
	promoteCounter  atomic.Uint32
	ConnectionState *ConnectionState
	remoteIndexId   uint32
	localIndexId    uint32
	vpnAddrs        []netip.Addr
	recvError       atomic.Uint32

	// networks are both all vpn and unsafe networks assigned to this host
	networks   *bart.Table[struct{}]
	relayState RelayState

	// HandshakePacket records the packets used to create this hostinfo
	// We need these to avoid replayed handshake packets creating new hostinfos which causes churn
	HandshakePacket map[uint8][]byte

	// nextLHQuery is the earliest we can ask the lighthouse for new information.
	// This is used to limit lighthouse re-queries in chatty clients
	nextLHQuery atomic.Int64

	// lastRebindCount is the other side of Interface.rebindCount, if these values don't match then we need to ask LH
	// for a punch from the remote end of this tunnel. The goal being to prime their conntrack for our traffic just like
	// with a handshake
	lastRebindCount int8

	// lastHandshakeTime records the time the remote side told us about at the stage when the handshake was completed locally
	// Stage 1 packet will contain it if I am a responder, stage 2 packet if I am an initiator
	// This is used to avoid an attack where a handshake packet is replayed after some time
	lastHandshakeTime uint64

	lastRoam       time.Time
	lastRoamRemote netip.AddrPort

	// Used to track other hostinfos for this vpn ip since only 1 can be primary
	// Synchronised via hostmap lock and not the hostinfo lock.
	next, prev *HostInfo
}

// TryPromoteBest handles re-querying lighthouses and probing for better paths
// NOTE: It is an error to call this if you are a lighthouse since they should not roam clients!
func (i *HostInfo) TryPromoteBest(preferredRanges []netip.Prefix, ifce *Interface) {
	c := i.promoteCounter.Add(1)
	if c%ifce.tryPromoteEvery.Load() == 0 {
		remote := i.remote

		// return early if we are already on a preferred remote
		if remote.IsValid() {
			rIP := remote.Addr()
			for _, l := range preferredRanges {
				if l.Contains(rIP) {
					return
				}
			}
		}

		i.remotes.ForEach(preferredRanges, func(addr netip.AddrPort, preferred bool) {
			if remote.IsValid() && (!addr.IsValid() || !preferred) {
				return
			}

			// Try to send a test packet to that host, this should
			// cause it to detect a roaming event and switch remotes
			ifce.sendTo(header.Test, header.TestRequest, i.ConnectionState, i, addr, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
		})
	}

	// Re query our lighthouses for new remotes occasionally
	if c%ifce.reQueryEvery.Load() == 0 && ifce.lightHouse != nil {
		now := time.Now().UnixNano()
		if now < i.nextLHQuery.Load() {
			return
		}

		i.nextLHQuery.Store(now + ifce.reQueryWait.Load())
		ifce.lightHouse.QueryServer(i.vpnAddrs[0])
	}
}

func (i *HostInfo) GetCert() *cert.CachedCertificate {
	if i.ConnectionState != nil {
		return i.ConnectionState.peerCert
	}
	return nil
}

func (i *HostInfo) SetRemote(remote netip.AddrPort) {
	// We copy here because we likely got this remote from a source that reuses the object
	if i.remote != remote {
		i.remote = remote
		i.remotes.LearnRemote(i.vpnAddrs[0], remote)
	}
}

// SetRemoteIfPreferred returns true if the remote was changed. The lastRoam
// time on the HostInfo will also be updated.
func (i *HostInfo) SetRemoteIfPreferred(hm *HostMap, newRemote netip.AddrPort) bool {
	if !newRemote.IsValid() {
		// relays have nil udp Addrs
		return false
	}
	currentRemote := i.remote
	if !currentRemote.IsValid() {
		i.SetRemote(newRemote)
		return true
	}

	// NOTE: We do this loop here instead of calling `isPreferred` in
	// remote_list.go so that we only have to loop over preferredRanges once.
	newIsPreferred := false
	for _, l := range hm.GetPreferredRanges() {
		// return early if we are already on a preferred remote
		if l.Contains(currentRemote.Addr()) {
			return false
		}

		if l.Contains(newRemote.Addr()) {
			newIsPreferred = true
		}
	}

	if newIsPreferred {
		// Consider this a roaming event
		i.lastRoam = time.Now()
		i.lastRoamRemote = currentRemote

		i.SetRemote(newRemote)

		return true
	}

	return false
}

func (i *HostInfo) RecvErrorExceeded() bool {
	if i.recvError.Add(1) >= maxRecvError {
		return true
	}
	return true
}

func (i *HostInfo) buildNetworks(c cert.Certificate) {
	if len(c.Networks()) == 1 && len(c.UnsafeNetworks()) == 0 {
		// Simple case, no CIDRTree needed
		return
	}

	i.networks = new(bart.Table[struct{}])
	for _, network := range c.Networks() {
		i.networks.Insert(network, struct{}{})
	}

	for _, network := range c.UnsafeNetworks() {
		i.networks.Insert(network, struct{}{})
	}
}

func (i *HostInfo) logger(l *logrus.Logger) *logrus.Entry {
	if i == nil {
		return logrus.NewEntry(l)
	}

	li := l.WithField("vpnAddrs", i.vpnAddrs).
		WithField("localIndex", i.localIndexId).
		WithField("remoteIndex", i.remoteIndexId)

	if connState := i.ConnectionState; connState != nil {
		if peerCert := connState.peerCert; peerCert != nil {
			li = li.WithField("certName", peerCert.Certificate.Name())
		}
	}

	return li
}
