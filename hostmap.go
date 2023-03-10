package nebula

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/udp"
)

// const ProbeLen = 100
const PromoteEvery = 1000
const ReQueryEvery = 5000
const MaxRemotes = 10

// MaxHostInfosPerVpnIp is the max number of hostinfos we will track for a given vpn ip
// 5 allows for an initial handshake and each host pair re-handshaking twice
const MaxHostInfosPerVpnIp = 5

// How long we should prevent roaming back to the previous IP.
// This helps prevent flapping due to packets already in flight
const RoamingSuppressSeconds = 2

const (
	Requested = iota
	Established
)

const (
	Unknowntype = iota
	ForwardingType
	TerminalType
)

type Relay struct {
	Type        int
	State       int
	LocalIndex  uint32
	RemoteIndex uint32
	PeerIp      iputil.VpnIp
}

type HostMap struct {
	sync.RWMutex    //Because we concurrently read and write to our maps
	name            string
	Indexes         map[uint32]*HostInfo
	Relays          map[uint32]*HostInfo // Maps a Relay IDX to a Relay HostInfo object
	RemoteIndexes   map[uint32]*HostInfo
	Hosts           map[iputil.VpnIp]*HostInfo
	preferredRanges []*net.IPNet
	vpnCIDR         *net.IPNet
	metricsEnabled  bool
	l               *logrus.Logger
}

type RelayState struct {
	sync.RWMutex

	relays        map[iputil.VpnIp]struct{} // Set of VpnIp's of Hosts to use as relays to access this peer
	relayForByIp  map[iputil.VpnIp]*Relay   // Maps VpnIps of peers for which this HostInfo is a relay to some Relay info
	relayForByIdx map[uint32]*Relay         // Maps a local index to some Relay info
}

func (rs *RelayState) DeleteRelay(ip iputil.VpnIp) {
	rs.Lock()
	defer rs.Unlock()
	delete(rs.relays, ip)
}

func (rs *RelayState) GetRelayForByIp(ip iputil.VpnIp) (*Relay, bool) {
	rs.RLock()
	defer rs.RUnlock()
	r, ok := rs.relayForByIp[ip]
	return r, ok
}

func (rs *RelayState) InsertRelayTo(ip iputil.VpnIp) {
	rs.Lock()
	defer rs.Unlock()
	rs.relays[ip] = struct{}{}
}

func (rs *RelayState) CopyRelayIps() []iputil.VpnIp {
	rs.RLock()
	defer rs.RUnlock()
	ret := make([]iputil.VpnIp, 0, len(rs.relays))
	for ip := range rs.relays {
		ret = append(ret, ip)
	}
	return ret
}

func (rs *RelayState) CopyRelayForIps() []iputil.VpnIp {
	rs.RLock()
	defer rs.RUnlock()
	currentRelays := make([]iputil.VpnIp, 0, len(rs.relayForByIp))
	for relayIp := range rs.relayForByIp {
		currentRelays = append(currentRelays, relayIp)
	}
	return currentRelays
}

func (rs *RelayState) CopyRelayForIdxs() []uint32 {
	rs.RLock()
	defer rs.RUnlock()
	ret := make([]uint32, 0, len(rs.relayForByIdx))
	for i := range rs.relayForByIdx {
		ret = append(ret, i)
	}
	return ret
}

func (rs *RelayState) RemoveRelay(localIdx uint32) (iputil.VpnIp, bool) {
	rs.Lock()
	defer rs.Unlock()
	relay, ok := rs.relayForByIdx[localIdx]
	if !ok {
		return iputil.VpnIp(0), false
	}
	delete(rs.relayForByIdx, localIdx)
	delete(rs.relayForByIp, relay.PeerIp)
	return relay.PeerIp, true
}

func (rs *RelayState) QueryRelayForByIp(vpnIp iputil.VpnIp) (*Relay, bool) {
	rs.RLock()
	defer rs.RUnlock()
	r, ok := rs.relayForByIp[vpnIp]
	return r, ok
}

func (rs *RelayState) QueryRelayForByIdx(idx uint32) (*Relay, bool) {
	rs.RLock()
	defer rs.RUnlock()
	r, ok := rs.relayForByIdx[idx]
	return r, ok
}
func (rs *RelayState) InsertRelay(ip iputil.VpnIp, idx uint32, r *Relay) {
	rs.Lock()
	defer rs.Unlock()
	rs.relayForByIp[ip] = r
	rs.relayForByIdx[idx] = r
}

type HostInfo struct {
	sync.RWMutex

	remote            *udp.Addr
	remotes           *RemoteList
	promoteCounter    atomic.Uint32
	ConnectionState   *ConnectionState
	handshakeStart    time.Time        //todo: this an entry in the handshake manager
	HandshakeReady    bool             //todo: being in the manager means you are ready
	HandshakeCounter  int              //todo: another handshake manager entry
	HandshakeComplete bool             //todo: this should go away in favor of ConnectionState.ready
	HandshakePacket   map[uint8][]byte //todo: this is other handshake manager entry
	packetStore       []*cachedPacket  //todo: this is other handshake manager entry
	remoteIndexId     uint32
	localIndexId      uint32
	vpnIp             iputil.VpnIp
	recvError         int
	remoteCidr        *cidr.Tree4
	relayState        RelayState

	// lastRebindCount is the other side of Interface.rebindCount, if these values don't match then we need to ask LH
	// for a punch from the remote end of this tunnel. The goal being to prime their conntrack for our traffic just like
	// with a handshake
	lastRebindCount int8

	// lastHandshakeTime records the time the remote side told us about at the stage when the handshake was completed locally
	// Stage 1 packet will contain it if I am a responder, stage 2 packet if I am an initiator
	// This is used to avoid an attack where a handshake packet is replayed after some time
	lastHandshakeTime uint64

	lastRoam       time.Time
	lastRoamRemote *udp.Addr

	// Used to track other hostinfos for this vpn ip since only 1 can be primary
	// Synchronised via hostmap lock and not the hostinfo lock.
	next, prev *HostInfo
}

type ViaSender struct {
	relayHI   *HostInfo // relayHI is the host info object of the relay
	remoteIdx uint32    // remoteIdx is the index included in the header of the received packet
	relay     *Relay    // relay contains the rest of the relay information, including the PeerIP of the host trying to communicate with us.
}

type cachedPacket struct {
	messageType    header.MessageType
	messageSubType header.MessageSubType
	callback       packetCallback
	packet         []byte
}

type packetCallback func(t header.MessageType, st header.MessageSubType, h *HostInfo, p, nb, out []byte)

type cachedPacketMetrics struct {
	sent    metrics.Counter
	dropped metrics.Counter
}

func NewHostMap(l *logrus.Logger, name string, vpnCIDR *net.IPNet, preferredRanges []*net.IPNet) *HostMap {
	h := map[iputil.VpnIp]*HostInfo{}
	i := map[uint32]*HostInfo{}
	r := map[uint32]*HostInfo{}
	relays := map[uint32]*HostInfo{}
	m := HostMap{
		name:            name,
		Indexes:         i,
		Relays:          relays,
		RemoteIndexes:   r,
		Hosts:           h,
		preferredRanges: preferredRanges,
		vpnCIDR:         vpnCIDR,
		l:               l,
	}
	return &m
}

// UpdateStats takes a name and reports host and index counts to the stats collection system
func (hm *HostMap) EmitStats(name string) {
	hm.RLock()
	hostLen := len(hm.Hosts)
	indexLen := len(hm.Indexes)
	remoteIndexLen := len(hm.RemoteIndexes)
	relaysLen := len(hm.Relays)
	hm.RUnlock()

	metrics.GetOrRegisterGauge("hostmap."+name+".hosts", nil).Update(int64(hostLen))
	metrics.GetOrRegisterGauge("hostmap."+name+".indexes", nil).Update(int64(indexLen))
	metrics.GetOrRegisterGauge("hostmap."+name+".remoteIndexes", nil).Update(int64(remoteIndexLen))
	metrics.GetOrRegisterGauge("hostmap."+name+".relayIndexes", nil).Update(int64(relaysLen))
}

func (hm *HostMap) RemoveRelay(localIdx uint32) {
	hm.Lock()
	hiRelay, ok := hm.Relays[localIdx]
	if !ok {
		hm.Unlock()
		return
	}
	delete(hm.Relays, localIdx)
	hm.Unlock()
	ip, ok := hiRelay.relayState.RemoveRelay(localIdx)
	if !ok {
		return
	}
	hiPeer, err := hm.QueryVpnIp(ip)
	if err != nil {
		return
	}
	var otherPeerIdx uint32
	hiPeer.relayState.DeleteRelay(hiRelay.vpnIp)
	relay, ok := hiPeer.relayState.GetRelayForByIp(hiRelay.vpnIp)
	if ok {
		otherPeerIdx = relay.LocalIndex
	}
	// I am a relaying host. I need to remove the other relay, too.
	hm.RemoveRelay(otherPeerIdx)
}

func (hm *HostMap) GetIndexByVpnIp(vpnIp iputil.VpnIp) (uint32, error) {
	hm.RLock()
	if i, ok := hm.Hosts[vpnIp]; ok {
		index := i.localIndexId
		hm.RUnlock()
		return index, nil
	}
	hm.RUnlock()
	return 0, errors.New("vpn IP not found")
}

func (hm *HostMap) Add(ip iputil.VpnIp, hostinfo *HostInfo) {
	hm.Lock()
	hm.Hosts[ip] = hostinfo
	hm.Unlock()
}

func (hm *HostMap) AddVpnIp(vpnIp iputil.VpnIp, init func(hostinfo *HostInfo)) (hostinfo *HostInfo, created bool) {
	hm.RLock()
	if h, ok := hm.Hosts[vpnIp]; !ok {
		hm.RUnlock()
		h = &HostInfo{
			vpnIp:           vpnIp,
			HandshakePacket: make(map[uint8][]byte, 0),
			relayState: RelayState{
				relays:        map[iputil.VpnIp]struct{}{},
				relayForByIp:  map[iputil.VpnIp]*Relay{},
				relayForByIdx: map[uint32]*Relay{},
			},
		}
		if init != nil {
			init(h)
		}
		hm.Lock()
		hm.Hosts[vpnIp] = h
		hm.Unlock()
		return h, true
	} else {
		hm.RUnlock()
		return h, false
	}
}

func (hm *HostMap) DeleteVpnIp(vpnIp iputil.VpnIp) {
	hm.Lock()
	delete(hm.Hosts, vpnIp)
	if len(hm.Hosts) == 0 {
		hm.Hosts = map[iputil.VpnIp]*HostInfo{}
	}
	hm.Unlock()

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "vpnIp": vpnIp, "mapTotalSize": len(hm.Hosts)}).
			Debug("Hostmap vpnIp deleted")
	}
}

// Only used by pendingHostMap when the remote index is not initially known
func (hm *HostMap) addRemoteIndexHostInfo(index uint32, h *HostInfo) {
	hm.Lock()
	h.remoteIndexId = index
	hm.RemoteIndexes[index] = h
	hm.Unlock()

	if hm.l.Level > logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "indexNumber": index, "mapTotalSize": len(hm.Indexes),
			"hostinfo": m{"existing": true, "localIndexId": h.localIndexId, "hostId": h.vpnIp}}).
			Debug("Hostmap remoteIndex added")
	}
}

func (hm *HostMap) AddVpnIpHostInfo(vpnIp iputil.VpnIp, h *HostInfo) {
	hm.Lock()
	h.vpnIp = vpnIp
	hm.Hosts[vpnIp] = h
	hm.Indexes[h.localIndexId] = h
	hm.RemoteIndexes[h.remoteIndexId] = h
	hm.Unlock()

	if hm.l.Level > logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "vpnIp": vpnIp, "mapTotalSize": len(hm.Hosts),
			"hostinfo": m{"existing": true, "localIndexId": h.localIndexId, "vpnIp": h.vpnIp}}).
			Debug("Hostmap vpnIp added")
	}
}

// This is only called in pendingHostmap, to cleanup an inbound handshake
func (hm *HostMap) DeleteIndex(index uint32) {
	hm.Lock()
	hostinfo, ok := hm.Indexes[index]
	if ok {
		delete(hm.Indexes, index)
		delete(hm.RemoteIndexes, hostinfo.remoteIndexId)

		// Check if we have an entry under hostId that matches the same hostinfo
		// instance. Clean it up as well if we do.
		hostinfo2, ok := hm.Hosts[hostinfo.vpnIp]
		if ok && hostinfo2 == hostinfo {
			delete(hm.Hosts, hostinfo.vpnIp)
		}
	}
	hm.Unlock()

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "indexNumber": index, "mapTotalSize": len(hm.Indexes)}).
			Debug("Hostmap index deleted")
	}
}

// This is used to cleanup on recv_error
func (hm *HostMap) DeleteReverseIndex(index uint32) {
	hm.Lock()
	hostinfo, ok := hm.RemoteIndexes[index]
	if ok {
		delete(hm.Indexes, hostinfo.localIndexId)
		delete(hm.RemoteIndexes, index)

		// Check if we have an entry under hostId that matches the same hostinfo
		// instance. Clean it up as well if we do (they might not match in pendingHostmap)
		var hostinfo2 *HostInfo
		hostinfo2, ok = hm.Hosts[hostinfo.vpnIp]
		if ok && hostinfo2 == hostinfo {
			delete(hm.Hosts, hostinfo.vpnIp)
		}
	}
	hm.Unlock()

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "indexNumber": index, "mapTotalSize": len(hm.Indexes)}).
			Debug("Hostmap remote index deleted")
	}
}

// DeleteHostInfo will fully unlink the hostinfo and return true if it was the final hostinfo for this vpn ip
func (hm *HostMap) DeleteHostInfo(hostinfo *HostInfo) bool {
	// Delete the host itself, ensuring it's not modified anymore
	hm.Lock()
        // If we have a previous or next hostinfo then we are not the last one for this vpn ip
	final := (hostinfo.next == nil && hostinfo.prev == nil)
	hm.unlockedDeleteHostInfo(hostinfo)
	hm.Unlock()

	// And tear down all the relays going through this host
	for _, localIdx := range hostinfo.relayState.CopyRelayForIdxs() {
		hm.RemoveRelay(localIdx)
	}

	// And tear down the relays this deleted hostInfo was using to be reached
	teardownRelayIdx := []uint32{}
	for _, relayIp := range hostinfo.relayState.CopyRelayIps() {
		relayHostInfo, err := hm.QueryVpnIp(relayIp)
		if err != nil {
			hm.l.WithError(err).WithField("relay", relayIp).Info("Missing relay host in hostmap")
		} else {
			if r, ok := relayHostInfo.relayState.QueryRelayForByIp(hostinfo.vpnIp); ok {
				teardownRelayIdx = append(teardownRelayIdx, r.LocalIndex)
			}
		}
	}
	for _, localIdx := range teardownRelayIdx {
		hm.RemoveRelay(localIdx)
	}

	return final
}

func (hm *HostMap) DeleteRelayIdx(localIdx uint32) {
	hm.Lock()
	defer hm.Unlock()
	delete(hm.RemoteIndexes, localIdx)
}

func (hm *HostMap) MakePrimary(hostinfo *HostInfo) {
	hm.Lock()
	defer hm.Unlock()
	hm.unlockedMakePrimary(hostinfo)
}

func (hm *HostMap) unlockedMakePrimary(hostinfo *HostInfo) {
	oldHostinfo := hm.Hosts[hostinfo.vpnIp]
	if oldHostinfo == hostinfo {
		return
	}

	if hostinfo.prev != nil {
		hostinfo.prev.next = hostinfo.next
	}

	if hostinfo.next != nil {
		hostinfo.next.prev = hostinfo.prev
	}

	hm.Hosts[hostinfo.vpnIp] = hostinfo

	if oldHostinfo == nil {
		return
	}

	hostinfo.next = oldHostinfo
	oldHostinfo.prev = hostinfo
	hostinfo.prev = nil
}

func (hm *HostMap) unlockedDeleteHostInfo(hostinfo *HostInfo) {
	primary, ok := hm.Hosts[hostinfo.vpnIp]
	if ok && primary == hostinfo {
		// The vpnIp pointer points to the same hostinfo as the local index id, we can remove it
		delete(hm.Hosts, hostinfo.vpnIp)
		if len(hm.Hosts) == 0 {
			hm.Hosts = map[iputil.VpnIp]*HostInfo{}
		}

		if hostinfo.next != nil {
			// We had more than 1 hostinfo at this vpnip, promote the next in the list to primary
			hm.Hosts[hostinfo.vpnIp] = hostinfo.next
			// It is primary, there is no previous hostinfo now
			hostinfo.next.prev = nil
		}

	} else {
		// Relink if we were in the middle of multiple hostinfos for this vpn ip
		if hostinfo.prev != nil {
			hostinfo.prev.next = hostinfo.next
		}

		if hostinfo.next != nil {
			hostinfo.next.prev = hostinfo.prev
		}
	}

	hostinfo.next = nil
	hostinfo.prev = nil

	// The remote index uses index ids outside our control so lets make sure we are only removing
	// the remote index pointer here if it points to the hostinfo we are deleting
	hostinfo2, ok := hm.RemoteIndexes[hostinfo.remoteIndexId]
	if ok && hostinfo2 == hostinfo {
		delete(hm.RemoteIndexes, hostinfo.remoteIndexId)
		if len(hm.RemoteIndexes) == 0 {
			hm.RemoteIndexes = map[uint32]*HostInfo{}
		}
	}

	delete(hm.Indexes, hostinfo.localIndexId)
	if len(hm.Indexes) == 0 {
		hm.Indexes = map[uint32]*HostInfo{}
	}

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "mapTotalSize": len(hm.Hosts),
			"vpnIp": hostinfo.vpnIp, "indexNumber": hostinfo.localIndexId, "remoteIndexNumber": hostinfo.remoteIndexId}).
			Debug("Hostmap hostInfo deleted")
	}
}

func (hm *HostMap) QueryIndex(index uint32) (*HostInfo, error) {
	//TODO: we probably just want to return bool instead of error, or at least a static error
	hm.RLock()
	if h, ok := hm.Indexes[index]; ok {
		hm.RUnlock()
		return h, nil
	} else {
		hm.RUnlock()
		return nil, errors.New("unable to find index")
	}
}
func (hm *HostMap) QueryRelayIndex(index uint32) (*HostInfo, error) {
	//TODO: we probably just want to return bool instead of error, or at least a static error
	hm.RLock()
	if h, ok := hm.Relays[index]; ok {
		hm.RUnlock()
		return h, nil
	} else {
		hm.RUnlock()
		return nil, errors.New("unable to find index")
	}
}

func (hm *HostMap) QueryReverseIndex(index uint32) (*HostInfo, error) {
	hm.RLock()
	if h, ok := hm.RemoteIndexes[index]; ok {
		hm.RUnlock()
		return h, nil
	} else {
		hm.RUnlock()
		return nil, fmt.Errorf("unable to find reverse index or connectionstate nil in %s hostmap", hm.name)
	}
}

func (hm *HostMap) QueryVpnIp(vpnIp iputil.VpnIp) (*HostInfo, error) {
	return hm.queryVpnIp(vpnIp, nil)
}

// PromoteBestQueryVpnIp will attempt to lazily switch to the best remote every
// `PromoteEvery` calls to this function for a given host.
func (hm *HostMap) PromoteBestQueryVpnIp(vpnIp iputil.VpnIp, ifce *Interface) (*HostInfo, error) {
	return hm.queryVpnIp(vpnIp, ifce)
}

func (hm *HostMap) queryVpnIp(vpnIp iputil.VpnIp, promoteIfce *Interface) (*HostInfo, error) {
	hm.RLock()
	if h, ok := hm.Hosts[vpnIp]; ok {
		hm.RUnlock()
		// Do not attempt promotion if you are a lighthouse
		if promoteIfce != nil && !promoteIfce.lightHouse.amLighthouse {
			h.TryPromoteBest(hm.preferredRanges, promoteIfce)
		}
		return h, nil

	}

	hm.RUnlock()
	return nil, errors.New("unable to find host")
}

// unlockedAddHostInfo assumes you have a write-lock and will add a hostinfo object to the hostmap Indexes and RemoteIndexes maps.
// If an entry exists for the Hosts table (vpnIp -> hostinfo) then the provided hostinfo will be made primary
func (hm *HostMap) unlockedAddHostInfo(hostinfo *HostInfo, f *Interface) {
	if f.serveDns {
		remoteCert := hostinfo.ConnectionState.peerCert
		dnsR.Add(remoteCert.Details.Name+".", remoteCert.Details.Ips[0].IP.String())
	}

	existing := hm.Hosts[hostinfo.vpnIp]
	hm.Hosts[hostinfo.vpnIp] = hostinfo

	if existing != nil {
		hostinfo.next = existing
		existing.prev = hostinfo
	}

	hm.Indexes[hostinfo.localIndexId] = hostinfo
	hm.RemoteIndexes[hostinfo.remoteIndexId] = hostinfo

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "vpnIp": hostinfo.vpnIp, "mapTotalSize": len(hm.Hosts),
			"hostinfo": m{"existing": true, "localIndexId": hostinfo.localIndexId, "hostId": hostinfo.vpnIp}}).
			Debug("Hostmap vpnIp added")
	}

	i := 1
	check := hostinfo
	for check != nil {
		if i > MaxHostInfosPerVpnIp {
			hm.unlockedDeleteHostInfo(check)
		}
		check = check.next
		i++
	}
}

// punchList assembles a list of all non nil RemoteList pointer entries in this hostmap
// The caller can then do the its work outside of the read lock
func (hm *HostMap) punchList(rl []*RemoteList) []*RemoteList {
	hm.RLock()
	defer hm.RUnlock()

	for _, v := range hm.Hosts {
		if v.remotes != nil {
			rl = append(rl, v.remotes)
		}
	}
	return rl
}

// Punchy iterates through the result of punchList() to assemble all known addresses and sends a hole punch packet to them
func (hm *HostMap) Punchy(ctx context.Context, conn *udp.Conn) {
	var metricsTxPunchy metrics.Counter
	if hm.metricsEnabled {
		metricsTxPunchy = metrics.GetOrRegisterCounter("messages.tx.punchy", nil)
	} else {
		metricsTxPunchy = metrics.NilCounter{}
	}

	var remotes []*RemoteList
	b := []byte{1}

	clockSource := time.NewTicker(time.Second * 10)
	defer clockSource.Stop()

	for {
		remotes = hm.punchList(remotes[:0])
		for _, rl := range remotes {
			//TODO: CopyAddrs generates garbage but ForEach locks for the work here, figure out which way is better
			for _, addr := range rl.CopyAddrs(hm.preferredRanges) {
				metricsTxPunchy.Inc(1)
				conn.WriteTo(b, addr)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-clockSource.C:
			continue
		}
	}
}

// TryPromoteBest handles re-querying lighthouses and probing for better paths
// NOTE: It is an error to call this if you are a lighthouse since they should not roam clients!
func (i *HostInfo) TryPromoteBest(preferredRanges []*net.IPNet, ifce *Interface) {
	c := i.promoteCounter.Add(1)
	if c%PromoteEvery == 0 {
		// The lock here is currently protecting i.remote access
		i.RLock()
		remote := i.remote
		i.RUnlock()

		// return early if we are already on a preferred remote
		if remote != nil {
			rIP := remote.IP
			for _, l := range preferredRanges {
				if l.Contains(rIP) {
					return
				}
			}
		}

		i.remotes.ForEach(preferredRanges, func(addr *udp.Addr, preferred bool) {
			if remote != nil && (addr == nil || !preferred) {
				return
			}

			// Try to send a test packet to that host, this should
			// cause it to detect a roaming event and switch remotes
			ifce.sendTo(header.Test, header.TestRequest, i.ConnectionState, i, addr, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
		})
	}

	// Re query our lighthouses for new remotes occasionally
	if c%ReQueryEvery == 0 && ifce.lightHouse != nil {
		ifce.lightHouse.QueryServer(i.vpnIp, ifce)
	}
}

func (i *HostInfo) cachePacket(l *logrus.Logger, t header.MessageType, st header.MessageSubType, packet []byte, f packetCallback, m *cachedPacketMetrics) {
	//TODO: return the error so we can log with more context
	if len(i.packetStore) < 100 {
		tempPacket := make([]byte, len(packet))
		copy(tempPacket, packet)
		//l.WithField("trace", string(debug.Stack())).Error("Caching packet", tempPacket)
		i.packetStore = append(i.packetStore, &cachedPacket{t, st, f, tempPacket})
		if l.Level >= logrus.DebugLevel {
			i.logger(l).
				WithField("length", len(i.packetStore)).
				WithField("stored", true).
				Debugf("Packet store")
		}

	} else if l.Level >= logrus.DebugLevel {
		m.dropped.Inc(1)
		i.logger(l).
			WithField("length", len(i.packetStore)).
			WithField("stored", false).
			Debugf("Packet store")
	}
}

// handshakeComplete will set the connection as ready to communicate, as well as flush any stored packets
func (i *HostInfo) handshakeComplete(l *logrus.Logger, m *cachedPacketMetrics) {
	//TODO: I'm not certain the distinction between handshake complete and ConnectionState being ready matters because:
	//TODO: HandshakeComplete means send stored packets and ConnectionState.ready means we are ready to send
	//TODO: if the transition from HandhsakeComplete to ConnectionState.ready happens all within this function they are identical

	i.ConnectionState.queueLock.Lock()
	i.HandshakeComplete = true
	//TODO: this should be managed by the handshake state machine to set it based on how many handshake were seen.
	// Clamping it to 2 gets us out of the woods for now
	i.ConnectionState.messageCounter.Store(2)

	if l.Level >= logrus.DebugLevel {
		i.logger(l).Debugf("Sending %d stored packets", len(i.packetStore))
	}

	if len(i.packetStore) > 0 {
		nb := make([]byte, 12, 12)
		out := make([]byte, mtu)
		for _, cp := range i.packetStore {
			cp.callback(cp.messageType, cp.messageSubType, i, cp.packet, nb, out)
		}
		m.sent.Inc(int64(len(i.packetStore)))
	}

	i.remotes.ResetBlockedRemotes()
	i.packetStore = make([]*cachedPacket, 0)
	i.ConnectionState.ready = true
	i.ConnectionState.queueLock.Unlock()
	i.ConnectionState.certState = nil
}

func (i *HostInfo) GetCert() *cert.NebulaCertificate {
	if i.ConnectionState != nil {
		return i.ConnectionState.peerCert
	}
	return nil
}

func (i *HostInfo) SetRemote(remote *udp.Addr) {
	// We copy here because we likely got this remote from a source that reuses the object
	if !i.remote.Equals(remote) {
		i.remote = remote.Copy()
		i.remotes.LearnRemote(i.vpnIp, remote.Copy())
	}
}

// SetRemoteIfPreferred returns true if the remote was changed. The lastRoam
// time on the HostInfo will also be updated.
func (i *HostInfo) SetRemoteIfPreferred(hm *HostMap, newRemote *udp.Addr) bool {
	if newRemote == nil {
		// relays have nil udp Addrs
		return false
	}
	currentRemote := i.remote
	if currentRemote == nil {
		i.SetRemote(newRemote)
		return true
	}

	// NOTE: We do this loop here instead of calling `isPreferred` in
	// remote_list.go so that we only have to loop over preferredRanges once.
	newIsPreferred := false
	for _, l := range hm.preferredRanges {
		// return early if we are already on a preferred remote
		if l.Contains(currentRemote.IP) {
			return false
		}

		if l.Contains(newRemote.IP) {
			newIsPreferred = true
		}
	}

	if newIsPreferred {
		// Consider this a roaming event
		i.lastRoam = time.Now()
		i.lastRoamRemote = currentRemote.Copy()

		i.SetRemote(newRemote)

		return true
	}

	return false
}

func (i *HostInfo) RecvErrorExceeded() bool {
	if i.recvError < 3 {
		i.recvError += 1
		return false
	}
	return true
}

func (i *HostInfo) CreateRemoteCIDR(c *cert.NebulaCertificate) {
	if len(c.Details.Ips) == 1 && len(c.Details.Subnets) == 0 {
		// Simple case, no CIDRTree needed
		return
	}

	remoteCidr := cidr.NewTree4()
	for _, ip := range c.Details.Ips {
		remoteCidr.AddCIDR(&net.IPNet{IP: ip.IP, Mask: net.IPMask{255, 255, 255, 255}}, struct{}{})
	}

	for _, n := range c.Details.Subnets {
		remoteCidr.AddCIDR(n, struct{}{})
	}
	i.remoteCidr = remoteCidr
}

func (i *HostInfo) logger(l *logrus.Logger) *logrus.Entry {
	if i == nil {
		return logrus.NewEntry(l)
	}

	li := l.WithField("vpnIp", i.vpnIp).
		WithField("localIndex", i.localIndexId).
		WithField("remoteIndex", i.remoteIndexId)

	if connState := i.ConnectionState; connState != nil {
		if peerCert := connState.peerCert; peerCert != nil {
			li = li.WithField("certName", peerCert.Details.Name)
		}
	}

	return li
}

// Utility functions

func localIps(l *logrus.Logger, allowList *LocalAllowList) *[]net.IP {
	//FIXME: This function is pretty garbage
	var ips []net.IP
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		allow := allowList.AllowName(i.Name)
		if l.Level >= logrus.TraceLevel {
			l.WithField("interfaceName", i.Name).WithField("allow", allow).Trace("localAllowList.AllowName")
		}

		if !allow {
			continue
		}
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				//continue
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			//TODO: Filtering out link local for now, this is probably the most correct thing
			//TODO: Would be nice to filter out SLAAC MAC based ips as well
			if ip.IsLoopback() == false && !ip.IsLinkLocalUnicast() {
				allow := allowList.Allow(ip)
				if l.Level >= logrus.TraceLevel {
					l.WithField("localIp", ip).WithField("allow", allow).Trace("localAllowList.Allow")
				}
				if !allow {
					continue
				}

				ips = append(ips, ip)
			}
		}
	}
	return &ips
}
