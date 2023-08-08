package nebula

import (
	"errors"
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
const defaultPromoteEvery = 1000       // Count of packets sent before we try moving a tunnel to a preferred underlay ip address
const defaultReQueryEvery = 5000       // Count of packets sent before re-querying a hostinfo to the lighthouse
const defaultReQueryWait = time.Minute // Minimum amount of seconds to wait before re-querying a hostinfo the lighthouse. Evaluated every ReQueryEvery
const MaxRemotes = 10

// MaxHostInfosPerVpnIp is the max number of hostinfos we will track for a given vpn ip
// 5 allows for an initial handshake and each host pair re-handshaking twice
const MaxHostInfosPerVpnIp = 5

// How long we should prevent roaming back to the previous IP.
// This helps prevent flapping due to packets already in flight
const RoamingSuppressSeconds = 2

const (
	Requested = iota
	PeerRequested
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
	Indexes         map[uint32]*HostInfo
	Relays          map[uint32]*HostInfo // Maps a Relay IDX to a Relay HostInfo object
	RemoteIndexes   map[uint32]*HostInfo
	Hosts           map[iputil.VpnIp]*HostInfo
	preferredRanges []*net.IPNet
	vpnCIDR         *net.IPNet
	metricsEnabled  bool
	l               *logrus.Logger
}

// For synchronization, treat the pointed-to Relay struct as immutable. To edit the Relay
// struct, make a copy of an existing value, edit the fileds in the copy, and
// then store a pointer to the new copy in both realyForBy* maps.
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

func (rs *RelayState) CopyAllRelayFor() []*Relay {
	rs.RLock()
	defer rs.RUnlock()
	ret := make([]*Relay, 0, len(rs.relayForByIdx))
	for _, r := range rs.relayForByIdx {
		ret = append(ret, r)
	}
	return ret
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
	r, ok := rs.relayForByIdx[localIdx]
	if !ok {
		return iputil.VpnIp(0), false
	}
	delete(rs.relayForByIdx, localIdx)
	delete(rs.relayForByIp, r.PeerIp)
	return r.PeerIp, true
}

func (rs *RelayState) CompleteRelayByIP(vpnIp iputil.VpnIp, remoteIdx uint32) bool {
	rs.Lock()
	defer rs.Unlock()
	r, ok := rs.relayForByIp[vpnIp]
	if !ok {
		return false
	}
	newRelay := *r
	newRelay.State = Established
	newRelay.RemoteIndex = remoteIdx
	rs.relayForByIdx[r.LocalIndex] = &newRelay
	rs.relayForByIp[r.PeerIp] = &newRelay
	return true
}

func (rs *RelayState) CompleteRelayByIdx(localIdx uint32, remoteIdx uint32) (*Relay, bool) {
	rs.Lock()
	defer rs.Unlock()
	r, ok := rs.relayForByIdx[localIdx]
	if !ok {
		return nil, false
	}
	newRelay := *r
	newRelay.State = Established
	newRelay.RemoteIndex = remoteIdx
	rs.relayForByIdx[r.LocalIndex] = &newRelay
	rs.relayForByIp[r.PeerIp] = &newRelay
	return &newRelay, true
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

	remote               *udp.Addr
	remotes              *RemoteList
	promoteCounter       atomic.Uint32
	ConnectionState      *ConnectionState
	handshakeStart       time.Time   //todo: this an entry in the handshake manager
	HandshakeReady       bool        //todo: being in the manager means you are ready
	HandshakeCounter     int         //todo: another handshake manager entry
	HandshakeLastRemotes []*udp.Addr //todo: another handshake manager entry, which remotes we sent to last time
	HandshakeComplete    bool        //todo: this should go away in favor of ConnectionState.ready
	HandshakePacket      map[uint8][]byte
	packetStore          []*cachedPacket //todo: this is other handshake manager entry
	remoteIndexId        uint32
	localIndexId         uint32
	vpnIp                iputil.VpnIp
	recvError            int
	remoteCidr           *cidr.Tree4
	relayState           RelayState

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

func NewHostMap(l *logrus.Logger, vpnCIDR *net.IPNet, preferredRanges []*net.IPNet) *HostMap {
	h := map[iputil.VpnIp]*HostInfo{}
	i := map[uint32]*HostInfo{}
	r := map[uint32]*HostInfo{}
	relays := map[uint32]*HostInfo{}
	m := HostMap{
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

// EmitStats reports host, index, and relay counts to the stats collection system
func (hm *HostMap) EmitStats() {
	hm.RLock()
	hostLen := len(hm.Hosts)
	indexLen := len(hm.Indexes)
	remoteIndexLen := len(hm.RemoteIndexes)
	relaysLen := len(hm.Relays)
	hm.RUnlock()

	metrics.GetOrRegisterGauge("hostmap.main.hosts", nil).Update(int64(hostLen))
	metrics.GetOrRegisterGauge("hostmap.main.indexes", nil).Update(int64(indexLen))
	metrics.GetOrRegisterGauge("hostmap.main.remoteIndexes", nil).Update(int64(remoteIndexLen))
	metrics.GetOrRegisterGauge("hostmap.main.relayIndexes", nil).Update(int64(relaysLen))
}

func (hm *HostMap) RemoveRelay(localIdx uint32) {
	hm.Lock()
	_, ok := hm.Relays[localIdx]
	if !ok {
		hm.Unlock()
		return
	}
	delete(hm.Relays, localIdx)
	hm.Unlock()
}

// DeleteHostInfo will fully unlink the hostinfo and return true if it was the final hostinfo for this vpn ip
func (hm *HostMap) DeleteHostInfo(hostinfo *HostInfo) bool {
	// Delete the host itself, ensuring it's not modified anymore
	hm.Lock()
	// If we have a previous or next hostinfo then we are not the last one for this vpn ip
	final := (hostinfo.next == nil && hostinfo.prev == nil)
	hm.unlockedDeleteHostInfo(hostinfo)
	hm.Unlock()

	return final
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
		hm.l.WithField("hostMap", m{"mapTotalSize": len(hm.Hosts),
			"vpnIp": hostinfo.vpnIp, "indexNumber": hostinfo.localIndexId, "remoteIndexNumber": hostinfo.remoteIndexId}).
			Debug("Hostmap hostInfo deleted")
	}

	for _, localRelayIdx := range hostinfo.relayState.CopyRelayForIdxs() {
		delete(hm.Relays, localRelayIdx)
	}
}

func (hm *HostMap) QueryIndex(index uint32) *HostInfo {
	hm.RLock()
	if h, ok := hm.Indexes[index]; ok {
		hm.RUnlock()
		return h
	} else {
		hm.RUnlock()
		return nil
	}
}

func (hm *HostMap) QueryRelayIndex(index uint32) *HostInfo {
	//TODO: we probably just want to return bool instead of error, or at least a static error
	hm.RLock()
	if h, ok := hm.Relays[index]; ok {
		hm.RUnlock()
		return h
	} else {
		hm.RUnlock()
		return nil
	}
}

func (hm *HostMap) QueryReverseIndex(index uint32) *HostInfo {
	hm.RLock()
	if h, ok := hm.RemoteIndexes[index]; ok {
		hm.RUnlock()
		return h
	} else {
		hm.RUnlock()
		return nil
	}
}

func (hm *HostMap) QueryVpnIp(vpnIp iputil.VpnIp) *HostInfo {
	return hm.queryVpnIp(vpnIp, nil)
}

func (hm *HostMap) QueryVpnIpRelayFor(targetIp, relayHostIp iputil.VpnIp) (*HostInfo, *Relay, error) {
	hm.RLock()
	defer hm.RUnlock()

	h, ok := hm.Hosts[relayHostIp]
	if !ok {
		return nil, nil, errors.New("unable to find host")
	}
	for h != nil {
		r, ok := h.relayState.QueryRelayForByIp(targetIp)
		if ok && r.State == Established {
			return h, r, nil
		}
		h = h.next
	}
	return nil, nil, errors.New("unable to find host with relay")
}

// PromoteBestQueryVpnIp will attempt to lazily switch to the best remote every
// `PromoteEvery` calls to this function for a given host.
func (hm *HostMap) PromoteBestQueryVpnIp(vpnIp iputil.VpnIp, ifce *Interface) *HostInfo {
	return hm.queryVpnIp(vpnIp, ifce)
}

func (hm *HostMap) queryVpnIp(vpnIp iputil.VpnIp, promoteIfce *Interface) *HostInfo {
	hm.RLock()
	if h, ok := hm.Hosts[vpnIp]; ok {
		hm.RUnlock()
		// Do not attempt promotion if you are a lighthouse
		if promoteIfce != nil && !promoteIfce.lightHouse.amLighthouse {
			h.TryPromoteBest(hm.preferredRanges, promoteIfce)
		}
		return h

	}

	hm.RUnlock()
	return nil
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
		hm.l.WithField("hostMap", m{"vpnIp": hostinfo.vpnIp, "mapTotalSize": len(hm.Hosts),
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

func (hm *HostMap) GetPreferredRanges() []*net.IPNet {
	return hm.preferredRanges
}

func (hm *HostMap) ForEachVpnIp(f controlEach) {
	hm.RLock()
	defer hm.RUnlock()

	for _, v := range hm.Hosts {
		f(v)
	}
}

func (hm *HostMap) ForEachIndex(f controlEach) {
	hm.RLock()
	defer hm.RUnlock()

	for _, v := range hm.Indexes {
		f(v)
	}
}

// TryPromoteBest handles re-querying lighthouses and probing for better paths
// NOTE: It is an error to call this if you are a lighthouse since they should not roam clients!
func (i *HostInfo) TryPromoteBest(preferredRanges []*net.IPNet, ifce *Interface) {
	c := i.promoteCounter.Add(1)
	if c%ifce.tryPromoteEvery.Load() == 0 {
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
	if c%ifce.reQueryEvery.Load() == 0 && ifce.lightHouse != nil {
		now := time.Now().UnixNano()
		if now < i.nextLHQuery.Load() {
			return
		}

		i.nextLHQuery.Store(now + ifce.reQueryWait.Load())
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
