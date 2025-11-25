package nebula

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
)

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
	Disestablished
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
	PeerAddr    netip.Addr
}

type HostMap struct {
	sync.RWMutex    //Because we concurrently read and write to our maps
	Indexes         map[uint32]*HostInfo
	Relays          map[uint32]*HostInfo // Maps a Relay IDX to a Relay HostInfo object
	RemoteIndexes   map[uint32]*HostInfo
	Hosts           map[netip.Addr]*HostInfo
	preferredRanges atomic.Pointer[[]netip.Prefix]
	l               *logrus.Logger
}

// For synchronization, treat the pointed-to Relay struct as immutable. To edit the Relay
// struct, make a copy of an existing value, edit the fileds in the copy, and
// then store a pointer to the new copy in both realyForBy* maps.
type RelayState struct {
	sync.RWMutex

	relays []netip.Addr // Ordered set of VpnAddrs of Hosts to use as relays to access this peer
	// For data race avoidance, the contents of a *Relay are treated immutably. To update a *Relay, copy the existing data,
	// modify what needs to be updated, and store the new modified copy in the relayForByIp and relayForByIdx maps (with
	// the RelayState Lock held)
	relayForByAddr map[netip.Addr]*Relay // Maps vpnAddr of peers for which this HostInfo is a relay to some Relay info
	relayForByIdx  map[uint32]*Relay     // Maps a local index to some Relay info
}

func (rs *RelayState) DeleteRelay(ip netip.Addr) {
	rs.Lock()
	defer rs.Unlock()
	for idx, val := range rs.relays {
		if val == ip {
			rs.relays = append(rs.relays[:idx], rs.relays[idx+1:]...)
			return
		}
	}
}

func (rs *RelayState) UpdateRelayForByIpState(vpnIp netip.Addr, state int) {
	rs.Lock()
	defer rs.Unlock()
	if r, ok := rs.relayForByAddr[vpnIp]; ok {
		newRelay := *r
		newRelay.State = state
		rs.relayForByAddr[newRelay.PeerAddr] = &newRelay
		rs.relayForByIdx[newRelay.LocalIndex] = &newRelay
	}
}

func (rs *RelayState) UpdateRelayForByIdxState(idx uint32, state int) {
	rs.Lock()
	defer rs.Unlock()
	if r, ok := rs.relayForByIdx[idx]; ok {
		newRelay := *r
		newRelay.State = state
		rs.relayForByAddr[newRelay.PeerAddr] = &newRelay
		rs.relayForByIdx[newRelay.LocalIndex] = &newRelay
	}
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

func (rs *RelayState) GetRelayForByAddr(addr netip.Addr) (*Relay, bool) {
	rs.RLock()
	defer rs.RUnlock()
	r, ok := rs.relayForByAddr[addr]
	return r, ok
}

func (rs *RelayState) InsertRelayTo(ip netip.Addr) {
	rs.Lock()
	defer rs.Unlock()
	if !slices.Contains(rs.relays, ip) {
		rs.relays = append(rs.relays, ip)
	}
}

func (rs *RelayState) CopyRelayIps() []netip.Addr {
	ret := make([]netip.Addr, len(rs.relays))
	rs.RLock()
	defer rs.RUnlock()
	copy(ret, rs.relays)
	return ret
}

func (rs *RelayState) CopyRelayForIps() []netip.Addr {
	rs.RLock()
	defer rs.RUnlock()
	currentRelays := make([]netip.Addr, 0, len(rs.relayForByAddr))
	for relayIp := range rs.relayForByAddr {
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

func (rs *RelayState) CompleteRelayByIP(vpnIp netip.Addr, remoteIdx uint32) bool {
	rs.Lock()
	defer rs.Unlock()
	r, ok := rs.relayForByAddr[vpnIp]
	if !ok {
		return false
	}
	newRelay := *r
	newRelay.State = Established
	newRelay.RemoteIndex = remoteIdx
	rs.relayForByIdx[r.LocalIndex] = &newRelay
	rs.relayForByAddr[r.PeerAddr] = &newRelay
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
	rs.relayForByAddr[r.PeerAddr] = &newRelay
	return &newRelay, true
}

func (rs *RelayState) QueryRelayForByIp(vpnIp netip.Addr) (*Relay, bool) {
	rs.RLock()
	defer rs.RUnlock()
	r, ok := rs.relayForByAddr[vpnIp]
	return r, ok
}

func (rs *RelayState) QueryRelayForByIdx(idx uint32) (*Relay, bool) {
	rs.RLock()
	defer rs.RUnlock()
	r, ok := rs.relayForByIdx[idx]
	return r, ok
}

func (rs *RelayState) InsertRelay(ip netip.Addr, idx uint32, r *Relay) {
	rs.Lock()
	defer rs.Unlock()
	rs.relayForByAddr[ip] = r
	rs.relayForByIdx[idx] = r
}

type NetworkType uint8

const (
	NetworkTypeUnknown NetworkType = iota
	// NetworkTypeVPN is a network that overlaps one or more of the vpnNetworks in our certificate
	NetworkTypeVPN
	// NetworkTypeVPNPeer is a network that does not overlap one of our networks
	NetworkTypeVPNPeer
	// NetworkTypeUnsafe is a network from Certificate.UnsafeNetworks()
	NetworkTypeUnsafe
)

type HostInfo struct {
	remote          netip.AddrPort
	remotes         *RemoteList
	promoteCounter  atomic.Uint32
	ConnectionState *ConnectionState
	remoteIndexId   uint32
	localIndexId    uint32

	// vpnAddrs is a list of vpn addresses assigned to this host that are within our own vpn networks
	// The host may have other vpn addresses that are outside our
	// vpn networks but were removed because they are not usable
	vpnAddrs []netip.Addr

	// networks is a combination of specific vpn addresses (not prefixes!) and full unsafe networks assigned to this host.
	networks   *bart.Table[NetworkType]
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

	//TODO: in, out, and others might benefit from being an atomic.Int32. We could collapse connectionManager pendingDeletion, relayUsed, and in/out into this 1 thing
	in, out, pendingDeletion atomic.Bool

	// lastUsed tracks the last time ConnectionManager checked the tunnel and it was in use.
	// This value will be behind against actual tunnel utilization in the hot path.
	// This should only be used by the ConnectionManagers ticker routine.
	lastUsed time.Time
}

type ViaSender struct {
	UdpAddr   netip.AddrPort
	relayHI   *HostInfo // relayHI is the host info object of the relay
	remoteIdx uint32    // remoteIdx is the index included in the header of the received packet
	relay     *Relay    // relay contains the rest of the relay information, including the PeerIP of the host trying to communicate with us.
	IsRelayed bool      // IsRelayed is true if the packet was sent through a relay
}

func (v ViaSender) String() string {
	if v.IsRelayed {
		return fmt.Sprintf("%s (relayed)", v.UdpAddr)
	}
	return v.UdpAddr.String()
}

func (v ViaSender) MarshalJSON() ([]byte, error) {
	if v.IsRelayed {
		return json.Marshal(m{"relay": v.UdpAddr})
	}
	return json.Marshal(m{"direct": v.UdpAddr})
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

func NewHostMapFromConfig(l *logrus.Logger, c *config.C) *HostMap {
	hm := newHostMap(l)

	hm.reload(c, true)
	c.RegisterReloadCallback(func(c *config.C) {
		hm.reload(c, false)
	})

	l.WithField("preferredRanges", hm.GetPreferredRanges()).
		Info("Main HostMap created")

	return hm
}

func newHostMap(l *logrus.Logger) *HostMap {
	return &HostMap{
		Indexes:       map[uint32]*HostInfo{},
		Relays:        map[uint32]*HostInfo{},
		RemoteIndexes: map[uint32]*HostInfo{},
		Hosts:         map[netip.Addr]*HostInfo{},
		l:             l,
	}
}

func (hm *HostMap) reload(c *config.C, initial bool) {
	if initial || c.HasChanged("preferred_ranges") {
		var preferredRanges []netip.Prefix
		rawPreferredRanges := c.GetStringSlice("preferred_ranges", []string{})

		for _, rawPreferredRange := range rawPreferredRanges {
			preferredRange, err := netip.ParsePrefix(rawPreferredRange)

			if err != nil {
				hm.l.WithError(err).WithField("range", rawPreferredRanges).Warn("Failed to parse preferred ranges, ignoring")
				continue
			}

			preferredRanges = append(preferredRanges, preferredRange)
		}

		oldRanges := hm.preferredRanges.Swap(&preferredRanges)
		if !initial {
			hm.l.WithField("oldPreferredRanges", *oldRanges).WithField("newPreferredRanges", preferredRanges).Info("preferred_ranges changed")
		}
	}
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
	// Get the current primary, if it exists
	oldHostinfo := hm.Hosts[hostinfo.vpnAddrs[0]]

	// Every address in the hostinfo gets elevated to primary
	for _, vpnAddr := range hostinfo.vpnAddrs {
		//NOTE: It is possible that we leave a dangling hostinfo here but connection manager works on
		// indexes so it should be fine.
		hm.Hosts[vpnAddr] = hostinfo
	}

	// If we are already primary then we won't bother re-linking
	if oldHostinfo == hostinfo {
		return
	}

	// Unlink this hostinfo
	if hostinfo.prev != nil {
		hostinfo.prev.next = hostinfo.next
	}
	if hostinfo.next != nil {
		hostinfo.next.prev = hostinfo.prev
	}

	// If there wasn't a previous primary then clear out any links
	if oldHostinfo == nil {
		hostinfo.next = nil
		hostinfo.prev = nil
		return
	}

	// Relink the hostinfo as primary
	hostinfo.next = oldHostinfo
	oldHostinfo.prev = hostinfo
	hostinfo.prev = nil
}

func (hm *HostMap) unlockedDeleteHostInfo(hostinfo *HostInfo) {
	for _, addr := range hostinfo.vpnAddrs {
		h := hm.Hosts[addr]
		for h != nil {
			if h == hostinfo {
				hm.unlockedInnerDeleteHostInfo(h, addr)
			}
			h = h.next
		}
	}
}

func (hm *HostMap) unlockedInnerDeleteHostInfo(hostinfo *HostInfo, addr netip.Addr) {
	primary, ok := hm.Hosts[addr]
	isLastHostinfo := hostinfo.next == nil && hostinfo.prev == nil
	if ok && primary == hostinfo {
		// The vpn addr pointer points to the same hostinfo as the local index id, we can remove it
		delete(hm.Hosts, addr)
		if len(hm.Hosts) == 0 {
			hm.Hosts = map[netip.Addr]*HostInfo{}
		}

		if hostinfo.next != nil {
			// We had more than 1 hostinfo at this vpn addr, promote the next in the list to primary
			hm.Hosts[addr] = hostinfo.next
			// It is primary, there is no previous hostinfo now
			hostinfo.next.prev = nil
		}

	} else {
		// Relink if we were in the middle of multiple hostinfos for this vpn addr
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
			"vpnAddrs": hostinfo.vpnAddrs, "indexNumber": hostinfo.localIndexId, "remoteIndexNumber": hostinfo.remoteIndexId}).
			Debug("Hostmap hostInfo deleted")
	}

	if isLastHostinfo {
		// I have lost connectivity to my peers. My relay tunnel is likely broken. Mark the next
		// hops as 'Requested' so that new relay tunnels are created in the future.
		hm.unlockedDisestablishVpnAddrRelayFor(hostinfo)
	}
	// Clean up any local relay indexes for which I am acting as a relay hop
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

func (hm *HostMap) QueryVpnAddr(vpnIp netip.Addr) *HostInfo {
	return hm.queryVpnAddr(vpnIp, nil)
}

func (hm *HostMap) QueryVpnAddrsRelayFor(targetIps []netip.Addr, relayHostIp netip.Addr) (*HostInfo, *Relay, error) {
	hm.RLock()
	defer hm.RUnlock()

	h, ok := hm.Hosts[relayHostIp]
	if !ok {
		return nil, nil, errors.New("unable to find host")
	}

	for h != nil {
		for _, targetIp := range targetIps {
			r, ok := h.relayState.QueryRelayForByIp(targetIp)
			if ok && r.State == Established {
				return h, r, nil
			}
		}
		h = h.next
	}

	return nil, nil, errors.New("unable to find host with relay")
}

func (hm *HostMap) unlockedDisestablishVpnAddrRelayFor(hi *HostInfo) {
	for _, relayHostIp := range hi.relayState.CopyRelayIps() {
		if h, ok := hm.Hosts[relayHostIp]; ok {
			for h != nil {
				h.relayState.UpdateRelayForByIpState(hi.vpnAddrs[0], Disestablished)
				h = h.next
			}
		}
	}
	for _, rs := range hi.relayState.CopyAllRelayFor() {
		if rs.Type == ForwardingType {
			if h, ok := hm.Hosts[rs.PeerAddr]; ok {
				for h != nil {
					h.relayState.UpdateRelayForByIpState(hi.vpnAddrs[0], Disestablished)
					h = h.next
				}
			}
		}
	}
}

func (hm *HostMap) queryVpnAddr(vpnIp netip.Addr, promoteIfce *Interface) *HostInfo {
	hm.RLock()
	if h, ok := hm.Hosts[vpnIp]; ok {
		hm.RUnlock()
		// Do not attempt promotion if you are a lighthouse
		if promoteIfce != nil && !promoteIfce.lightHouse.amLighthouse {
			h.TryPromoteBest(hm.GetPreferredRanges(), promoteIfce)
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
		dnsR.Add(remoteCert.Certificate.Name()+".", hostinfo.vpnAddrs)
	}
	for _, addr := range hostinfo.vpnAddrs {
		hm.unlockedInnerAddHostInfo(addr, hostinfo, f)
	}

	hm.Indexes[hostinfo.localIndexId] = hostinfo
	hm.RemoteIndexes[hostinfo.remoteIndexId] = hostinfo

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"vpnAddrs": hostinfo.vpnAddrs, "mapTotalSize": len(hm.Hosts),
			"hostinfo": m{"existing": true, "localIndexId": hostinfo.localIndexId, "vpnAddrs": hostinfo.vpnAddrs}}).
			Debug("Hostmap vpnIp added")
	}
}

func (hm *HostMap) unlockedInnerAddHostInfo(vpnAddr netip.Addr, hostinfo *HostInfo, f *Interface) {
	existing := hm.Hosts[vpnAddr]
	hm.Hosts[vpnAddr] = hostinfo

	if existing != nil && existing != hostinfo {
		hostinfo.next = existing
		existing.prev = hostinfo
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

func (hm *HostMap) GetPreferredRanges() []netip.Prefix {
	//NOTE: if preferredRanges is ever not stored before a load this will fail to dereference a nil pointer
	return *hm.preferredRanges.Load()
}

func (hm *HostMap) ForEachVpnAddr(f controlEach) {
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

// TODO: Maybe use ViaSender here?
func (i *HostInfo) SetRemote(remote netip.AddrPort) {
	// We copy here because we likely got this remote from a source that reuses the object
	if i.remote != remote {
		i.remote = remote
		i.remotes.LearnRemote(i.vpnAddrs[0], remote)
	}
}

// SetRemoteIfPreferred returns true if the remote was changed. The lastRoam
// time on the HostInfo will also be updated.
func (i *HostInfo) SetRemoteIfPreferred(hm *HostMap, via ViaSender) bool {
	if via.IsRelayed {
		return false
	}

	currentRemote := i.remote
	if !currentRemote.IsValid() {
		i.SetRemote(via.UdpAddr)
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

		if l.Contains(via.UdpAddr.Addr()) {
			newIsPreferred = true
		}
	}

	if newIsPreferred {
		// Consider this a roaming event
		i.lastRoam = time.Now()
		i.lastRoamRemote = currentRemote

		i.SetRemote(via.UdpAddr)

		return true
	}

	return false
}

// buildNetworks fills in the networks field of HostInfo. It accepts a cert.Certificate so you never ever mix the network types up.
func (i *HostInfo) buildNetworks(myVpnNetworksTable *bart.Lite, c cert.Certificate) {
	if len(c.Networks()) == 1 && len(c.UnsafeNetworks()) == 0 {
		if myVpnNetworksTable.Contains(c.Networks()[0].Addr()) {
			return // Simple case, no BART needed
		}
	}

	i.networks = new(bart.Table[NetworkType])
	for _, network := range c.Networks() {
		nprefix := netip.PrefixFrom(network.Addr(), network.Addr().BitLen())
		if myVpnNetworksTable.Contains(network.Addr()) {
			i.networks.Insert(nprefix, NetworkTypeVPN)
		} else {
			i.networks.Insert(nprefix, NetworkTypeVPNPeer)
		}
	}

	for _, network := range c.UnsafeNetworks() {
		i.networks.Insert(network, NetworkTypeUnsafe)
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

// Utility functions

func localAddrs(l *logrus.Logger, allowList *LocalAllowList) []netip.Addr {
	//FIXME: This function is pretty garbage
	var finalAddrs []netip.Addr
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
		for _, rawAddr := range addrs {
			var addr netip.Addr
			switch v := rawAddr.(type) {
			case *net.IPNet:
				//continue
				addr, _ = netip.AddrFromSlice(v.IP)
			case *net.IPAddr:
				addr, _ = netip.AddrFromSlice(v.IP)
			}

			if !addr.IsValid() {
				if l.Level >= logrus.DebugLevel {
					l.WithField("localAddr", rawAddr).Debug("addr was invalid")
				}
				continue
			}
			addr = addr.Unmap()

			if addr.IsLoopback() == false && addr.IsLinkLocalUnicast() == false {
				isAllowed := allowList.Allow(addr)
				if l.Level >= logrus.TraceLevel {
					l.WithField("localAddr", addr).WithField("allowed", isAllowed).Trace("localAllowList.Allow")
				}
				if !isAllowed {
					continue
				}

				finalAddrs = append(finalAddrs, addr)
			}
		}
	}
	return finalAddrs
}
