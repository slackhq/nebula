package nebula

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/logging"
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
	sync.RWMutex  //Because we concurrently read and write to our maps
	Indexes       map[uint32]*HostInfo
	Relays        map[uint32]*HostInfo // Maps a Relay IDX to a Relay HostInfo object
	RemoteIndexes map[uint32]*HostInfo
	// Hosts maps a vpn address to its primary hostinfo, one entry per address we hold a tunnel
	// for. moreHosts only has an entry while an address is held by 2 or more hostinfos and stores
	// the full most-recent-first list; moreHosts[a][0] is always the same hostinfo as Hosts[a].
	// Each address gets its own independent list, so a hostinfo owning multiple addresses can
	// never corrupt another address's ordering the way the old shared next/prev chain could.
	// Entries in moreHosts are only ever written by unlockedSetHostsForAddr; Hosts is written
	// directly only in the single-hostinfo fast paths where moreHosts is known to have no entry,
	// and unlockedDeleteHostInfo swaps either map for a fresh one when it fully drains.
	Hosts           map[netip.Addr]*HostInfo
	moreHosts       map[netip.Addr][]*HostInfo
	preferredRanges atomic.Pointer[[]netip.Prefix]
	l               *slog.Logger
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
	rs.RLock()
	defer rs.RUnlock()
	ret := make([]netip.Addr, len(rs.relays))
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
	remote          atomic.Pointer[netip.AddrPort]
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

func NewHostMapFromConfig(l *slog.Logger, c *config.C) *HostMap {
	hm := newHostMap(l)

	hm.reload(c, true)
	c.RegisterReloadCallback(func(c *config.C) {
		hm.reload(c, false)
	})

	l.Info("Main HostMap created", "preferredRanges", hm.GetPreferredRanges())

	return hm
}

func newHostMap(l *slog.Logger) *HostMap {
	return &HostMap{
		Indexes:       map[uint32]*HostInfo{},
		Relays:        map[uint32]*HostInfo{},
		RemoteIndexes: map[uint32]*HostInfo{},
		Hosts:         map[netip.Addr]*HostInfo{},
		moreHosts:     map[netip.Addr][]*HostInfo{},
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
				hm.l.Warn("Failed to parse preferred ranges, ignoring",
					"error", err,
					"range", rawPreferredRanges,
				)
				continue
			}

			preferredRanges = append(preferredRanges, preferredRange)
		}

		oldRanges := hm.preferredRanges.Swap(&preferredRanges)
		if !initial {
			hm.l.Info("preferred_ranges changed",
				"oldPreferredRanges", *oldRanges,
				"newPreferredRanges", preferredRanges,
			)
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

// unlockedSetHostsForAddr stores the per-address hostinfo list (list[0] is the primary). An empty
// list removes the address. This is the one place Hosts and moreHosts are written together, keep
// it that way. Callers must hold the write lock.
func (hm *HostMap) unlockedSetHostsForAddr(addr netip.Addr, list []*HostInfo) {
	if len(list) == 0 {
		delete(hm.Hosts, addr)
		delete(hm.moreHosts, addr)
		return
	}
	hm.Hosts[addr] = list[0]
	if len(list) > 1 {
		hm.moreHosts[addr] = list
	} else {
		delete(hm.moreHosts, addr)
	}
}

// unlockedGetHostList returns every hostinfo holding addr, primary first, or nil if we have no
// tunnel for addr. The common single-hostinfo case builds a fresh one element list, so keep this
// off the packet hot path; the primary is a direct Hosts read. Callers must hold the lock (read
// or write).
func (hm *HostMap) unlockedGetHostList(addr netip.Addr) []*HostInfo {
	if list, ok := hm.moreHosts[addr]; ok {
		return list
	}
	if h, ok := hm.Hosts[addr]; ok {
		return []*HostInfo{h}
	}
	return nil
}

// removeHostInfo returns list with hi removed (order preserved), or list unchanged if hi is
// absent. It deletes in place: every mutator holds the hostmap write lock and no reader ever
// retains a slice across a mutation (readers iterate under RLock), so there is no snapshot to
// invalidate.
func removeHostInfo(list []*HostInfo, hi *HostInfo) []*HostInfo {
	idx := slices.Index(list, hi)
	if idx < 0 {
		return list
	}
	return slices.Delete(list, idx, idx+1)
}

// DeleteHostInfo will fully unlink the hostinfo and return true if no other hostinfo still holds
// any of its vpn addrs, meaning we no longer have a tunnel to the peer
func (hm *HostMap) DeleteHostInfo(hostinfo *HostInfo) bool {
	// Delete the host itself, ensuring it's not modified anymore
	hm.Lock()
	final := hm.unlockedDeleteHostInfo(hostinfo)
	hm.Unlock()

	return final
}

func (hm *HostMap) MakePrimary(hostinfo *HostInfo) {
	hm.Lock()
	defer hm.Unlock()
	hm.unlockedMakePrimary(hostinfo)
}

// unlockedMakePrimary reports whether hostinfo is (now) the primary for each of its addresses,
// false only when it is no longer in the hostmap at all.
func (hm *HostMap) unlockedMakePrimary(hostinfo *HostInfo) bool {
	// A hostinfo that is no longer in the hostmap must not be re-inserted here. Callers can race
	// tunnel teardown, deciding to promote under the read lock and only taking the write lock
	// after a delete fully unlinked the hostinfo (connection manager swapPrimary, AddRelay). Every
	// live hostinfo is registered in Indexes by unlockedAddHostInfo, so this is a membership test.
	if hm.Indexes[hostinfo.localIndexId] != hostinfo {
		return false
	}

	// Move hostinfo to the front (primary) of each of its address lists. The lists are
	// independent per address, so this can never leave a dangling entry the way promoting
	// against a single shared chain could.
	for _, addr := range hostinfo.vpnAddrs {
		if hm.Hosts[addr] == hostinfo {
			// Already primary for this address, the list is already in the right order
			continue
		}
		list := removeHostInfo(hm.unlockedGetHostList(addr), hostinfo)
		list = append([]*HostInfo{hostinfo}, list...)
		hm.unlockedSetHostsForAddr(addr, list)
	}
	return true
}

// unlockedDeleteHostInfo removes hostinfo from every one of its address lists and from the index
// maps. It returns true if this was the last hostinfo for all of its addresses (we no longer have
// any tunnel to the peer), which the caller uses to decide whether to clear learned lighthouse
// state and disestablish relays.
func (hm *HostMap) unlockedDeleteHostInfo(hostinfo *HostInfo) bool {
	// Remove this hostinfo from each of its address lists. The lists are independent, so a
	// sibling is never promoted to an address it does not own and no other list is touched.
	final := true
	for _, addr := range hostinfo.vpnAddrs {
		if list, ok := hm.moreHosts[addr]; ok {
			list = removeHostInfo(list, hostinfo)
			hm.unlockedSetHostsForAddr(addr, list)
			if len(list) > 0 {
				final = false
			}
		} else if existing, ok := hm.Hosts[addr]; ok {
			if existing == hostinfo {
				// Common case, the only hostinfo for this address. moreHosts has no entry to clean up.
				delete(hm.Hosts, addr)
			} else {
				// We don't hold this address but another hostinfo does, we still have a tunnel to the peer
				final = false
			}
		}
	}

	// Go maps never shrink their buckets, replace fully drained maps so a node that churned
	// through a large peer count gives the memory back. Same idiom as the index maps below.
	if len(hm.Hosts) == 0 {
		hm.Hosts = map[netip.Addr]*HostInfo{}
	}
	if len(hm.moreHosts) == 0 {
		hm.moreHosts = map[netip.Addr][]*HostInfo{}
	}

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

	if hm.l.Enabled(context.Background(), slog.LevelDebug) {
		hm.l.Debug("Hostmap hostInfo deleted",
			"hostMap", m{"mapTotalSize": len(hm.Hosts),
				"vpnAddrs": hostinfo.vpnAddrs, "indexNumber": hostinfo.localIndexId, "remoteIndexNumber": hostinfo.remoteIndexId},
		)
	}

	if final {
		// I have lost connectivity to my peers. My relay tunnel is likely broken. Mark the next
		// hops as 'Requested' so that new relay tunnels are created in the future.
		hm.unlockedDisestablishVpnAddrRelayFor(hostinfo)
	}
	// Clean up any local relay indexes for which I am acting as a relay hop
	for _, localRelayIdx := range hostinfo.relayState.CopyRelayForIdxs() {
		delete(hm.Relays, localRelayIdx)
	}

	return final
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

	// This runs per relayed packet, so check the primary with a single map probe and only consult
	// moreHosts when the primary can't relay for us.
	h, ok := hm.Hosts[relayHostIp]
	if !ok {
		return nil, nil, errors.New("unable to find host")
	}

	for _, targetIp := range targetIps {
		r, ok := h.relayState.QueryRelayForByIp(targetIp)
		if ok && r.State == Established {
			return h, r, nil
		}
	}

	if list, ok := hm.moreHosts[relayHostIp]; ok {
		// list[0] is the primary we already checked
		for _, h := range list[1:] {
			for _, targetIp := range targetIps {
				r, ok := h.relayState.QueryRelayForByIp(targetIp)
				if ok && r.State == Established {
					return h, r, nil
				}
			}
		}
	}

	return nil, nil, errors.New("unable to find host with relay")
}

func (hm *HostMap) unlockedDisestablishVpnAddrRelayFor(hi *HostInfo) {
	for _, relayHostIp := range hi.relayState.CopyRelayIps() {
		for _, h := range hm.unlockedGetHostList(relayHostIp) {
			h.relayState.UpdateRelayForByIpState(hi.vpnAddrs[0], Disestablished)
		}
	}
	for _, rs := range hi.relayState.CopyAllRelayFor() {
		if rs.Type == ForwardingType {
			for _, h := range hm.unlockedGetHostList(rs.PeerAddr) {
				h.relayState.UpdateRelayForByIpState(hi.vpnAddrs[0], Disestablished)
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
	if f.dnsServer != nil {
		remoteCert := hostinfo.ConnectionState.peerCert
		f.dnsServer.Add(remoteCert.Certificate.Name()+".", hostinfo.vpnAddrs)
	}
	for _, addr := range hostinfo.vpnAddrs {
		hm.unlockedInnerAddHostInfo(addr, hostinfo, f)
	}

	hm.Indexes[hostinfo.localIndexId] = hostinfo
	hm.RemoteIndexes[hostinfo.remoteIndexId] = hostinfo

	hostinfo.out.Store(true)
	if f.connectionManager != nil { // f.connectionManager is only nil in some unit tests
		f.connectionManager.trafficTimer.Add(hostinfo.localIndexId, f.connectionManager.checkInterval)
	}

	if hm.l.Enabled(context.Background(), slog.LevelDebug) {
		hm.l.Debug("Hostmap vpnIp added",
			"hostMap", m{"vpnAddrs": hostinfo.vpnAddrs, "mapTotalSize": len(hm.Hosts),
				"hostinfo": m{"existing": true, "localIndexId": hostinfo.localIndexId, "vpnAddrs": hostinfo.vpnAddrs}},
		)
	}
}

func (hm *HostMap) unlockedInnerAddHostInfo(vpnAddr netip.Addr, hostinfo *HostInfo, f *Interface) {
	existing, ok := hm.Hosts[vpnAddr]
	if !ok {
		// Common case, the first hostinfo for this address. moreHosts stays empty.
		hm.Hosts[vpnAddr] = hostinfo
		return
	}

	// The new hostinfo becomes the primary for this address. Remove any stale copy of it first so
	// we never hold a duplicate, then prepend.
	list, ok := hm.moreHosts[vpnAddr]
	if !ok {
		list = []*HostInfo{existing}
	}
	list = removeHostInfo(list, hostinfo)
	list = append([]*HostInfo{hostinfo}, list...)
	hm.unlockedSetHostsForAddr(vpnAddr, list)

	// Enforce the per-address cap by fully retiring the oldest hostinfo once we exceed it.
	// Deleting it removes it from all of its addresses and the index maps, matching prior behavior.
	if len(list) > MaxHostInfosPerVpnIp {
		hm.unlockedDeleteHostInfo(list[len(list)-1])
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
		remote := i.GetRemote()

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

func (i *HostInfo) GetRemote() netip.AddrPort {
	if p := i.remote.Load(); p != nil {
		return *p
	}
	return netip.AddrPort{}
}

// TODO: Maybe use ViaSender here?
func (i *HostInfo) SetRemote(remote netip.AddrPort) {
	// We copy here because we likely got this remote from a source that reuses the object
	if i.GetRemote() != remote {
		i.remote.Store(&remote)
		i.remotes.LearnRemote(i.vpnAddrs[0], remote)
	}
}

// SetRemoteIfPreferred returns true if the remote was changed. The lastRoam
// time on the HostInfo will also be updated.
func (i *HostInfo) SetRemoteIfPreferred(hm *HostMap, via ViaSender) bool {
	if via.IsRelayed {
		return false
	}

	currentRemote := i.GetRemote()
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

// logger returns a derived slog.Logger with per-hostinfo fields pre-bound.
func (i *HostInfo) logger(l *slog.Logger) *slog.Logger {
	if i == nil {
		return l
	}

	li := l.With(
		"vpnAddrs", i.vpnAddrs,
		"localIndex", i.localIndexId,
		"remoteIndex", i.remoteIndexId,
	)

	if connState := i.ConnectionState; connState != nil {
		if peerCert := connState.peerCert; peerCert != nil {
			li = li.With("certName", peerCert.Certificate.Name())
		}
	}

	return li
}

// Utility functions

func localAddrs(l *slog.Logger, allowList *LocalAllowList) []netip.Addr {
	//FIXME: This function is pretty garbage
	var finalAddrs []netip.Addr
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		allow := allowList.AllowName(i.Name)
		if l.Enabled(context.Background(), logging.LevelTrace) {
			l.Log(context.Background(), logging.LevelTrace, "localAllowList.AllowName",
				"interfaceName", i.Name,
				"allow", allow,
			)
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
				if l.Enabled(context.Background(), slog.LevelDebug) {
					l.Debug("addr was invalid", "localAddr", rawAddr)
				}
				continue
			}
			addr = addr.Unmap()

			if addr.IsLoopback() == false && addr.IsLinkLocalUnicast() == false {
				isAllowed := allowList.Allow(addr)
				if l.Enabled(context.Background(), logging.LevelTrace) {
					l.Log(context.Background(), logging.LevelTrace, "localAllowList.Allow",
						"localAddr", addr,
						"allowed", isAllowed,
					)
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
