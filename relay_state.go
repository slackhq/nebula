package nebula

import (
	"net/netip"
	"sync"
)

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

// RelayState describes an established relay between 3 parties
// for synchronization, treat the pointed-to Relay struct as immutable. To edit the Relay
// struct, make a copy of an existing value, edit the fileds in the copy, and
// then store a pointer to the new copy in both realyForBy* maps.
type RelayState struct {
	sync.RWMutex

	relays         map[netip.Addr]struct{} // Set of vpnAddr's of Hosts to use as relays to access this peer
	relayForByAddr map[netip.Addr]*Relay   // Maps vpnAddr of peers for which this HostInfo is a relay to some Relay info
	relayForByIdx  map[uint32]*Relay       // Maps a local index to some Relay info
}

type Relay struct {
	Type        int
	State       int
	LocalIndex  uint32
	RemoteIndex uint32
	PeerAddr    netip.Addr
}

type ViaSender struct {
	relayHI   *HostInfo // relayHI is the host info object of the relay
	remoteIdx uint32    // remoteIdx is the index included in the header of the received packet
	relay     *Relay    // relay contains the rest of the relay information, including the PeerIP of the host trying to communicate with us.
}

func (rs *RelayState) DeleteRelay(ip netip.Addr) {
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

func (rs *RelayState) GetRelayForByAddr(addr netip.Addr) (*Relay, bool) {
	rs.RLock()
	defer rs.RUnlock()
	r, ok := rs.relayForByAddr[addr]
	return r, ok
}

func (rs *RelayState) InsertRelayTo(ip netip.Addr) {
	rs.Lock()
	defer rs.Unlock()
	rs.relays[ip] = struct{}{}
}

func (rs *RelayState) CopyRelayIps() []netip.Addr {
	rs.RLock()
	defer rs.RUnlock()
	ret := make([]netip.Addr, 0, len(rs.relays))
	for ip := range rs.relays {
		ret = append(ret, ip)
	}
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
