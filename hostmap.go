package nebula

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

// MaxHostInfosPerVpnIp is the max number of hostinfos we will track for a given vpn ip
// 5 allows for an initial handshake and each host pair re-handshaking twice
const MaxHostInfosPerVpnIp = 5

type HostMap struct {
	sync.RWMutex    //Because we concurrently read and write to our maps
	Indexes         map[uint32]*HostInfo
	Relays          map[uint32]*HostInfo // Maps a Relay IDX to a Relay HostInfo object
	RemoteIndexes   map[uint32]*HostInfo
	Hosts           map[netip.Addr]*HostInfo
	preferredRanges atomic.Pointer[[]netip.Prefix]
	l               *logrus.Logger
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
	//TODO: we may need to promote follow on hostinfos from these vpnAddrs as well since their oldHostinfo might not be the same as this one
	// this really looks like an ideal spot for memory leaks
	oldHostinfo := hm.Hosts[hostinfo.vpnAddrs[0]]
	if oldHostinfo == hostinfo {
		return
	}

	if hostinfo.prev != nil {
		hostinfo.prev.next = hostinfo.next
	}

	if hostinfo.next != nil {
		hostinfo.next.prev = hostinfo.prev
	}

	hm.Hosts[hostinfo.vpnAddrs[0]] = hostinfo

	if oldHostinfo == nil {
		return
	}

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

			//TODO: Filtering out link local for now, this is probably the most correct thing
			//TODO: Would be nice to filter out SLAAC MAC based ips as well
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
