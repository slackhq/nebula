package nebula

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
)

//const ProbeLen = 100
const PromoteEvery = 1000
const ReQueryEvery = 5000
const MaxRemotes = 10

// How long we should prevent roaming back to the previous IP.
// This helps prevent flapping due to packets already in flight
const RoamingSuppressSeconds = 2

type HostMap struct {
	sync.RWMutex    //Because we concurrently read and write to our maps
	name            string
	Indexes         map[uint32]*HostInfo
	RemoteIndexes   map[uint32]*HostInfo
	Hosts           map[uint32]*HostInfo
	preferredRanges []*net.IPNet
	vpnCIDR         *net.IPNet
	unsafeRoutes    *CIDRTree
	metricsEnabled  bool
	l               *logrus.Logger
}

type HostInfo struct {
	sync.RWMutex

	remote            *udpAddr
	remotes           *RemoteList
	promoteCounter    uint32
	ConnectionState   *ConnectionState
	handshakeStart    time.Time        //todo: this an entry in the handshake manager
	HandshakeReady    bool             //todo: being in the manager means you are ready
	HandshakeCounter  int              //todo: another handshake manager entry
	HandshakeComplete bool             //todo: this should go away in favor of ConnectionState.ready
	HandshakePacket   map[uint8][]byte //todo: this is other handshake manager entry
	packetStore       []*cachedPacket  //todo: this is other handshake manager entry
	remoteIndexId     uint32
	localIndexId      uint32
	hostId            uint32
	recvError         int
	remoteCidr        *CIDRTree

	// lastRebindCount is the other side of Interface.rebindCount, if these values don't match then we need to ask LH
	// for a punch from the remote end of this tunnel. The goal being to prime their conntrack for our traffic just like
	// with a handshake
	lastRebindCount int8

	// lastHandshakeTime records the time the remote side told us about at the stage when the handshake was completed locally
	// Stage 1 packet will contain it if I am a responder, stage 2 packet if I am an initiator
	// This is used to avoid an attack where a handshake packet is replayed after some time
	lastHandshakeTime uint64

	lastRoam       time.Time
	lastRoamRemote *udpAddr
}

type cachedPacket struct {
	messageType    NebulaMessageType
	messageSubType NebulaMessageSubType
	callback       packetCallback
	packet         []byte
}

type packetCallback func(t NebulaMessageType, st NebulaMessageSubType, h *HostInfo, p, nb, out []byte)

type cachedPacketMetrics struct {
	sent    metrics.Counter
	dropped metrics.Counter
}

func NewHostMap(l *logrus.Logger, name string, vpnCIDR *net.IPNet, preferredRanges []*net.IPNet) *HostMap {
	h := map[uint32]*HostInfo{}
	i := map[uint32]*HostInfo{}
	r := map[uint32]*HostInfo{}
	m := HostMap{
		name:            name,
		Indexes:         i,
		RemoteIndexes:   r,
		Hosts:           h,
		preferredRanges: preferredRanges,
		vpnCIDR:         vpnCIDR,
		unsafeRoutes:    NewCIDRTree(),
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
	hm.RUnlock()

	metrics.GetOrRegisterGauge("hostmap."+name+".hosts", nil).Update(int64(hostLen))
	metrics.GetOrRegisterGauge("hostmap."+name+".indexes", nil).Update(int64(indexLen))
	metrics.GetOrRegisterGauge("hostmap."+name+".remoteIndexes", nil).Update(int64(remoteIndexLen))
}

func (hm *HostMap) GetIndexByVpnIP(vpnIP uint32) (uint32, error) {
	hm.RLock()
	if i, ok := hm.Hosts[vpnIP]; ok {
		index := i.localIndexId
		hm.RUnlock()
		return index, nil
	}
	hm.RUnlock()
	return 0, errors.New("vpn IP not found")
}

func (hm *HostMap) Add(ip uint32, hostinfo *HostInfo) {
	hm.Lock()
	hm.Hosts[ip] = hostinfo
	hm.Unlock()
}

func (hm *HostMap) AddVpnIP(vpnIP uint32) *HostInfo {
	h := &HostInfo{}
	hm.RLock()
	if _, ok := hm.Hosts[vpnIP]; !ok {
		hm.RUnlock()
		h = &HostInfo{
			promoteCounter:  0,
			hostId:          vpnIP,
			HandshakePacket: make(map[uint8][]byte, 0),
		}
		hm.Lock()
		hm.Hosts[vpnIP] = h
		hm.Unlock()
		return h
	} else {
		h = hm.Hosts[vpnIP]
		hm.RUnlock()
		return h
	}
}

func (hm *HostMap) DeleteVpnIP(vpnIP uint32) {
	hm.Lock()
	delete(hm.Hosts, vpnIP)
	if len(hm.Hosts) == 0 {
		hm.Hosts = map[uint32]*HostInfo{}
	}
	hm.Unlock()

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "vpnIp": IntIp(vpnIP), "mapTotalSize": len(hm.Hosts)}).
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
			"hostinfo": m{"existing": true, "localIndexId": h.localIndexId, "hostId": IntIp(h.hostId)}}).
			Debug("Hostmap remoteIndex added")
	}
}

func (hm *HostMap) AddVpnIPHostInfo(vpnIP uint32, h *HostInfo) {
	hm.Lock()
	h.hostId = vpnIP
	hm.Hosts[vpnIP] = h
	hm.Indexes[h.localIndexId] = h
	hm.RemoteIndexes[h.remoteIndexId] = h
	hm.Unlock()

	if hm.l.Level > logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "vpnIp": IntIp(vpnIP), "mapTotalSize": len(hm.Hosts),
			"hostinfo": m{"existing": true, "localIndexId": h.localIndexId, "hostId": IntIp(h.hostId)}}).
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
		hostinfo2, ok := hm.Hosts[hostinfo.hostId]
		if ok && hostinfo2 == hostinfo {
			delete(hm.Hosts, hostinfo.hostId)
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
		hostinfo2, ok = hm.Hosts[hostinfo.hostId]
		if ok && hostinfo2 == hostinfo {
			delete(hm.Hosts, hostinfo.hostId)
		}
	}
	hm.Unlock()

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "indexNumber": index, "mapTotalSize": len(hm.Indexes)}).
			Debug("Hostmap remote index deleted")
	}
}

func (hm *HostMap) DeleteHostInfo(hostinfo *HostInfo) {
	hm.Lock()
	defer hm.Unlock()
	hm.unlockedDeleteHostInfo(hostinfo)
}

func (hm *HostMap) unlockedDeleteHostInfo(hostinfo *HostInfo) {
	// Check if this same hostId is in the hostmap with a different instance.
	// This could happen if we have an entry in the pending hostmap with different
	// index values than the one in the main hostmap.
	hostinfo2, ok := hm.Hosts[hostinfo.hostId]
	if ok && hostinfo2 != hostinfo {
		delete(hm.Hosts, hostinfo2.hostId)
		delete(hm.Indexes, hostinfo2.localIndexId)
		delete(hm.RemoteIndexes, hostinfo2.remoteIndexId)
	}

	delete(hm.Hosts, hostinfo.hostId)
	if len(hm.Hosts) == 0 {
		hm.Hosts = map[uint32]*HostInfo{}
	}
	delete(hm.Indexes, hostinfo.localIndexId)
	if len(hm.Indexes) == 0 {
		hm.Indexes = map[uint32]*HostInfo{}
	}
	delete(hm.RemoteIndexes, hostinfo.remoteIndexId)
	if len(hm.RemoteIndexes) == 0 {
		hm.RemoteIndexes = map[uint32]*HostInfo{}
	}

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "mapTotalSize": len(hm.Hosts),
			"vpnIp": IntIp(hostinfo.hostId), "indexNumber": hostinfo.localIndexId, "remoteIndexNumber": hostinfo.remoteIndexId}).
			Debug("Hostmap hostInfo deleted")
	}
}

func (hm *HostMap) QueryIndex(index uint32) (*HostInfo, error) {
	//TODO: we probably just want ot return bool instead of error, or at least a static error
	hm.RLock()
	if h, ok := hm.Indexes[index]; ok {
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

func (hm *HostMap) QueryVpnIP(vpnIp uint32) (*HostInfo, error) {
	return hm.queryVpnIP(vpnIp, nil)
}

// PromoteBestQueryVpnIP will attempt to lazily switch to the best remote every
// `PromoteEvery` calls to this function for a given host.
func (hm *HostMap) PromoteBestQueryVpnIP(vpnIp uint32, ifce *Interface) (*HostInfo, error) {
	return hm.queryVpnIP(vpnIp, ifce)
}

func (hm *HostMap) queryVpnIP(vpnIp uint32, promoteIfce *Interface) (*HostInfo, error) {
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

func (hm *HostMap) queryUnsafeRoute(ip uint32) uint32 {
	r := hm.unsafeRoutes.MostSpecificContains(ip)
	if r != nil {
		return r.(uint32)
	} else {
		return 0
	}
}

// We already have the hm Lock when this is called, so make sure to not call
// any other methods that might try to grab it again
func (hm *HostMap) addHostInfo(hostinfo *HostInfo, f *Interface) {
	if f.serveDns {
		remoteCert := hostinfo.ConnectionState.peerCert
		dnsR.Add(remoteCert.Details.Name+".", remoteCert.Details.Ips[0].IP.String())
	}

	hm.Hosts[hostinfo.hostId] = hostinfo
	hm.Indexes[hostinfo.localIndexId] = hostinfo
	hm.RemoteIndexes[hostinfo.remoteIndexId] = hostinfo

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapName": hm.name, "vpnIp": IntIp(hostinfo.hostId), "mapTotalSize": len(hm.Hosts),
			"hostinfo": m{"existing": true, "localIndexId": hostinfo.localIndexId, "hostId": IntIp(hostinfo.hostId)}}).
			Debug("Hostmap vpnIp added")
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
func (hm *HostMap) Punchy(conn *udpConn) {
	var metricsTxPunchy metrics.Counter
	if hm.metricsEnabled {
		metricsTxPunchy = metrics.GetOrRegisterCounter("messages.tx.punchy", nil)
	} else {
		metricsTxPunchy = metrics.NilCounter{}
	}

	var remotes []*RemoteList
	b := []byte{1}
	for {
		remotes = hm.punchList(remotes[:0])
		for _, rl := range remotes {
			//TODO: CopyAddrs generates garbage but ForEach locks for the work here, figure out which way is better
			for _, addr := range rl.CopyAddrs(hm.preferredRanges) {
				metricsTxPunchy.Inc(1)
				conn.WriteTo(b, addr)
			}
		}
		time.Sleep(time.Second * 10)
	}
}

func (hm *HostMap) addUnsafeRoutes(routes *[]route) {
	for _, r := range *routes {
		hm.l.WithField("route", r.route).WithField("via", r.via).Warn("Adding UNSAFE Route")
		hm.unsafeRoutes.AddCIDR(r.route, ip2int(*r.via))
	}
}

func (i *HostInfo) BindConnectionState(cs *ConnectionState) {
	i.ConnectionState = cs
}

// TryPromoteBest handles re-querying lighthouses and probing for better paths
// NOTE: It is an error to call this if you are a lighthouse since they should not roam clients!
func (i *HostInfo) TryPromoteBest(preferredRanges []*net.IPNet, ifce *Interface) {
	c := atomic.AddUint32(&i.promoteCounter, 1)
	if c%PromoteEvery == 0 {
		// The lock here is currently protecting i.remote access
		i.RLock()
		defer i.RUnlock()

		// return early if we are already on a preferred remote
		rIP := i.remote.IP
		for _, l := range preferredRanges {
			if l.Contains(rIP) {
				return
			}
		}

		i.remotes.ForEach(preferredRanges, func(addr *udpAddr, preferred bool) {
			if addr == nil || !preferred {
				return
			}

			// Try to send a test packet to that host, this should
			// cause it to detect a roaming event and switch remotes
			ifce.send(test, testRequest, i.ConnectionState, i, addr, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
		})
	}

	// Re query our lighthouses for new remotes occasionally
	if c%ReQueryEvery == 0 && ifce.lightHouse != nil {
		ifce.lightHouse.QueryServer(i.hostId, ifce)
	}
}

func (i *HostInfo) cachePacket(l *logrus.Logger, t NebulaMessageType, st NebulaMessageSubType, packet []byte, f packetCallback, m *cachedPacketMetrics) {
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
	atomic.StoreUint64(&i.ConnectionState.atomicMessageCounter, 2)

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

func (i *HostInfo) SetRemote(remote *udpAddr) {
	// We copy here because we likely got this remote from a source that reuses the object
	if !i.remote.Equals(remote) {
		i.remote = remote.Copy()
		i.remotes.LearnRemote(i.hostId, remote.Copy())
	}
}

func (i *HostInfo) ClearConnectionState() {
	i.ConnectionState = nil
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

	remoteCidr := NewCIDRTree()
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

	li := l.WithField("vpnIp", IntIp(i.hostId))

	if connState := i.ConnectionState; connState != nil {
		if peerCert := connState.peerCert; peerCert != nil {
			li = li.WithField("certName", peerCert.Details.Name)
		}
	}

	return li
}

//########################

/*

func (hm *HostMap) DebugRemotes(vpnIp uint32) string {
	s := "\n"
	for _, h := range hm.Hosts {
		for _, r := range h.Remotes {
			s += fmt.Sprintf("%s : %d ## %v\n", r.addr.IP.String(), r.addr.Port, r.probes)
		}
	}
	return s
}

func (i *HostInfo) HandleReply(addr *net.UDPAddr, counter int) {
	for _, r := range i.Remotes {
		if r.addr.IP.Equal(addr.IP) && r.addr.Port == addr.Port {
			r.ProbeReceived(counter)
		}
	}
}

func (i *HostInfo) Probes() []*Probe {
	p := []*Probe{}
	for _, d := range i.Remotes {
		p = append(p, &Probe{Addr: d.addr, Counter: d.Probe()})
	}
	return p
}

*/

// Utility functions

func localIps(l *logrus.Logger, allowList *AllowList) *[]net.IP {
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
