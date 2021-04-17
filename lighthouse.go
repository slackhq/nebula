package nebula

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
)

//TODO: if a lighthouse doesn't have an answer, clients AGGRESSIVELY REQUERY.. why? handshake manager and/or getOrHandshake?
//TODO: nodes are roaming lighthouses, this is bad. How are they learning?

var ErrHostNotKnown = errors.New("host not known")

type LightHouse struct {
	//TODO: We need a timer wheel to kick out vpnIps that haven't reported in a long time
	sync.RWMutex //Because we concurrently read and write to our maps
	amLighthouse bool
	myVpnIp      uint32
	myVpnZeros   uint32
	punchConn    *udpConn

	// Local cache of answers from light houses
	// map of vpn Ip to answers
	addrMap map[uint32]*RemoteList

	// filters remote addresses allowed for each host
	// - When we are a lighthouse, this filters what addresses we store and
	// respond with.
	// - When we are not a lighthouse, this filters which addresses we accept
	// from lighthouses.
	remoteAllowList *AllowList

	// filters local addresses that we advertise to lighthouses
	localAllowList *AllowList

	// used to trigger the HandshakeManager when we receive HostQueryReply
	handshakeTrigger chan<- uint32

	// staticList exists to avoid having a bool in each addrMap entry
	// since static should be rare
	staticList  map[uint32]struct{}
	lighthouses map[uint32]struct{}
	interval    int
	nebulaPort  uint32 // 32 bits because protobuf does not have a uint16
	punchBack   bool
	punchDelay  time.Duration

	metrics           *MessageMetrics
	metricHolepunchTx metrics.Counter
	l                 *logrus.Logger
}

type EncWriter interface {
	SendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte)
}

func NewLightHouse(l *logrus.Logger, amLighthouse bool, myVpnIpNet *net.IPNet, ips []uint32, interval int, nebulaPort uint32, pc *udpConn, punchBack bool, punchDelay time.Duration, metricsEnabled bool) *LightHouse {
	ones, _ := myVpnIpNet.Mask.Size()
	h := LightHouse{
		amLighthouse: amLighthouse,
		myVpnIp:      ip2int(myVpnIpNet.IP),
		myVpnZeros:   uint32(32 - ones),
		addrMap:      make(map[uint32]*RemoteList),
		nebulaPort:   nebulaPort,
		lighthouses:  make(map[uint32]struct{}),
		staticList:   make(map[uint32]struct{}),
		interval:     interval,
		punchConn:    pc,
		punchBack:    punchBack,
		punchDelay:   punchDelay,
		l:            l,
	}

	if metricsEnabled {
		h.metrics = newLighthouseMetrics()

		h.metricHolepunchTx = metrics.GetOrRegisterCounter("messages.tx.holepunch", nil)
	} else {
		h.metricHolepunchTx = metrics.NilCounter{}
	}

	for _, ip := range ips {
		h.lighthouses[ip] = struct{}{}
	}

	return &h
}

func (lh *LightHouse) SetRemoteAllowList(allowList *AllowList) {
	lh.Lock()
	defer lh.Unlock()

	lh.remoteAllowList = allowList
}

func (lh *LightHouse) SetLocalAllowList(allowList *AllowList) {
	lh.Lock()
	defer lh.Unlock()

	lh.localAllowList = allowList
}

func (lh *LightHouse) ValidateLHStaticEntries() error {
	for lhIP, _ := range lh.lighthouses {
		if _, ok := lh.staticList[lhIP]; !ok {
			return fmt.Errorf("Lighthouse %s does not have a static_host_map entry", IntIp(lhIP))
		}
	}
	return nil
}

func (lh *LightHouse) Query(ip uint32, f EncWriter) *RemoteList {
	if !lh.IsLighthouseIP(ip) {
		lh.QueryServer(ip, f)
	}
	lh.RLock()
	if v, ok := lh.addrMap[ip]; ok {
		lh.RUnlock()
		return v
	}
	lh.RUnlock()
	return nil
}

// This is asynchronous so no reply should be expected
func (lh *LightHouse) QueryServer(ip uint32, f EncWriter) {
	if lh.amLighthouse {
		return
	}

	if lh.IsLighthouseIP(ip) {
		return
	}

	// Send a query to the lighthouses and hope for the best next time
	query, err := proto.Marshal(NewLhQueryByInt(ip))
	if err != nil {
		lh.l.WithError(err).WithField("vpnIp", IntIp(ip)).Error("Failed to marshal lighthouse query payload")
		return
	}

	lh.metricTx(NebulaMeta_HostQuery, int64(len(lh.lighthouses)))
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)
	for n := range lh.lighthouses {
		f.SendMessageToVpnIp(lightHouse, 0, n, query, nb, out)
	}
}

func (lh *LightHouse) QueryCache(ip uint32) *RemoteList {
	lh.RLock()
	if v, ok := lh.addrMap[ip]; ok {
		lh.RUnlock()
		return v
	}
	lh.RUnlock()

	lh.Lock()
	defer lh.Unlock()
	// Add an entry if we don't already have one
	return lh.unlockedGetRemoteList(ip)
}

// queryAndPrepMessage is a lock helper on RemoteList, assisting the caller to build a lighthouse message containing
// details from the remote list. It looks for a hit in the addrMap and a hit in the RemoteList under the owner vpnIp
// If one is found then f() is called with proper locking, f() must return result of n.MarshalTo()
func (lh *LightHouse) queryAndPrepMessage(vpnIp uint32, f func(*cache) (int, error)) (bool, int, error) {
	lh.RLock()
	// Do we have an entry in the main cache?
	if v, ok := lh.addrMap[vpnIp]; ok {
		// Swap lh lock for remote list lock
		v.RLock()
		defer v.RUnlock()

		lh.RUnlock()

		// vpnIp should also be the owner here since we are a lighthouse.
		c := v.cache[vpnIp]
		// Make sure we have
		if c != nil {
			n, err := f(c)
			return true, n, err
		}
		return false, 0, nil
	}
	lh.RUnlock()
	return false, 0, nil
}

func (lh *LightHouse) DeleteVpnIP(vpnIP uint32) {
	// First we check the static mapping
	// and do nothing if it is there
	if _, ok := lh.staticList[vpnIP]; ok {
		return
	}
	lh.Lock()
	//l.Debugln(lh.addrMap)
	delete(lh.addrMap, vpnIP)

	if lh.l.Level >= logrus.DebugLevel {
		lh.l.Debugf("deleting %s from lighthouse.", IntIp(vpnIP))
	}

	lh.Unlock()
}

// AddStaticRemote adds a static host entry for vpnIp as ourselves as the owner
// We are the owner because we don't want a lighthouse server to advertise for static hosts it was configured with
// And we don't want a lighthouse query reply to interfere with our learned cache if we are a client
func (lh *LightHouse) AddStaticRemote(vpnIp uint32, toAddr *udpAddr) {
	lh.Lock()
	am := lh.unlockedGetRemoteList(vpnIp)
	am.Lock()
	defer am.Unlock()
	lh.Unlock()

	if ipv4 := toAddr.IP.To4(); ipv4 != nil {
		to := NewIp4AndPort(ipv4, uint32(toAddr.Port))
		if !lh.unlockedShouldAddV4(to) {
			return
		}
		am.unlockedPrependV4(lh.myVpnIp, to)

	} else {
		to := NewIp6AndPort(toAddr.IP, uint32(toAddr.Port))
		if !lh.unlockedShouldAddV6(to) {
			return
		}
		am.unlockedPrependV6(lh.myVpnIp, to)
	}

	// Mark it as static
	lh.staticList[vpnIp] = struct{}{}
}

// unlockedGetRemoteList assumes you have the lh lock
func (lh *LightHouse) unlockedGetRemoteList(vpnIP uint32) *RemoteList {
	am, ok := lh.addrMap[vpnIP]
	if !ok {
		am = NewRemoteList()
		lh.addrMap[vpnIP] = am
	}
	return am
}

// unlockedShouldAddV4 checks if to is allowed by our allow list
func (lh *LightHouse) unlockedShouldAddV4(to *Ip4AndPort) bool {
	allow := lh.remoteAllowList.AllowIpV4(to.Ip)
	if lh.l.Level >= logrus.TraceLevel {
		lh.l.WithField("remoteIp", IntIp(to.Ip)).WithField("allow", allow).Trace("remoteAllowList.Allow")
	}

	if !allow || ipMaskContains(lh.myVpnIp, lh.myVpnZeros, to.Ip) {
		return false
	}

	return true
}

// unlockedShouldAddV6 checks if to is allowed by our allow list
func (lh *LightHouse) unlockedShouldAddV6(to *Ip6AndPort) bool {
	allow := lh.remoteAllowList.AllowIpV6(to.Hi, to.Lo)
	if lh.l.Level >= logrus.TraceLevel {
		lh.l.WithField("remoteIp", lhIp6ToIp(to)).WithField("allow", allow).Trace("remoteAllowList.Allow")
	}

	// We don't check our vpn network here because nebula does not support ipv6 on the inside
	if !allow {
		return false
	}

	return true
}

func lhIp6ToIp(v *Ip6AndPort) net.IP {
	ip := make(net.IP, 16)
	binary.BigEndian.PutUint64(ip[:8], v.Hi)
	binary.BigEndian.PutUint64(ip[8:], v.Lo)
	return ip
}

func (lh *LightHouse) IsLighthouseIP(vpnIP uint32) bool {
	if _, ok := lh.lighthouses[vpnIP]; ok {
		return true
	}
	return false
}

func NewLhQueryByInt(VpnIp uint32) *NebulaMeta {
	return &NebulaMeta{
		Type: NebulaMeta_HostQuery,
		Details: &NebulaMetaDetails{
			VpnIp: VpnIp,
		},
	}
}

func NewIp4AndPort(ip net.IP, port uint32) *Ip4AndPort {
	ipp := Ip4AndPort{Port: port}
	ipp.Ip = ip2int(ip)
	return &ipp
}

func NewIp6AndPort(ip net.IP, port uint32) *Ip6AndPort {
	return &Ip6AndPort{
		Hi:   binary.BigEndian.Uint64(ip[:8]),
		Lo:   binary.BigEndian.Uint64(ip[8:]),
		Port: port,
	}
}

func NewUDPAddrFromLH4(ipp *Ip4AndPort) *udpAddr {
	ip := ipp.Ip
	return NewUDPAddr(
		net.IPv4(byte(ip&0xff000000>>24), byte(ip&0x00ff0000>>16), byte(ip&0x0000ff00>>8), byte(ip&0x000000ff)),
		uint16(ipp.Port),
	)
}

func NewUDPAddrFromLH6(ipp *Ip6AndPort) *udpAddr {
	return NewUDPAddr(lhIp6ToIp(ipp), uint16(ipp.Port))
}

func (lh *LightHouse) LhUpdateWorker(f EncWriter) {
	if lh.amLighthouse || lh.interval == 0 {
		return
	}

	for {
		lh.SendUpdate(f)
		time.Sleep(time.Second * time.Duration(lh.interval))
	}
}

func (lh *LightHouse) SendUpdate(f EncWriter) {
	var v4 []*Ip4AndPort
	var v6 []*Ip6AndPort

	for _, e := range *localIps(lh.l, lh.localAllowList) {
		if ip4 := e.To4(); ip4 != nil && ipMaskContains(lh.myVpnIp, lh.myVpnZeros, ip2int(ip4)) {
			continue
		}

		// Only add IPs that aren't my VPN/tun IP
		if ip := e.To4(); ip != nil {
			v4 = append(v4, NewIp4AndPort(e, lh.nebulaPort))
		} else {
			v6 = append(v6, NewIp6AndPort(e, lh.nebulaPort))
		}
	}
	m := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotification,
		Details: &NebulaMetaDetails{
			VpnIp:       lh.myVpnIp,
			Ip4AndPorts: v4,
			Ip6AndPorts: v6,
		},
	}

	lh.metricTx(NebulaMeta_HostUpdateNotification, int64(len(lh.lighthouses)))
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	mm, err := proto.Marshal(m)
	if err != nil {
		lh.l.WithError(err).Error("Error while marshaling for lighthouse update")
		return
	}

	for vpnIp := range lh.lighthouses {
		f.SendMessageToVpnIp(lightHouse, 0, vpnIp, mm, nb, out)
	}
}

type LightHouseHandler struct {
	lh   *LightHouse
	nb   []byte
	out  []byte
	pb   []byte
	meta *NebulaMeta
	l    *logrus.Logger
}

func (lh *LightHouse) NewRequestHandler() *LightHouseHandler {
	lhh := &LightHouseHandler{
		lh:  lh,
		nb:  make([]byte, 12, 12),
		out: make([]byte, mtu),
		l:   lh.l,
		pb:  make([]byte, mtu),

		meta: &NebulaMeta{
			Details: &NebulaMetaDetails{},
		},
	}

	return lhh
}

func (lh *LightHouse) metricRx(t NebulaMeta_MessageType, i int64) {
	lh.metrics.Rx(NebulaMessageType(t), 0, i)
}

func (lh *LightHouse) metricTx(t NebulaMeta_MessageType, i int64) {
	lh.metrics.Tx(NebulaMessageType(t), 0, i)
}

// This method is similar to Reset(), but it re-uses the pointer structs
// so that we don't have to re-allocate them
func (lhh *LightHouseHandler) resetMeta() *NebulaMeta {
	details := lhh.meta.Details
	lhh.meta.Reset()

	// Keep the array memory around
	details.Ip4AndPorts = details.Ip4AndPorts[:0]
	details.Ip6AndPorts = details.Ip6AndPorts[:0]
	lhh.meta.Details = details

	return lhh.meta
}

func (lhh *LightHouseHandler) HandleRequest(rAddr *udpAddr, vpnIp uint32, p []byte, w EncWriter) {
	n := lhh.resetMeta()
	err := n.Unmarshal(p)
	if err != nil {
		lhh.l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).WithField("udpAddr", rAddr).
			Error("Failed to unmarshal lighthouse packet")
		//TODO: send recv_error?
		return
	}

	if n.Details == nil {
		lhh.l.WithField("vpnIp", IntIp(vpnIp)).WithField("udpAddr", rAddr).
			Error("Invalid lighthouse update")
		//TODO: send recv_error?
		return
	}

	lhh.lh.metricRx(n.Type, 1)

	switch n.Type {
	case NebulaMeta_HostQuery:
		lhh.handleHostQuery(n, vpnIp, rAddr, w)

	case NebulaMeta_HostQueryReply:
		lhh.handleHostQueryReply(n, vpnIp)

	case NebulaMeta_HostUpdateNotification:
		lhh.handleHostUpdateNotification(n, vpnIp)

	case NebulaMeta_HostMovedNotification:
	case NebulaMeta_HostPunchNotification:
		lhh.handleHostPunchNotification(n, vpnIp, w)
	}
}

func (lhh *LightHouseHandler) handleHostQuery(n *NebulaMeta, vpnIp uint32, addr *udpAddr, w EncWriter) {
	// Exit if we don't answer queries
	if !lhh.lh.amLighthouse {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.Debugln("I don't answer queries, but received from: ", addr)
		}
		return
	}

	//TODO: we can DRY this further
	reqVpnIP := n.Details.VpnIp
	//TODO: Maybe instead of marshalling into n we marshal into a new `r` to not nuke our current request data
	found, ln, err := lhh.lh.queryAndPrepMessage(n.Details.VpnIp, func(c *cache) (int, error) {
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostQueryReply
		n.Details.VpnIp = reqVpnIP

		lhh.coalesceAnswers(c, n)

		return n.MarshalTo(lhh.pb)
	})

	if !found {
		return
	}

	if err != nil {
		lhh.l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).Error("Failed to marshal lighthouse host query reply")
		return
	}

	lhh.lh.metricTx(NebulaMeta_HostQueryReply, 1)
	w.SendMessageToVpnIp(lightHouse, 0, vpnIp, lhh.pb[:ln], lhh.nb, lhh.out[:0])

	// This signals the other side to punch some zero byte udp packets
	found, ln, err = lhh.lh.queryAndPrepMessage(vpnIp, func(c *cache) (int, error) {
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostPunchNotification
		n.Details.VpnIp = vpnIp

		lhh.coalesceAnswers(c, n)

		return n.MarshalTo(lhh.pb)
	})

	if !found {
		return
	}

	if err != nil {
		lhh.l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).Error("Failed to marshal lighthouse host was queried for")
		return
	}

	lhh.lh.metricTx(NebulaMeta_HostPunchNotification, 1)
	w.SendMessageToVpnIp(lightHouse, 0, reqVpnIP, lhh.pb[:ln], lhh.nb, lhh.out[:0])
}

func (lhh *LightHouseHandler) coalesceAnswers(c *cache, n *NebulaMeta) {
	if c.v4 != nil {
		if c.v4.learned != nil {
			n.Details.Ip4AndPorts = append(n.Details.Ip4AndPorts, c.v4.learned)
		}
		if c.v4.reported != nil && len(c.v4.reported) > 0 {
			n.Details.Ip4AndPorts = append(n.Details.Ip4AndPorts, c.v4.reported...)
		}
	}

	if c.v6 != nil {
		if c.v6.learned != nil {
			n.Details.Ip6AndPorts = append(n.Details.Ip6AndPorts, c.v6.learned)
		}
		if c.v6.reported != nil && len(c.v6.reported) > 0 {
			n.Details.Ip6AndPorts = append(n.Details.Ip6AndPorts, c.v6.reported...)
		}
	}
}

func (lhh *LightHouseHandler) handleHostQueryReply(n *NebulaMeta, vpnIp uint32) {
	if !lhh.lh.IsLighthouseIP(vpnIp) {
		return
	}

	lhh.lh.Lock()
	am := lhh.lh.unlockedGetRemoteList(n.Details.VpnIp)
	am.Lock()
	lhh.lh.Unlock()

	am.unlockedSetV4(vpnIp, n.Details.Ip4AndPorts, lhh.lh.unlockedShouldAddV4)
	am.unlockedSetV6(vpnIp, n.Details.Ip6AndPorts, lhh.lh.unlockedShouldAddV6)
	am.Unlock()

	// Non-blocking attempt to trigger, skip if it would block
	select {
	case lhh.lh.handshakeTrigger <- n.Details.VpnIp:
	default:
	}
}

func (lhh *LightHouseHandler) handleHostUpdateNotification(n *NebulaMeta, vpnIp uint32) {
	if !lhh.lh.amLighthouse {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.Debugln("I am not a lighthouse, do not take host updates: ", vpnIp)
		}
		return
	}

	//Simple check that the host sent this not someone else
	if n.Details.VpnIp != vpnIp {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.WithField("vpnIp", IntIp(vpnIp)).WithField("answer", IntIp(n.Details.VpnIp)).Debugln("Host sent invalid update")
		}
		return
	}

	lhh.lh.Lock()
	am := lhh.lh.unlockedGetRemoteList(vpnIp)
	am.Lock()
	lhh.lh.Unlock()

	am.unlockedSetV4(vpnIp, n.Details.Ip4AndPorts, lhh.lh.unlockedShouldAddV4)
	am.unlockedSetV6(vpnIp, n.Details.Ip6AndPorts, lhh.lh.unlockedShouldAddV6)
	am.Unlock()
}

func (lhh *LightHouseHandler) handleHostPunchNotification(n *NebulaMeta, vpnIp uint32, w EncWriter) {
	if !lhh.lh.IsLighthouseIP(vpnIp) {
		return
	}

	empty := []byte{0}
	punch := func(vpnPeer *udpAddr) {
		if vpnPeer == nil {
			return
		}

		go func() {
			time.Sleep(lhh.lh.punchDelay)
			lhh.lh.metricHolepunchTx.Inc(1)
			lhh.lh.punchConn.WriteTo(empty, vpnPeer)
		}()

		if lhh.l.Level >= logrus.DebugLevel {
			//TODO: lacking the ip we are actually punching on, old: l.Debugf("Punching %s on %d for %s", IntIp(a.Ip), a.Port, IntIp(n.Details.VpnIp))
			lhh.l.Debugf("Punching on %d for %s", vpnPeer.Port, IntIp(n.Details.VpnIp))
		}
	}

	for _, a := range n.Details.Ip4AndPorts {
		punch(NewUDPAddrFromLH4(a))
	}

	for _, a := range n.Details.Ip6AndPorts {
		punch(NewUDPAddrFromLH6(a))
	}

	// This sends a nebula test packet to the host trying to contact us. In the case
	// of a double nat or other difficult scenario, this may help establish
	// a tunnel.
	if lhh.lh.punchBack {
		go func() {
			time.Sleep(time.Second * 5)
			if lhh.l.Level >= logrus.DebugLevel {
				lhh.l.Debugf("Sending a nebula test packet to vpn ip %s", IntIp(n.Details.VpnIp))
			}
			//NOTE: we have to allocate a new output buffer here since we are spawning a new goroutine
			// for each punchBack packet. We should move this into a timerwheel or a single goroutine
			// managed by a channel.
			w.SendMessageToVpnIp(test, testRequest, n.Details.VpnIp, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
		}()
	}
}

// ipMaskContains checks if testIp is contained by ip after applying a cidr
// zeros is 32 - bits from net.IPMask.Size()
func ipMaskContains(ip uint32, zeros uint32, testIp uint32) bool {
	return (testIp^ip)>>zeros == 0
}
