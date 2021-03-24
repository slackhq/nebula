package nebula

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
)

//TODO: if the pb code for ipv6 used a fixed data type we could save more work
//TODO: nodes are roaming lighthouses, this is bad. How are they learning?
//TODO: as a lh client, ignore any address within my nebula network?????

var ErrHostNotKnown = errors.New("host not known")

// The maximum number of ip addresses to store for a given vpnIp per address family
const maxAddrs = 10

type ip4And6 struct {
	//TODO: adding a lock here could allow us to release the lock on lh.addrMap quicker

	// v4 and v6 store addresses that have been self reported by the client
	v4 []*Ip4AndPort
	v6 []*Ip6AndPort

	// Learned addresses are ones that a client does not know about but a lighthouse learned from as a result of the received packet
	learnedV4 []*Ip4AndPort
	learnedV6 []*Ip6AndPort
}

type LightHouse struct {
	//TODO: We need a timer wheel to kick out vpnIps that haven't reported in a long time
	sync.RWMutex //Because we concurrently read and write to our maps
	amLighthouse bool
	myIp         uint32
	punchConn    *udpConn

	// Local cache of answers from light houses
	addrMap map[uint32]*ip4And6

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
	SendMessageToAll(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte)
}

func NewLightHouse(l *logrus.Logger, amLighthouse bool, myIp uint32, ips []uint32, interval int, nebulaPort uint32, pc *udpConn, punchBack bool, punchDelay time.Duration, metricsEnabled bool) *LightHouse {
	h := LightHouse{
		amLighthouse: amLighthouse,
		myIp:         myIp,
		addrMap:      make(map[uint32]*ip4And6),
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

func (lh *LightHouse) Query(ip uint32, f EncWriter) ([]*udpAddr, error) {
	//TODO: we need to hold the lock through the next func
	if !lh.IsLighthouseIP(ip) {
		lh.QueryServer(ip, f)
	}
	lh.RLock()
	if v, ok := lh.addrMap[ip]; ok {
		lh.RUnlock()
		return TransformLHReplyToUdpAddrs(v), nil
	}
	lh.RUnlock()
	return nil, ErrHostNotKnown
}

// This is asynchronous so no reply should be expected
func (lh *LightHouse) QueryServer(ip uint32, f EncWriter) {
	if !lh.amLighthouse {
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
}

func (lh *LightHouse) QueryCache(ip uint32) []*udpAddr {
	//TODO: we need to hold the lock through the next func
	lh.RLock()
	if v, ok := lh.addrMap[ip]; ok {
		lh.RUnlock()
		return TransformLHReplyToUdpAddrs(v)
	}
	lh.RUnlock()
	return nil
}

//
func (lh *LightHouse) queryAndPrepMessage(ip uint32, f func(*ip4And6) (int, error)) (bool, int, error) {
	lh.RLock()
	if v, ok := lh.addrMap[ip]; ok {
		n, err := f(v)
		lh.RUnlock()
		return true, n, err
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

// AddRemote is correct way for non LightHouse members to add an address. toAddr will be placed in the learned map
// static means this is a static host entry from the config file, it should only be used on start up
func (lh *LightHouse) AddRemote(vpnIP uint32, toAddr *udpAddr, static bool) {
	if ipv4 := toAddr.IP.To4(); ipv4 != nil {
		lh.addRemoteV4(vpnIP, NewIp4AndPort(ipv4, uint32(toAddr.Port)), static, true)
	} else {
		lh.addRemoteV6(vpnIP, NewIp6AndPort(toAddr.IP, uint32(toAddr.Port)), static, true)
	}

	//TODO: if we do not add due to a config filter we may end up not having any addresses here
	if static {
		lh.staticList[vpnIP] = struct{}{}
	}
}

// unsafeGetAddrs assumes you have the lh lock
func (lh *LightHouse) unsafeGetAddrs(vpnIP uint32) *ip4And6 {
	am, ok := lh.addrMap[vpnIP]
	if !ok {
		am = &ip4And6{
			v4:        make([]*Ip4AndPort, 0),
			v6:        make([]*Ip6AndPort, 0),
			learnedV4: make([]*Ip4AndPort, 0),
			learnedV6: make([]*Ip6AndPort, 0),
		}
		lh.addrMap[vpnIP] = am
	}
	return am
}

func (lh *LightHouse) copyIp4AndPort(ip *Ip4AndPort) *Ip4AndPort {
	return &Ip4AndPort{
		Ip:   ip.Ip,
		Port: ip.Port,
	}
}

func (lh *LightHouse) copyIp6AndPort(ip *Ip6AndPort) *Ip6AndPort {
	newIp := &Ip6AndPort{
		Ip:   make([]byte, len(ip.Ip)),
		Port: ip.Port,
	}
	copy(newIp.Ip, ip.Ip)
	return newIp
}

// addRemoteV4 is a lighthouse internal function to cache client updates or server responses for ipv4 addresses
func (lh *LightHouse) addRemoteV4(vpnIP uint32, to *Ip4AndPort, static bool, learned bool) {
	// First we check if the sender thinks this is a static entry
	// and do nothing if it is not, but should be considered static
	if static == false {
		if _, ok := lh.staticList[vpnIP]; ok {
			return
		}
	}

	ip := int2ip(to.Ip)
	allow := lh.remoteAllowList.Allow(ip)
	if lh.l.Level >= logrus.DebugLevel {
		lh.l.WithField("remoteIp", ip).WithField("allow", allow).Debug("remoteAllowList.Allow")
	}

	if !allow {
		return
	}

	lh.Lock()
	defer lh.Unlock()
	am := lh.unsafeGetAddrs(vpnIP)
	if learned {
		am.learnedV4 = lh.unsafeAddRemoteV4(am.learnedV4, to)
	} else {
		am.v4 = lh.unsafeAddRemoteV4(am.v4, to)
	}
}

// unsafeAddRemoteV4 assumes there is already an addrMap entry and that you have the lh lock
func (lh *LightHouse) unsafeAddRemoteV4(am []*Ip4AndPort, to *Ip4AndPort) []*Ip4AndPort {
	for _, v := range am {
		if v.Ip == to.Ip && v.Port == to.Port {
			return am
		}
	}

	// prepend to keep things fresh
	am = append(am, nil)
	copy(am[1:], am)
	am[0] = lh.copyIp4AndPort(to)
	if len(am) > maxAddrs {
		am = am[:maxAddrs]
	}
	return am
}

// addRemoteV6 is a lighthouse internal function to cache client updates or server responses for ipv6 addresses
func (lh *LightHouse) addRemoteV6(vpnIP uint32, to *Ip6AndPort, static bool, learned bool) {
	// First we check if the sender thinks this is a static entry
	// and do nothing if it is not, but should be considered static
	if static == false {
		if _, ok := lh.staticList[vpnIP]; ok {
			return
		}
	}

	ip := net.IP(to.Ip)
	allow := lh.remoteAllowList.Allow(ip)
	if lh.l.Level >= logrus.DebugLevel {
		lh.l.WithField("remoteIp", ip).WithField("allow", allow).Debug("remoteAllowList.Allow")
	}

	if !allow {
		return
	}

	lh.Lock()
	defer lh.Unlock()
	am := lh.unsafeGetAddrs(vpnIP)
	if learned {
		am.learnedV6 = lh.unsafeAddRemoteV6(am.learnedV6, to)
	} else {
		am.v6 = lh.unsafeAddRemoteV6(am.v6, to)
	}
}

// unsafeAddRemoteV6 assumes there is already an addrMap entry and that you have the lh lock
func (lh *LightHouse) unsafeAddRemoteV6(am []*Ip6AndPort, to *Ip6AndPort) []*Ip6AndPort {
	for _, v := range am {
		if bytes.Equal(v.Ip, to.Ip) && v.Port == to.Port {
			return am
		}
	}

	// prepend to keep things fresh
	am = append(am, nil)
	copy(am[1:], am)
	am[0] = lh.copyIp6AndPort(to)

	if len(am) > maxAddrs {
		am = am[:maxAddrs]
	}
	return am
}

func (lh *LightHouse) AddRemoteAndReset(vpnIP uint32, toIp *udpAddr) {
	if lh.amLighthouse {
		lh.DeleteVpnIP(vpnIP)
		lh.AddRemote(vpnIP, toIp, false)
	}
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
	ipp := Ip6AndPort{Port: port}
	ipp.Ip = make([]byte, len(ip))
	copy(ipp.Ip, ip)
	return &ipp
}

func NewUDPAddrFromLH4(ipp *Ip4AndPort) *udpAddr {
	ip := ipp.Ip
	return NewUDPAddr(
		net.IPv4(byte(ip&0xff000000>>24), byte(ip&0x00ff0000>>16), byte(ip&0x0000ff00>>8), byte(ip&0x000000ff)),
		uint16(ipp.Port),
	)
}

func NewUDPAddrFromLH6(ipp *Ip6AndPort) *udpAddr {
	return NewUDPAddr(ipp.Ip, uint16(ipp.Port))
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
		if ip2int(e) == lh.myIp {
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
			VpnIp:       lh.myIp,
			Ip4AndPorts: v4,
			Ip6AndPorts: v6,
		},
	}

	lh.metricTx(NebulaMeta_HostUpdateNotification, int64(len(lh.lighthouses)))
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)
	for vpnIp := range lh.lighthouses {
		mm, err := proto.Marshal(m)
		if err != nil && lh.l.Level >= logrus.DebugLevel {
			lh.l.Debugf("Invalid marshal to update")
		}
		//l.Error("LIGHTHOUSE PACKET SEND", mm)
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

//TODO: do we need c here?
func (lhh *LightHouseHandler) HandleRequest(rAddr *udpAddr, vpnIp uint32, p []byte, c *cert.NebulaCertificate, w EncWriter) {
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
	//TODO: If we use a lock on cache we can avoid holding it on lh.addrMap and keep things moving better
	found, ln, err := lhh.lh.queryAndPrepMessage(n.Details.VpnIp, func(cache *ip4And6) (int, error) {
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostQueryReply
		n.Details.VpnIp = reqVpnIP

		lhh.coalesceAnswers(cache, n)

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
	found, ln, err = lhh.lh.queryAndPrepMessage(vpnIp, func(cache *ip4And6) (int, error) {
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostPunchNotification
		n.Details.VpnIp = vpnIp

		lhh.coalesceAnswers(cache, n)

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

func (lhh *LightHouseHandler) coalesceAnswers(cache *ip4And6, n *NebulaMeta) {
	n.Details.Ip4AndPorts = append(n.Details.Ip4AndPorts, cache.v4...)
	n.Details.Ip4AndPorts = append(n.Details.Ip4AndPorts, cache.learnedV4...)

	n.Details.Ip6AndPorts = append(n.Details.Ip6AndPorts, cache.v6...)
	n.Details.Ip6AndPorts = append(n.Details.Ip6AndPorts, cache.learnedV6...)
}

func (lhh *LightHouseHandler) handleHostQueryReply(n *NebulaMeta, vpnIp uint32) {
	if !lhh.lh.IsLighthouseIP(vpnIp) {
		return
	}

	// We can't just slam the responses in as they may come from multiple lighthouses and we should coalesce the answers
	for _, to := range n.Details.Ip4AndPorts {
		lhh.lh.addRemoteV4(n.Details.VpnIp, to, false, false)
	}

	for _, to := range n.Details.Ip6AndPorts {
		lhh.lh.addRemoteV6(n.Details.VpnIp, to, false, false)
	}

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
	defer lhh.lh.Unlock()
	am := lhh.lh.unsafeGetAddrs(vpnIp)

	//TODO: other note on a lock for am so we can release more quickly and lock our real unit of change which is far less contended
	//TODO: we are not filtering by local or remote allowed addrs here, is this an ok change to make?

	//NOTE: The underlying protobuf code allocates a new Ip4AndPorts and Ip6AndPorts each time so we don't need to copy here
	// Horribly things will happen if that ever changes
	for _, v := range n.Details.Ip4AndPorts {
		am.v4 = lhh.lh.unsafeAddRemoteV4(am.v4, v)
	}

	//NOTE: unlike ipv4, which reuses the []Ip4AndPort memory safely, Ip6AndPort renders into a []byte and is not reused
	for _, v := range n.Details.Ip6AndPorts {
		am.v6 = lhh.lh.unsafeAddRemoteV6(am.v6, v)
	}
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

func TransformLHReplyToUdpAddrs(ips *ip4And6) []*udpAddr {
	addrs := make([]*udpAddr, len(ips.v4)+len(ips.v6)+len(ips.learnedV4)+len(ips.learnedV6))
	i := 0

	for _, v := range ips.learnedV4 {
		addrs[i] = NewUDPAddrFromLH4(v)
		i++
	}

	for _, v := range ips.v4 {
		addrs[i] = NewUDPAddrFromLH4(v)
		i++
	}

	for _, v := range ips.learnedV6 {
		addrs[i] = NewUDPAddrFromLH6(v)
		i++
	}

	for _, v := range ips.v6 {
		addrs[i] = NewUDPAddrFromLH6(v)
		i++
	}

	return addrs
}
