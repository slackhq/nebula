package nebula

import (
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

var ErrHostNotKnown = errors.New("host not known")

type LightHouse struct {
	sync.RWMutex //Because we concurrently read and write to our maps
	amLighthouse bool
	myIp         uint32
	punchConn    *udpConn

	// Local cache of answers from light houses
	addrMap map[uint32][]*udpAddr

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
		addrMap:      make(map[uint32][]*udpAddr),
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
	if !lh.IsLighthouseIP(ip) {
		lh.QueryServer(ip, f)
	}
	lh.RLock()
	if v, ok := lh.addrMap[ip]; ok {
		lh.RUnlock()
		return v, nil
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

// Query our local lighthouse cached results
func (lh *LightHouse) QueryCache(ip uint32) []*udpAddr {
	lh.RLock()
	if v, ok := lh.addrMap[ip]; ok {
		lh.RUnlock()
		return v
	}
	lh.RUnlock()
	return nil
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
	lh.l.Debugf("deleting %s from lighthouse.", IntIp(vpnIP))
	lh.Unlock()
}

func (lh *LightHouse) AddRemote(vpnIP uint32, toIp *udpAddr, static bool) {
	// First we check if the sender thinks this is a static entry
	// and do nothing if it is not, but should be considered static
	if static == false {
		if _, ok := lh.staticList[vpnIP]; ok {
			return
		}
	}

	lh.Lock()
	defer lh.Unlock()
	for _, v := range lh.addrMap[vpnIP] {
		if v.Equals(toIp) {
			return
		}
	}

	allow := lh.remoteAllowList.Allow(toIp.IP)
	lh.l.WithField("remoteIp", toIp).WithField("allow", allow).Debug("remoteAllowList.Allow")
	if !allow {
		return
	}

	//l.Debugf("Adding reply of %s as %s\n", IntIp(vpnIP), toIp)
	if static {
		lh.staticList[vpnIP] = struct{}{}
	}

	lh.addrMap[vpnIP] = append(lh.addrMap[vpnIP], toIp.Copy())
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

func NewIp4AndPortFromUDPAddr(addr *udpAddr) *Ip4AndPort {
	return NewIp4AndPort(addr.IP, uint32(addr.Port))
}

func NewIp6AndPortFromUDPAddr(addr *udpAddr) *Ip6AndPort {
	return NewIp6AndPort(addr.IP, uint32(addr.Port))
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
			IpAndPorts:  v4,
			Ip6AndPorts: v6,
		},
	}

	lh.metricTx(NebulaMeta_HostUpdateNotification, int64(len(lh.lighthouses)))
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)
	for vpnIp := range lh.lighthouses {
		mm, err := proto.Marshal(m)
		if err != nil {
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
	meta *NebulaMeta
	l    *logrus.Logger

	v4   []*Ip4AndPort
	v6   []*Ip6AndPort
}

func (lh *LightHouse) NewRequestHandler() *LightHouseHandler {
	lhh := &LightHouseHandler{
		lh:  lh,
		nb:  make([]byte, 12, 12),
		out: make([]byte, mtu),
		l:   lh.l,
		meta: &NebulaMeta{
			Details: &NebulaMetaDetails{},
		},
	}

	lhh.resizeIp4AndPorts(10)
	lhh.resizeIp6AndPorts(10)

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

	details.Reset()
	lhh.meta.Reset()
	lhh.meta.Details = details

	return lhh.meta
}

func (lhh *LightHouseHandler) resizeIp4AndPorts(n int) {
	if cap(lhh.v4) < n {
		lhh.v4 = make([]*Ip4AndPort, n)
	}
}

func (lhh *LightHouseHandler) resizeIp6AndPorts(n int) {
	if cap(lhh.v6) < n {
		lhh.v6 = make([]*Ip6AndPort, n)
	}
}

func (lhh *LightHouseHandler) setIpAndPortsFromNetIps(ips []*udpAddr) ([]*Ip4AndPort, []*Ip6AndPort) {
	v4c := 0
	v6c := 0

	lhh.resizeIp4AndPorts(len(ips))
	lhh.resizeIp6AndPorts(len(ips))
	for _, e := range ips {
		if ip := e.IP.To4(); ip != nil {
			lhh.v4[v4c] = NewIp4AndPortFromUDPAddr(e)
			v4c++
		} else {
			lhh.v6[v6c] = NewIp6AndPortFromUDPAddr(e)
			v6c++
		}
	}

	return lhh.v4[:v4c], lhh.v6[:v6c]
}

func (lhh *LightHouseHandler) HandleRequest(rAddr *udpAddr, vpnIp uint32, p []byte, c *cert.NebulaCertificate, w EncWriter) {
	n := lhh.resetMeta()
	err := proto.UnmarshalMerge(p, n)
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
		lhh.l.Debugln("I don't answer queries, but received from: ", addr)
		return
	}

	//l.Debugln("Got Query")
	ips, err := lhh.lh.Query(n.Details.VpnIp, w)
	if err != nil {
		//l.Debugf("Can't answer query %s from %s because error: %s", IntIp(n.Details.VpnIp), rAddr, err)
		return
	} else {
		reqVpnIP := n.Details.VpnIp
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostQueryReply
		n.Details.VpnIp = reqVpnIP

		n.Details.IpAndPorts, n.Details.Ip6AndPorts = lhh.setIpAndPortsFromNetIps(ips)

		reply, err := proto.Marshal(n)
		if err != nil {
			lhh.l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).Error("Failed to marshal lighthouse host query reply")
			return
		}
		lhh.lh.metricTx(NebulaMeta_HostQueryReply, 1)
		w.SendMessageToVpnIp(lightHouse, 0, vpnIp, reply, lhh.nb, lhh.out[:0])

		// This signals the other side to punch some zero byte udp packets
		ips, err = lhh.lh.Query(vpnIp, w)
		if err != nil {
			lhh.l.WithField("vpnIp", IntIp(vpnIp)).Debugln("Can't notify host to punch")
			return
		} else {
			//l.Debugln("Notify host to punch", iap)
			n = lhh.resetMeta()
			n.Type = NebulaMeta_HostPunchNotification
			n.Details.VpnIp = vpnIp

			n.Details.IpAndPorts, n.Details.Ip6AndPorts = lhh.setIpAndPortsFromNetIps(ips)

			reply, _ := proto.Marshal(n)
			lhh.lh.metricTx(NebulaMeta_HostPunchNotification, 1)
			w.SendMessageToVpnIp(lightHouse, 0, reqVpnIP, reply, lhh.nb, lhh.out[:0])
		}
		//fmt.Println(reply, remoteaddr)
	}
}

func (lhh *LightHouseHandler) handleHostQueryReply(n *NebulaMeta, vpnIp uint32) {
	if !lhh.lh.IsLighthouseIP(vpnIp) {
		return
	}

	for _, a := range n.Details.IpAndPorts {
		ans := NewUDPAddrFromLH4(a)
		if ans != nil {
			lhh.lh.AddRemote(n.Details.VpnIp, ans, false)
		}
	}

	for _, a := range n.Details.Ip6AndPorts {
		ans := NewUDPAddrFromLH6(a)
		if ans != nil {
			lhh.lh.AddRemote(n.Details.VpnIp, ans, false)
		}
	}

	// Non-blocking attempt to trigger, skip if it would block
	select {
	case lhh.lh.handshakeTrigger <- n.Details.VpnIp:
	default:
	}
}

func (lhh *LightHouseHandler) handleHostUpdateNotification(n *NebulaMeta, vpnIp uint32) {
	//Simple check that the host sent this not someone else
	if n.Details.VpnIp != vpnIp {
		lhh.l.WithField("vpnIp", IntIp(vpnIp)).WithField("answer", IntIp(n.Details.VpnIp)).Debugln("Host sent invalid update")
		return
	}

	for _, a := range n.Details.IpAndPorts {
		ans := NewUDPAddrFromLH4(a)
		if ans != nil {
			lhh.lh.AddRemote(n.Details.VpnIp, ans, false)
		}
	}

	for _, a := range n.Details.Ip6AndPorts {
		ans := NewUDPAddrFromLH6(a)
		if ans != nil {
			lhh.lh.AddRemote(n.Details.VpnIp, ans, false)
		}
	}
}

func (lhh *LightHouseHandler) handleHostPunchNotification(n *NebulaMeta, vpnIp uint32, w EncWriter) {
	if !lhh.lh.IsLighthouseIP(vpnIp) {
		return
	}

	empty := []byte{0}
	for _, a := range n.Details.IpAndPorts {
		vpnPeer := NewUDPAddrFromLH4(a)
		if vpnPeer == nil {
			continue
		}

		go func() {
			time.Sleep(lhh.lh.punchDelay)
			lhh.lh.metricHolepunchTx.Inc(1)
			lhh.lh.punchConn.WriteTo(empty, vpnPeer)

		}()

		if lhh.l.Level >= logrus.DebugLevel {
			//TODO: lacking the ip we are actually punching on, old: l.Debugf("Punching %s on %d for %s", IntIp(a.Ip), a.Port, IntIp(n.Details.VpnIp))
			lhh.l.Debugf("Punching on %d for %s", a.Port, IntIp(n.Details.VpnIp))
		}
	}

	for _, a := range n.Details.Ip6AndPorts {
		vpnPeer := NewUDPAddrFromLH6(a)
		if vpnPeer == nil {
			continue
		}

		go func() {
			time.Sleep(lhh.lh.punchDelay)
			lhh.lh.metricHolepunchTx.Inc(1)
			lhh.lh.punchConn.WriteTo(empty, vpnPeer)

		}()

		if lhh.l.Level >= logrus.DebugLevel {
			//TODO: lacking the ip we are actually punching on, old: l.Debugf("Punching %s on %d for %s", IntIp(a.Ip), a.Port, IntIp(n.Details.VpnIp))
			lhh.l.Debugf("Punching on %d for %s", a.Port, IntIp(n.Details.VpnIp))
		}
	}

	// This sends a nebula test packet to the host trying to contact us. In the case
	// of a double nat or other difficult scenario, this may help establish
	// a tunnel.
	if lhh.lh.punchBack {
		go func() {
			time.Sleep(time.Second * 5)
			lhh.l.Debugf("Sending a nebula test packet to vpn ip %s", IntIp(n.Details.VpnIp))
			// TODO we have to allocate a new output buffer here since we are spawning a new goroutine
			// for each punchBack packet. We should move this into a timerwheel or a single goroutine
			// managed by a channel.
			w.SendMessageToVpnIp(test, testRequest, n.Details.VpnIp, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
		}()
	}
}
