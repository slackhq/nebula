package nebula

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/slackhq/nebula/util"
)

//TODO: if a lighthouse doesn't have an answer, clients AGGRESSIVELY REQUERY.. why? handshake manager and/or getOrHandshake?
//TODO: nodes are roaming lighthouses, this is bad. How are they learning?

var ErrHostNotKnown = errors.New("host not known")

type LightHouse struct {
	//TODO: We need a timer wheel to kick out vpnIps that haven't reported in a long time
	sync.RWMutex //Because we concurrently read and write to our maps
	ctx          context.Context
	amLighthouse bool
	myVpnNet     netip.Prefix
	punchConn    udp.Conn
	punchy       *Punchy

	// Local cache of answers from light houses
	// map of vpn Ip to answers
	addrMap map[netip.Addr]*RemoteList

	// filters remote addresses allowed for each host
	// - When we are a lighthouse, this filters what addresses we store and
	// respond with.
	// - When we are not a lighthouse, this filters which addresses we accept
	// from lighthouses.
	remoteAllowList atomic.Pointer[RemoteAllowList]

	// filters local addresses that we advertise to lighthouses
	localAllowList atomic.Pointer[LocalAllowList]

	// used to trigger the HandshakeManager when we receive HostQueryReply
	handshakeTrigger chan<- netip.Addr

	// staticList exists to avoid having a bool in each addrMap entry
	// since static should be rare
	staticList  atomic.Pointer[map[netip.Addr]struct{}]
	lighthouses atomic.Pointer[map[netip.Addr]struct{}]

	interval     atomic.Int64
	updateCancel context.CancelFunc
	ifce         EncWriter
	nebulaPort   uint32 // 32 bits because protobuf does not have a uint16

	advertiseAddrs atomic.Pointer[[]netip.AddrPort]

	// IP's of relays that can be used by peers to access me
	relaysForMe atomic.Pointer[[]netip.Addr]

	queryChan chan netip.Addr

	calculatedRemotes atomic.Pointer[bart.Table[[]*calculatedRemote]] // Maps VpnIp to []*calculatedRemote

	metrics           *MessageMetrics
	metricHolepunchTx metrics.Counter
	l                 *logrus.Logger
}

// NewLightHouseFromConfig will build a Lighthouse struct from the values provided in the config object
// addrMap should be nil unless this is during a config reload
func NewLightHouseFromConfig(ctx context.Context, l *logrus.Logger, c *config.C, myVpnNet netip.Prefix, pc udp.Conn, p *Punchy) (*LightHouse, error) {
	amLighthouse := c.GetBool("lighthouse.am_lighthouse", false)
	nebulaPort := uint32(c.GetInt("listen.port", 0))
	if amLighthouse && nebulaPort == 0 {
		return nil, util.NewContextualError("lighthouse.am_lighthouse enabled on node but no port number is set in config", nil, nil)
	}

	// If port is dynamic, discover it
	if nebulaPort == 0 && pc != nil {
		uPort, err := pc.LocalAddr()
		if err != nil {
			return nil, util.NewContextualError("Failed to get listening port", nil, err)
		}
		nebulaPort = uint32(uPort.Port())
	}

	h := LightHouse{
		ctx:          ctx,
		amLighthouse: amLighthouse,
		myVpnNet:     myVpnNet,
		addrMap:      make(map[netip.Addr]*RemoteList),
		nebulaPort:   nebulaPort,
		punchConn:    pc,
		punchy:       p,
		queryChan:    make(chan netip.Addr, c.GetUint32("handshakes.query_buffer", 64)),
		l:            l,
	}
	lighthouses := make(map[netip.Addr]struct{})
	h.lighthouses.Store(&lighthouses)
	staticList := make(map[netip.Addr]struct{})
	h.staticList.Store(&staticList)

	if c.GetBool("stats.lighthouse_metrics", false) {
		h.metrics = newLighthouseMetrics()
		h.metricHolepunchTx = metrics.GetOrRegisterCounter("messages.tx.holepunch", nil)
	} else {
		h.metricHolepunchTx = metrics.NilCounter{}
	}

	err := h.reload(c, true)
	if err != nil {
		return nil, err
	}

	c.RegisterReloadCallback(func(c *config.C) {
		err := h.reload(c, false)
		switch v := err.(type) {
		case *util.ContextualError:
			v.Log(l)
		case error:
			l.WithError(err).Error("failed to reload lighthouse")
		}
	})

	h.startQueryWorker()

	return &h, nil
}

func (lh *LightHouse) GetStaticHostList() map[netip.Addr]struct{} {
	return *lh.staticList.Load()
}

func (lh *LightHouse) GetLighthouses() map[netip.Addr]struct{} {
	return *lh.lighthouses.Load()
}

func (lh *LightHouse) GetRemoteAllowList() *RemoteAllowList {
	return lh.remoteAllowList.Load()
}

func (lh *LightHouse) GetLocalAllowList() *LocalAllowList {
	return lh.localAllowList.Load()
}

func (lh *LightHouse) GetAdvertiseAddrs() []netip.AddrPort {
	return *lh.advertiseAddrs.Load()
}

func (lh *LightHouse) GetRelaysForMe() []netip.Addr {
	return *lh.relaysForMe.Load()
}

func (lh *LightHouse) getCalculatedRemotes() *bart.Table[[]*calculatedRemote] {
	return lh.calculatedRemotes.Load()
}

func (lh *LightHouse) GetUpdateInterval() int64 {
	return lh.interval.Load()
}

func (lh *LightHouse) reload(c *config.C, initial bool) error {
	if initial || c.HasChanged("lighthouse.advertise_addrs") {
		rawAdvAddrs := c.GetStringSlice("lighthouse.advertise_addrs", []string{})
		advAddrs := make([]netip.AddrPort, 0)

		for i, rawAddr := range rawAdvAddrs {
			host, sport, err := net.SplitHostPort(rawAddr)
			if err != nil {
				return util.NewContextualError("Unable to parse lighthouse.advertise_addrs entry", m{"addr": rawAddr, "entry": i + 1}, err)
			}

			ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
			if err != nil {
				return util.NewContextualError("Unable to lookup lighthouse.advertise_addrs entry", m{"addr": rawAddr, "entry": i + 1}, err)
			}
			if len(ips) == 0 {
				return util.NewContextualError("Unable to lookup lighthouse.advertise_addrs entry", m{"addr": rawAddr, "entry": i + 1}, nil)
			}

			port, err := strconv.Atoi(sport)
			if err != nil {
				return util.NewContextualError("Unable to parse port in lighthouse.advertise_addrs entry", m{"addr": rawAddr, "entry": i + 1}, err)
			}

			if port == 0 {
				port = int(lh.nebulaPort)
			}

			//TODO: we could technically insert all returned ips instead of just the first one if a dns lookup was used
			ip := ips[0].Unmap()
			if lh.myVpnNet.Contains(ip) {
				lh.l.WithField("addr", rawAddr).WithField("entry", i+1).
					Warn("Ignoring lighthouse.advertise_addrs report because it is within the nebula network range")
				continue
			}

			advAddrs = append(advAddrs, netip.AddrPortFrom(ip, uint16(port)))
		}

		lh.advertiseAddrs.Store(&advAddrs)

		if !initial {
			lh.l.Info("lighthouse.advertise_addrs has changed")
		}
	}

	if initial || c.HasChanged("lighthouse.interval") {
		lh.interval.Store(int64(c.GetInt("lighthouse.interval", 10)))

		if !initial {
			lh.l.Infof("lighthouse.interval changed to %v", lh.interval.Load())

			if lh.updateCancel != nil {
				// May not always have a running routine
				lh.updateCancel()
			}

			lh.StartUpdateWorker()
		}
	}

	if initial || c.HasChanged("lighthouse.remote_allow_list") || c.HasChanged("lighthouse.remote_allow_ranges") {
		ral, err := NewRemoteAllowListFromConfig(c, "lighthouse.remote_allow_list", "lighthouse.remote_allow_ranges")
		if err != nil {
			return util.NewContextualError("Invalid lighthouse.remote_allow_list", nil, err)
		}

		lh.remoteAllowList.Store(ral)
		if !initial {
			//TODO: a diff will be annoyingly difficult
			lh.l.Info("lighthouse.remote_allow_list and/or lighthouse.remote_allow_ranges has changed")
		}
	}

	if initial || c.HasChanged("lighthouse.local_allow_list") {
		lal, err := NewLocalAllowListFromConfig(c, "lighthouse.local_allow_list")
		if err != nil {
			return util.NewContextualError("Invalid lighthouse.local_allow_list", nil, err)
		}

		lh.localAllowList.Store(lal)
		if !initial {
			//TODO: a diff will be annoyingly difficult
			lh.l.Info("lighthouse.local_allow_list has changed")
		}
	}

	if initial || c.HasChanged("lighthouse.calculated_remotes") {
		cr, err := NewCalculatedRemotesFromConfig(c, "lighthouse.calculated_remotes")
		if err != nil {
			return util.NewContextualError("Invalid lighthouse.calculated_remotes", nil, err)
		}

		lh.calculatedRemotes.Store(cr)
		if !initial {
			//TODO: a diff will be annoyingly difficult
			lh.l.Info("lighthouse.calculated_remotes has changed")
		}
	}

	//NOTE: many things will get much simpler when we combine static_host_map and lighthouse.hosts in config
	if initial || c.HasChanged("static_host_map") || c.HasChanged("static_map.cadence") || c.HasChanged("static_map.network") || c.HasChanged("static_map.lookup_timeout") {
		// Clean up. Entries still in the static_host_map will be re-built.
		// Entries no longer present must have their (possible) background DNS goroutines stopped.
		if existingStaticList := lh.staticList.Load(); existingStaticList != nil {
			lh.RLock()
			for staticVpnIp := range *existingStaticList {
				if am, ok := lh.addrMap[staticVpnIp]; ok && am != nil {
					am.hr.Cancel()
				}
			}
			lh.RUnlock()
		}
		// Build a new list based on current config.
		staticList := make(map[netip.Addr]struct{})
		err := lh.loadStaticMap(c, staticList)
		if err != nil {
			return err
		}

		lh.staticList.Store(&staticList)
		if !initial {
			//TODO: we should remove any remote list entries for static hosts that were removed/modified?
			if c.HasChanged("static_host_map") {
				lh.l.Info("static_host_map has changed")
			}
			if c.HasChanged("static_map.cadence") {
				lh.l.Info("static_map.cadence has changed")
			}
			if c.HasChanged("static_map.network") {
				lh.l.Info("static_map.network has changed")
			}
			if c.HasChanged("static_map.lookup_timeout") {
				lh.l.Info("static_map.lookup_timeout has changed")
			}
		}
	}

	if initial || c.HasChanged("lighthouse.hosts") {
		lhMap := make(map[netip.Addr]struct{})
		err := lh.parseLighthouses(c, lhMap)
		if err != nil {
			return err
		}

		lh.lighthouses.Store(&lhMap)
		if !initial {
			//NOTE: we are not tearing down existing lighthouse connections because they might be used for non lighthouse traffic
			lh.l.Info("lighthouse.hosts has changed")
		}
	}

	if initial || c.HasChanged("relay.relays") {
		switch c.GetBool("relay.am_relay", false) {
		case true:
			// Relays aren't allowed to specify other relays
			if len(c.GetStringSlice("relay.relays", nil)) > 0 {
				lh.l.Info("Ignoring relays from config because am_relay is true")
			}
			relaysForMe := []netip.Addr{}
			lh.relaysForMe.Store(&relaysForMe)
		case false:
			relaysForMe := []netip.Addr{}
			for _, v := range c.GetStringSlice("relay.relays", nil) {
				lh.l.WithField("relay", v).Info("Read relay from config")

				configRIP, err := netip.ParseAddr(v)
				//TODO: We could print the error here
				if err == nil {
					relaysForMe = append(relaysForMe, configRIP)
				}
			}
			lh.relaysForMe.Store(&relaysForMe)
		}
	}

	return nil
}

func (lh *LightHouse) parseLighthouses(c *config.C, lhMap map[netip.Addr]struct{}) error {
	lhs := c.GetStringSlice("lighthouse.hosts", []string{})
	if lh.amLighthouse && len(lhs) != 0 {
		lh.l.Warn("lighthouse.am_lighthouse enabled on node but upstream lighthouses exist in config")
	}

	for i, host := range lhs {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return util.NewContextualError("Unable to parse lighthouse host entry", m{"host": host, "entry": i + 1}, err)
		}
		if !lh.myVpnNet.Contains(ip) {
			return util.NewContextualError("lighthouse host is not in our subnet, invalid", m{"vpnIp": ip, "network": lh.myVpnNet}, nil)
		}
		lhMap[ip] = struct{}{}
	}

	if !lh.amLighthouse && len(lhMap) == 0 {
		lh.l.Warn("No lighthouse.hosts configured, this host will only be able to initiate tunnels with static_host_map entries")
	}

	staticList := lh.GetStaticHostList()
	for lhIP, _ := range lhMap {
		if _, ok := staticList[lhIP]; !ok {
			return fmt.Errorf("lighthouse %s does not have a static_host_map entry", lhIP)
		}
	}

	return nil
}

func getStaticMapCadence(c *config.C) (time.Duration, error) {
	cadence := c.GetString("static_map.cadence", "30s")
	d, err := time.ParseDuration(cadence)
	if err != nil {
		return 0, err
	}
	return d, nil
}

func getStaticMapLookupTimeout(c *config.C) (time.Duration, error) {
	lookupTimeout := c.GetString("static_map.lookup_timeout", "250ms")
	d, err := time.ParseDuration(lookupTimeout)
	if err != nil {
		return 0, err
	}
	return d, nil
}

func getStaticMapNetwork(c *config.C) (string, error) {
	network := c.GetString("static_map.network", "ip4")
	if network != "ip" && network != "ip4" && network != "ip6" {
		return "", fmt.Errorf("static_map.network must be one of ip, ip4, or ip6")
	}
	return network, nil
}

func (lh *LightHouse) loadStaticMap(c *config.C, staticList map[netip.Addr]struct{}) error {
	d, err := getStaticMapCadence(c)
	if err != nil {
		return err
	}

	network, err := getStaticMapNetwork(c)
	if err != nil {
		return err
	}

	lookupTimeout, err := getStaticMapLookupTimeout(c)
	if err != nil {
		return err
	}

	shm := c.GetMap("static_host_map", map[interface{}]interface{}{})
	i := 0

	for k, v := range shm {
		vpnIp, err := netip.ParseAddr(fmt.Sprintf("%v", k))
		if err != nil {
			return util.NewContextualError("Unable to parse static_host_map entry", m{"host": k, "entry": i + 1}, err)
		}

		if !lh.myVpnNet.Contains(vpnIp) {
			return util.NewContextualError("static_host_map key is not in our subnet, invalid", m{"vpnIp": vpnIp, "network": lh.myVpnNet, "entry": i + 1}, nil)
		}

		vals, ok := v.([]interface{})
		if !ok {
			vals = []interface{}{v}
		}
		remoteAddrs := []string{}
		for _, v := range vals {
			remoteAddrs = append(remoteAddrs, fmt.Sprintf("%v", v))
		}

		err = lh.addStaticRemotes(i, d, network, lookupTimeout, vpnIp, remoteAddrs, staticList)
		if err != nil {
			return err
		}
		i++
	}

	return nil
}

func (lh *LightHouse) Query(ip netip.Addr) *RemoteList {
	if !lh.IsLighthouseIP(ip) {
		lh.QueryServer(ip)
	}
	lh.RLock()
	if v, ok := lh.addrMap[ip]; ok {
		lh.RUnlock()
		return v
	}
	lh.RUnlock()
	return nil
}

// QueryServer is asynchronous so no reply should be expected
func (lh *LightHouse) QueryServer(ip netip.Addr) {
	// Don't put lighthouse ips in the query channel because we can't query lighthouses about lighthouses
	if lh.amLighthouse || lh.IsLighthouseIP(ip) {
		return
	}

	lh.queryChan <- ip
}

func (lh *LightHouse) QueryCache(ip netip.Addr) *RemoteList {
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
func (lh *LightHouse) queryAndPrepMessage(vpnIp netip.Addr, f func(*cache) (int, error)) (bool, int, error) {
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

func (lh *LightHouse) DeleteVpnIp(vpnIp netip.Addr) {
	// First we check the static mapping
	// and do nothing if it is there
	if _, ok := lh.GetStaticHostList()[vpnIp]; ok {
		return
	}
	lh.Lock()
	//l.Debugln(lh.addrMap)
	delete(lh.addrMap, vpnIp)

	if lh.l.Level >= logrus.DebugLevel {
		lh.l.Debugf("deleting %s from lighthouse.", vpnIp)
	}

	lh.Unlock()
}

// AddStaticRemote adds a static host entry for vpnIp as ourselves as the owner
// We are the owner because we don't want a lighthouse server to advertise for static hosts it was configured with
// And we don't want a lighthouse query reply to interfere with our learned cache if we are a client
// NOTE: this function should not interact with any hot path objects, like lh.staticList, the caller should handle it
func (lh *LightHouse) addStaticRemotes(i int, d time.Duration, network string, timeout time.Duration, vpnIp netip.Addr, toAddrs []string, staticList map[netip.Addr]struct{}) error {
	lh.Lock()
	am := lh.unlockedGetRemoteList(vpnIp)
	am.Lock()
	defer am.Unlock()
	ctx := lh.ctx
	lh.Unlock()

	hr, err := NewHostnameResults(ctx, lh.l, d, network, timeout, toAddrs, func() {
		// This callback runs whenever the DNS hostname resolver finds a different set of IP's
		// in its resolution for hostnames.
		am.Lock()
		defer am.Unlock()
		am.shouldRebuild = true
	})
	if err != nil {
		return util.NewContextualError("Static host address could not be parsed", m{"vpnIp": vpnIp, "entry": i + 1}, err)
	}
	am.unlockedSetHostnamesResults(hr)

	for _, addrPort := range hr.GetIPs() {
		if !lh.shouldAdd(vpnIp, addrPort.Addr()) {
			continue
		}
		switch {
		case addrPort.Addr().Is4():
			am.unlockedPrependV4(lh.myVpnNet.Addr(), NewIp4AndPortFromNetIP(addrPort.Addr(), addrPort.Port()))
		case addrPort.Addr().Is6():
			am.unlockedPrependV6(lh.myVpnNet.Addr(), NewIp6AndPortFromNetIP(addrPort.Addr(), addrPort.Port()))
		}
	}

	// Mark it as static in the caller provided map
	staticList[vpnIp] = struct{}{}
	return nil
}

// addCalculatedRemotes adds any calculated remotes based on the
// lighthouse.calculated_remotes configuration. It returns true if any
// calculated remotes were added
func (lh *LightHouse) addCalculatedRemotes(vpnIp netip.Addr) bool {
	tree := lh.getCalculatedRemotes()
	if tree == nil {
		return false
	}
	calculatedRemotes, ok := tree.Lookup(vpnIp)
	if !ok {
		return false
	}

	var calculated []*Ip4AndPort
	for _, cr := range calculatedRemotes {
		c := cr.Apply(vpnIp)
		if c != nil {
			calculated = append(calculated, c)
		}
	}

	lh.Lock()
	am := lh.unlockedGetRemoteList(vpnIp)
	am.Lock()
	defer am.Unlock()
	lh.Unlock()

	am.unlockedSetV4(lh.myVpnNet.Addr(), vpnIp, calculated, lh.unlockedShouldAddV4)

	return len(calculated) > 0
}

// unlockedGetRemoteList assumes you have the lh lock
func (lh *LightHouse) unlockedGetRemoteList(vpnIp netip.Addr) *RemoteList {
	am, ok := lh.addrMap[vpnIp]
	if !ok {
		am = NewRemoteList(func(a netip.Addr) bool { return lh.shouldAdd(vpnIp, a) })
		lh.addrMap[vpnIp] = am
	}
	return am
}

func (lh *LightHouse) shouldAdd(vpnIp netip.Addr, to netip.Addr) bool {
	allow := lh.GetRemoteAllowList().Allow(vpnIp, to)
	if lh.l.Level >= logrus.TraceLevel {
		lh.l.WithField("remoteIp", vpnIp).WithField("allow", allow).Trace("remoteAllowList.Allow")
	}
	if !allow || lh.myVpnNet.Contains(to) {
		return false
	}

	return true
}

// unlockedShouldAddV4 checks if to is allowed by our allow list
func (lh *LightHouse) unlockedShouldAddV4(vpnIp netip.Addr, to *Ip4AndPort) bool {
	ip := AddrPortFromIp4AndPort(to)
	allow := lh.GetRemoteAllowList().Allow(vpnIp, ip.Addr())
	if lh.l.Level >= logrus.TraceLevel {
		lh.l.WithField("remoteIp", vpnIp).WithField("allow", allow).Trace("remoteAllowList.Allow")
	}

	if !allow || lh.myVpnNet.Contains(ip.Addr()) {
		return false
	}

	return true
}

// unlockedShouldAddV6 checks if to is allowed by our allow list
func (lh *LightHouse) unlockedShouldAddV6(vpnIp netip.Addr, to *Ip6AndPort) bool {
	ip := AddrPortFromIp6AndPort(to)
	allow := lh.GetRemoteAllowList().Allow(vpnIp, ip.Addr())
	if lh.l.Level >= logrus.TraceLevel {
		lh.l.WithField("remoteIp", lhIp6ToIp(to)).WithField("allow", allow).Trace("remoteAllowList.Allow")
	}

	if !allow || lh.myVpnNet.Contains(ip.Addr()) {
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

func (lh *LightHouse) IsLighthouseIP(vpnIp netip.Addr) bool {
	if _, ok := lh.GetLighthouses()[vpnIp]; ok {
		return true
	}
	return false
}

func NewLhQueryByInt(vpnIp netip.Addr) *NebulaMeta {
	if vpnIp.Is6() {
		//TODO: need to support ipv6
		panic("ipv6 is not yet supported")
	}

	b := vpnIp.As4()
	return &NebulaMeta{
		Type: NebulaMeta_HostQuery,
		Details: &NebulaMetaDetails{
			VpnIp: binary.BigEndian.Uint32(b[:]),
		},
	}
}

func AddrPortFromIp4AndPort(ip *Ip4AndPort) netip.AddrPort {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], ip.Ip)
	return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(ip.Port))
}

func AddrPortFromIp6AndPort(ip *Ip6AndPort) netip.AddrPort {
	b := [16]byte{}
	binary.BigEndian.PutUint64(b[:8], ip.Hi)
	binary.BigEndian.PutUint64(b[8:], ip.Lo)
	return netip.AddrPortFrom(netip.AddrFrom16(b), uint16(ip.Port))
}

func NewIp4AndPortFromNetIP(ip netip.Addr, port uint16) *Ip4AndPort {
	v4Addr := ip.As4()
	return &Ip4AndPort{
		Ip:   binary.BigEndian.Uint32(v4Addr[:]),
		Port: uint32(port),
	}
}

// TODO: IPV6-WORK we can delete some more of these
func NewIp6AndPortFromNetIP(ip netip.Addr, port uint16) *Ip6AndPort {
	ip6Addr := ip.As16()
	return &Ip6AndPort{
		Hi:   binary.BigEndian.Uint64(ip6Addr[:8]),
		Lo:   binary.BigEndian.Uint64(ip6Addr[8:]),
		Port: uint32(port),
	}
}

func (lh *LightHouse) startQueryWorker() {
	if lh.amLighthouse {
		return
	}

	go func() {
		nb := make([]byte, 12, 12)
		out := make([]byte, mtu)

		for {
			select {
			case <-lh.ctx.Done():
				return
			case ip := <-lh.queryChan:
				lh.innerQueryServer(ip, nb, out)
			}
		}
	}()
}

func (lh *LightHouse) innerQueryServer(ip netip.Addr, nb, out []byte) {
	if lh.IsLighthouseIP(ip) {
		return
	}

	// Send a query to the lighthouses and hope for the best next time
	query, err := NewLhQueryByInt(ip).Marshal()
	if err != nil {
		lh.l.WithError(err).WithField("vpnIp", ip).Error("Failed to marshal lighthouse query payload")
		return
	}

	lighthouses := lh.GetLighthouses()
	lh.metricTx(NebulaMeta_HostQuery, int64(len(lighthouses)))

	for n := range lighthouses {
		lh.ifce.SendMessageToVpnIp(header.LightHouse, 0, n, query, nb, out)
	}
}

func (lh *LightHouse) StartUpdateWorker() {
	interval := lh.GetUpdateInterval()
	if lh.amLighthouse || interval == 0 {
		return
	}

	clockSource := time.NewTicker(time.Second * time.Duration(interval))
	updateCtx, cancel := context.WithCancel(lh.ctx)
	lh.updateCancel = cancel

	go func() {
		defer clockSource.Stop()

		for {
			lh.SendUpdate()

			select {
			case <-updateCtx.Done():
				return
			case <-clockSource.C:
				continue
			}
		}
	}()
}

func (lh *LightHouse) SendUpdate() {
	var v4 []*Ip4AndPort
	var v6 []*Ip6AndPort

	for _, e := range lh.GetAdvertiseAddrs() {
		if e.Addr().Is4() {
			v4 = append(v4, NewIp4AndPortFromNetIP(e.Addr(), e.Port()))
		} else {
			v6 = append(v6, NewIp6AndPortFromNetIP(e.Addr(), e.Port()))
		}
	}

	lal := lh.GetLocalAllowList()
	for _, e := range localIps(lh.l, lal) {
		if lh.myVpnNet.Contains(e) {
			continue
		}

		// Only add IPs that aren't my VPN/tun IP
		if e.Is4() {
			v4 = append(v4, NewIp4AndPortFromNetIP(e, uint16(lh.nebulaPort)))
		} else {
			v6 = append(v6, NewIp6AndPortFromNetIP(e, uint16(lh.nebulaPort)))
		}
	}

	var relays []uint32
	for _, r := range lh.GetRelaysForMe() {
		//TODO: IPV6-WORK both relays and vpnip need ipv6 support
		b := r.As4()
		relays = append(relays, binary.BigEndian.Uint32(b[:]))
	}

	//TODO: IPV6-WORK both relays and vpnip need ipv6 support
	b := lh.myVpnNet.Addr().As4()

	m := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotification,
		Details: &NebulaMetaDetails{
			VpnIp:       binary.BigEndian.Uint32(b[:]),
			Ip4AndPorts: v4,
			Ip6AndPorts: v6,
			RelayVpnIp:  relays,
		},
	}

	lighthouses := lh.GetLighthouses()
	lh.metricTx(NebulaMeta_HostUpdateNotification, int64(len(lighthouses)))
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	mm, err := m.Marshal()
	if err != nil {
		lh.l.WithError(err).Error("Error while marshaling for lighthouse update")
		return
	}

	for vpnIp := range lighthouses {
		lh.ifce.SendMessageToVpnIp(header.LightHouse, 0, vpnIp, mm, nb, out)
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
	lh.metrics.Rx(header.MessageType(t), 0, i)
}

func (lh *LightHouse) metricTx(t NebulaMeta_MessageType, i int64) {
	lh.metrics.Tx(header.MessageType(t), 0, i)
}

// This method is similar to Reset(), but it re-uses the pointer structs
// so that we don't have to re-allocate them
func (lhh *LightHouseHandler) resetMeta() *NebulaMeta {
	details := lhh.meta.Details
	lhh.meta.Reset()

	// Keep the array memory around
	details.Ip4AndPorts = details.Ip4AndPorts[:0]
	details.Ip6AndPorts = details.Ip6AndPorts[:0]
	details.RelayVpnIp = details.RelayVpnIp[:0]
	lhh.meta.Details = details

	return lhh.meta
}

func lhHandleRequest(lhh *LightHouseHandler, f *Interface) udp.LightHouseHandlerFunc {
	return func(rAddr netip.AddrPort, vpnIp netip.Addr, p []byte) {
		lhh.HandleRequest(rAddr, vpnIp, p, f)
	}
}

func (lhh *LightHouseHandler) HandleRequest(rAddr netip.AddrPort, vpnIp netip.Addr, p []byte, w EncWriter) {
	n := lhh.resetMeta()
	err := n.Unmarshal(p)
	if err != nil {
		lhh.l.WithError(err).WithField("vpnIp", vpnIp).WithField("udpAddr", rAddr).
			Error("Failed to unmarshal lighthouse packet")
		//TODO: send recv_error?
		return
	}

	if n.Details == nil {
		lhh.l.WithField("vpnIp", vpnIp).WithField("udpAddr", rAddr).
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
		lhh.handleHostUpdateNotification(n, vpnIp, w)

	case NebulaMeta_HostMovedNotification:
	case NebulaMeta_HostPunchNotification:
		lhh.handleHostPunchNotification(n, vpnIp, w)

	case NebulaMeta_HostUpdateNotificationAck:
		// noop
	}
}

func (lhh *LightHouseHandler) handleHostQuery(n *NebulaMeta, vpnIp netip.Addr, addr netip.AddrPort, w EncWriter) {
	// Exit if we don't answer queries
	if !lhh.lh.amLighthouse {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.Debugln("I don't answer queries, but received from: ", addr)
		}
		return
	}

	//TODO: we can DRY this further
	reqVpnIp := n.Details.VpnIp

	//TODO: IPV6-WORK
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], n.Details.VpnIp)
	queryVpnIp := netip.AddrFrom4(b)

	//TODO: Maybe instead of marshalling into n we marshal into a new `r` to not nuke our current request data
	found, ln, err := lhh.lh.queryAndPrepMessage(queryVpnIp, func(c *cache) (int, error) {
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostQueryReply
		n.Details.VpnIp = reqVpnIp

		lhh.coalesceAnswers(c, n)

		return n.MarshalTo(lhh.pb)
	})

	if !found {
		return
	}

	if err != nil {
		lhh.l.WithError(err).WithField("vpnIp", vpnIp).Error("Failed to marshal lighthouse host query reply")
		return
	}

	lhh.lh.metricTx(NebulaMeta_HostQueryReply, 1)
	w.SendMessageToVpnIp(header.LightHouse, 0, vpnIp, lhh.pb[:ln], lhh.nb, lhh.out[:0])

	// This signals the other side to punch some zero byte udp packets
	found, ln, err = lhh.lh.queryAndPrepMessage(vpnIp, func(c *cache) (int, error) {
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostPunchNotification
		//TODO: IPV6-WORK
		b = vpnIp.As4()
		n.Details.VpnIp = binary.BigEndian.Uint32(b[:])
		lhh.coalesceAnswers(c, n)

		return n.MarshalTo(lhh.pb)
	})

	if !found {
		return
	}

	if err != nil {
		lhh.l.WithError(err).WithField("vpnIp", vpnIp).Error("Failed to marshal lighthouse host was queried for")
		return
	}

	lhh.lh.metricTx(NebulaMeta_HostPunchNotification, 1)

	//TODO: IPV6-WORK
	binary.BigEndian.PutUint32(b[:], reqVpnIp)
	sendTo := netip.AddrFrom4(b)
	w.SendMessageToVpnIp(header.LightHouse, 0, sendTo, lhh.pb[:ln], lhh.nb, lhh.out[:0])
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

	if c.relay != nil {
		//TODO: IPV6-WORK
		relays := make([]uint32, len(c.relay.relay))
		b := [4]byte{}
		for i, _ := range relays {
			b = c.relay.relay[i].As4()
			relays[i] = binary.BigEndian.Uint32(b[:])
		}
		n.Details.RelayVpnIp = append(n.Details.RelayVpnIp, relays...)
	}
}

func (lhh *LightHouseHandler) handleHostQueryReply(n *NebulaMeta, vpnIp netip.Addr) {
	if !lhh.lh.IsLighthouseIP(vpnIp) {
		return
	}

	lhh.lh.Lock()
	//TODO: IPV6-WORK
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], n.Details.VpnIp)
	certVpnIp := netip.AddrFrom4(b)
	am := lhh.lh.unlockedGetRemoteList(certVpnIp)
	am.Lock()
	lhh.lh.Unlock()

	//TODO: IPV6-WORK
	am.unlockedSetV4(vpnIp, certVpnIp, n.Details.Ip4AndPorts, lhh.lh.unlockedShouldAddV4)
	am.unlockedSetV6(vpnIp, certVpnIp, n.Details.Ip6AndPorts, lhh.lh.unlockedShouldAddV6)

	//TODO: IPV6-WORK
	relays := make([]netip.Addr, len(n.Details.RelayVpnIp))
	for i, _ := range n.Details.RelayVpnIp {
		binary.BigEndian.PutUint32(b[:], n.Details.RelayVpnIp[i])
		relays[i] = netip.AddrFrom4(b)
	}
	am.unlockedSetRelay(vpnIp, certVpnIp, relays)
	am.Unlock()

	// Non-blocking attempt to trigger, skip if it would block
	select {
	case lhh.lh.handshakeTrigger <- certVpnIp:
	default:
	}
}

func (lhh *LightHouseHandler) handleHostUpdateNotification(n *NebulaMeta, vpnIp netip.Addr, w EncWriter) {
	if !lhh.lh.amLighthouse {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.Debugln("I am not a lighthouse, do not take host updates: ", vpnIp)
		}
		return
	}

	//Simple check that the host sent this not someone else
	//TODO: IPV6-WORK
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], n.Details.VpnIp)
	detailsVpnIp := netip.AddrFrom4(b)
	if detailsVpnIp != vpnIp {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.WithField("vpnIp", vpnIp).WithField("answer", detailsVpnIp).Debugln("Host sent invalid update")
		}
		return
	}

	lhh.lh.Lock()
	am := lhh.lh.unlockedGetRemoteList(vpnIp)
	am.Lock()
	lhh.lh.Unlock()

	am.unlockedSetV4(vpnIp, detailsVpnIp, n.Details.Ip4AndPorts, lhh.lh.unlockedShouldAddV4)
	am.unlockedSetV6(vpnIp, detailsVpnIp, n.Details.Ip6AndPorts, lhh.lh.unlockedShouldAddV6)

	//TODO: IPV6-WORK
	relays := make([]netip.Addr, len(n.Details.RelayVpnIp))
	for i, _ := range n.Details.RelayVpnIp {
		binary.BigEndian.PutUint32(b[:], n.Details.RelayVpnIp[i])
		relays[i] = netip.AddrFrom4(b)
	}
	am.unlockedSetRelay(vpnIp, detailsVpnIp, relays)
	am.Unlock()

	n = lhh.resetMeta()
	n.Type = NebulaMeta_HostUpdateNotificationAck

	//TODO: IPV6-WORK
	vpnIpB := vpnIp.As4()
	n.Details.VpnIp = binary.BigEndian.Uint32(vpnIpB[:])
	ln, err := n.MarshalTo(lhh.pb)

	if err != nil {
		lhh.l.WithError(err).WithField("vpnIp", vpnIp).Error("Failed to marshal lighthouse host update ack")
		return
	}

	lhh.lh.metricTx(NebulaMeta_HostUpdateNotificationAck, 1)
	w.SendMessageToVpnIp(header.LightHouse, 0, vpnIp, lhh.pb[:ln], lhh.nb, lhh.out[:0])
}

func (lhh *LightHouseHandler) handleHostPunchNotification(n *NebulaMeta, vpnIp netip.Addr, w EncWriter) {
	if !lhh.lh.IsLighthouseIP(vpnIp) {
		return
	}

	empty := []byte{0}
	punch := func(vpnPeer netip.AddrPort) {
		if !vpnPeer.IsValid() {
			return
		}

		go func() {
			time.Sleep(lhh.lh.punchy.GetDelay())
			lhh.lh.metricHolepunchTx.Inc(1)
			lhh.lh.punchConn.WriteTo(empty, vpnPeer)
		}()

		if lhh.l.Level >= logrus.DebugLevel {
			//TODO: lacking the ip we are actually punching on, old: l.Debugf("Punching %s on %d for %s", IntIp(a.Ip), a.Port, IntIp(n.Details.VpnIp))
			//TODO: IPV6-WORK, make this debug line not suck
			b := [4]byte{}
			binary.BigEndian.PutUint32(b[:], n.Details.VpnIp)
			lhh.l.Debugf("Punching on %d for %v", vpnPeer.Port(), netip.AddrFrom4(b))
		}
	}

	for _, a := range n.Details.Ip4AndPorts {
		punch(AddrPortFromIp4AndPort(a))
	}

	for _, a := range n.Details.Ip6AndPorts {
		punch(AddrPortFromIp6AndPort(a))
	}

	// This sends a nebula test packet to the host trying to contact us. In the case
	// of a double nat or other difficult scenario, this may help establish
	// a tunnel.
	if lhh.lh.punchy.GetRespond() {
		//TODO: IPV6-WORK
		b := [4]byte{}
		binary.BigEndian.PutUint32(b[:], n.Details.VpnIp)
		queryVpnIp := netip.AddrFrom4(b)
		go func() {
			time.Sleep(lhh.lh.punchy.GetRespondDelay())
			if lhh.l.Level >= logrus.DebugLevel {
				lhh.l.Debugf("Sending a nebula test packet to vpn ip %s", queryVpnIp)
			}
			//NOTE: we have to allocate a new output buffer here since we are spawning a new goroutine
			// for each punchBack packet. We should move this into a timerwheel or a single goroutine
			// managed by a channel.
			w.SendMessageToVpnIp(header.Test, header.TestRequest, queryVpnIp, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
		}()
	}
}
