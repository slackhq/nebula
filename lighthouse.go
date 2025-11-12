package nebula

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/slackhq/nebula/util"
)

var ErrHostNotKnown = errors.New("host not known")
var ErrBadDetailsVpnAddr = errors.New("invalid packet, malformed detailsVpnAddr")

type LightHouse struct {
	//TODO: We need a timer wheel to kick out vpnAddrs that haven't reported in a long time
	sync.RWMutex //Because we concurrently read and write to our maps
	ctx          context.Context
	amLighthouse bool

	myVpnNetworks      []netip.Prefix
	myVpnNetworksTable *bart.Lite
	punchConn          udp.Conn
	punchy             *Punchy

	// Local cache of answers from light houses
	// map of vpn addr to answers
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
	lighthouses atomic.Pointer[[]netip.Addr]

	interval     atomic.Int64
	updateCancel context.CancelFunc
	ifce         EncWriter
	nebulaPort   uint32 // 32 bits because protobuf does not have a uint16

	advertiseAddrs atomic.Pointer[[]netip.AddrPort]

	// Addr's of relays that can be used by peers to access me
	relaysForMe atomic.Pointer[[]netip.Addr]

	queryChan chan netip.Addr

	calculatedRemotes atomic.Pointer[bart.Table[[]*calculatedRemote]] // Maps VpnAddr to []*calculatedRemote

	metrics           *MessageMetrics
	metricHolepunchTx metrics.Counter
	l                 *logrus.Logger
}

// NewLightHouseFromConfig will build a Lighthouse struct from the values provided in the config object
// addrMap should be nil unless this is during a config reload
func NewLightHouseFromConfig(ctx context.Context, l *logrus.Logger, c *config.C, cs *CertState, pc udp.Conn, p *Punchy) (*LightHouse, error) {
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
		ctx:                ctx,
		amLighthouse:       amLighthouse,
		myVpnNetworks:      cs.myVpnNetworks,
		myVpnNetworksTable: cs.myVpnNetworksTable,
		addrMap:            make(map[netip.Addr]*RemoteList),
		nebulaPort:         nebulaPort,
		punchConn:          pc,
		punchy:             p,
		queryChan:          make(chan netip.Addr, c.GetUint32("handshakes.query_buffer", 64)),
		l:                  l,
	}
	lighthouses := make([]netip.Addr, 0)
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

func (lh *LightHouse) GetLighthouses() []netip.Addr {
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

			addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
			if err != nil {
				return util.NewContextualError("Unable to lookup lighthouse.advertise_addrs entry", m{"addr": rawAddr, "entry": i + 1}, err)
			}
			if len(addrs) == 0 {
				return util.NewContextualError("Unable to lookup lighthouse.advertise_addrs entry", m{"addr": rawAddr, "entry": i + 1}, nil)
			}

			port, err := strconv.Atoi(sport)
			if err != nil {
				return util.NewContextualError("Unable to parse port in lighthouse.advertise_addrs entry", m{"addr": rawAddr, "entry": i + 1}, err)
			}

			if port == 0 {
				port = int(lh.nebulaPort)
			}

			//TODO: we could technically insert all returned addrs instead of just the first one if a dns lookup was used
			addr := addrs[0].Unmap()
			if lh.myVpnNetworksTable.Contains(addr) {
				lh.l.WithField("addr", rawAddr).WithField("entry", i+1).
					Warn("Ignoring lighthouse.advertise_addrs report because it is within the nebula network range")
				continue
			}

			advAddrs = append(advAddrs, netip.AddrPortFrom(addr, uint16(port)))
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
			lh.l.Info("lighthouse.calculated_remotes has changed")
		}
	}

	//NOTE: many things will get much simpler when we combine static_host_map and lighthouse.hosts in config
	if initial || c.HasChanged("static_host_map") || c.HasChanged("static_map.cadence") || c.HasChanged("static_map.network") || c.HasChanged("static_map.lookup_timeout") {
		// Clean up. Entries still in the static_host_map will be re-built.
		// Entries no longer present must have their (possible) background DNS goroutines stopped.
		if existingStaticList := lh.staticList.Load(); existingStaticList != nil {
			lh.RLock()
			for staticVpnAddr := range *existingStaticList {
				if am, ok := lh.addrMap[staticVpnAddr]; ok && am != nil {
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
		lhList, err := lh.parseLighthouses(c)
		if err != nil {
			return err
		}

		lh.lighthouses.Store(&lhList)
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
				configRIP, err := netip.ParseAddr(v)
				if err != nil {
					lh.l.WithField("relay", v).WithError(err).Warn("Parse relay from config failed")
				} else {
					lh.l.WithField("relay", v).Info("Read relay from config")
					relaysForMe = append(relaysForMe, configRIP)
				}
			}
			lh.relaysForMe.Store(&relaysForMe)
		}
	}

	return nil
}

func (lh *LightHouse) parseLighthouses(c *config.C) ([]netip.Addr, error) {
	lhs := c.GetStringSlice("lighthouse.hosts", []string{})
	if lh.amLighthouse && len(lhs) != 0 {
		lh.l.Warn("lighthouse.am_lighthouse enabled on node but upstream lighthouses exist in config")
	}
	out := make([]netip.Addr, len(lhs))

	for i, host := range lhs {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return nil, util.NewContextualError("Unable to parse lighthouse host entry", m{"host": host, "entry": i + 1}, err)
		}

		if !lh.myVpnNetworksTable.Contains(addr) {
			lh.l.WithFields(m{"vpnAddr": addr, "networks": lh.myVpnNetworks}).
				Warn("lighthouse host is not within our networks, lighthouse functionality will work but layer 3 network traffic to the lighthouse will not")
		}
		out[i] = addr
	}

	if !lh.amLighthouse && len(out) == 0 {
		lh.l.Warn("No lighthouse.hosts configured, this host will only be able to initiate tunnels with static_host_map entries")
	}

	staticList := lh.GetStaticHostList()
	for i := range out {
		if _, ok := staticList[out[i]]; !ok {
			return nil, fmt.Errorf("lighthouse %s does not have a static_host_map entry", out[i])
		}
	}

	return out, nil
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

	shm := c.GetMap("static_host_map", map[string]any{})
	i := 0

	for k, v := range shm {
		vpnAddr, err := netip.ParseAddr(fmt.Sprintf("%v", k))
		if err != nil {
			return util.NewContextualError("Unable to parse static_host_map entry", m{"host": k, "entry": i + 1}, err)
		}

		if !lh.myVpnNetworksTable.Contains(vpnAddr) {
			lh.l.WithFields(m{"vpnAddr": vpnAddr, "networks": lh.myVpnNetworks, "entry": i + 1}).
				Warn("static_host_map key is not within our networks, layer 3 network traffic to this host will not work")
		}

		vals, ok := v.([]any)
		if !ok {
			vals = []any{v}
		}
		remoteAddrs := []string{}
		for _, v := range vals {
			remoteAddrs = append(remoteAddrs, fmt.Sprintf("%v", v))
		}

		err = lh.addStaticRemotes(i, d, network, lookupTimeout, vpnAddr, remoteAddrs, staticList)
		if err != nil {
			return err
		}
		i++
	}

	return nil
}

func (lh *LightHouse) Query(vpnAddr netip.Addr) *RemoteList {
	if !lh.IsLighthouseAddr(vpnAddr) {
		lh.QueryServer(vpnAddr)
	}
	lh.RLock()
	if v, ok := lh.addrMap[vpnAddr]; ok {
		lh.RUnlock()
		return v
	}
	lh.RUnlock()
	return nil
}

// QueryServer is asynchronous so no reply should be expected
func (lh *LightHouse) QueryServer(vpnAddr netip.Addr) {
	// Don't put lighthouse addrs in the query channel because we can't query lighthouses about lighthouses
	if lh.amLighthouse || lh.IsLighthouseAddr(vpnAddr) {
		return
	}

	lh.queryChan <- vpnAddr
}

func (lh *LightHouse) QueryCache(vpnAddrs []netip.Addr) *RemoteList {
	lh.RLock()
	if v, ok := lh.addrMap[vpnAddrs[0]]; ok {
		lh.RUnlock()
		return v
	}
	lh.RUnlock()

	lh.Lock()
	defer lh.Unlock()
	// Add an entry if we don't already have one
	return lh.unlockedGetRemoteList(vpnAddrs) //todo CERT-V2 this contains addrmap lookups we could potentially skip
}

// queryAndPrepMessage is a lock helper on RemoteList, assisting the caller to build a lighthouse message containing
// details from the remote list. It looks for a hit in the addrMap and a hit in the RemoteList under the owner vpnAddr
// If one is found then f() is called with proper locking, f() must return result of n.MarshalTo()
func (lh *LightHouse) queryAndPrepMessage(vpnAddr netip.Addr, f func(*cache) (int, error)) (bool, int, error) {
	lh.RLock()
	// Do we have an entry in the main cache?
	if v, ok := lh.addrMap[vpnAddr]; ok {
		// Swap lh lock for remote list lock
		v.RLock()
		defer v.RUnlock()

		lh.RUnlock()

		// We may be asking about a non primary address so lets get the primary address
		if slices.Contains(v.vpnAddrs, vpnAddr) {
			vpnAddr = v.vpnAddrs[0]
		}
		c := v.cache[vpnAddr]
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

func (lh *LightHouse) DeleteVpnAddrs(allVpnAddrs []netip.Addr) {
	// First we check the static host map. If any of the VpnAddrs to be deleted are present, do nothing.
	staticList := lh.GetStaticHostList()
	for _, addr := range allVpnAddrs {
		if _, ok := staticList[addr]; ok {
			return
		}
	}

	// None of the VpnAddrs were present. Now we can do the deletes.
	lh.Lock()
	rm, ok := lh.addrMap[allVpnAddrs[0]]
	if ok {
		for _, addr := range allVpnAddrs {
			srm := lh.addrMap[addr]
			if srm == rm {
				delete(lh.addrMap, addr)
				if lh.l.Level >= logrus.DebugLevel {
					lh.l.Debugf("deleting %s from lighthouse.", addr)
				}
			}
		}
	}
	lh.Unlock()
}

// AddStaticRemote adds a static host entry for vpnAddr as ourselves as the owner
// We are the owner because we don't want a lighthouse server to advertise for static hosts it was configured with
// And we don't want a lighthouse query reply to interfere with our learned cache if we are a client
// NOTE: this function should not interact with any hot path objects, like lh.staticList, the caller should handle it
func (lh *LightHouse) addStaticRemotes(i int, d time.Duration, network string, timeout time.Duration, vpnAddr netip.Addr, toAddrs []string, staticList map[netip.Addr]struct{}) error {
	lh.Lock()
	am := lh.unlockedGetRemoteList([]netip.Addr{vpnAddr})
	am.Lock()
	defer am.Unlock()
	ctx := lh.ctx
	lh.Unlock()

	hr, err := NewHostnameResults(ctx, lh.l, d, network, timeout, toAddrs, func() {
		// This callback runs whenever the DNS hostname resolver finds a different set of addr's
		// in its resolution for hostnames.
		am.Lock()
		defer am.Unlock()
		am.shouldRebuild = true
	})
	if err != nil {
		return util.NewContextualError("Static host address could not be parsed", m{"vpnAddr": vpnAddr, "entry": i + 1}, err)
	}
	am.unlockedSetHostnamesResults(hr)

	for _, addrPort := range hr.GetAddrs() {
		if !lh.shouldAdd([]netip.Addr{vpnAddr}, addrPort.Addr()) {
			continue
		}
		switch {
		case addrPort.Addr().Is4():
			am.unlockedPrependV4(lh.myVpnNetworks[0].Addr(), netAddrToProtoV4AddrPort(addrPort.Addr(), addrPort.Port()))
		case addrPort.Addr().Is6():
			am.unlockedPrependV6(lh.myVpnNetworks[0].Addr(), netAddrToProtoV6AddrPort(addrPort.Addr(), addrPort.Port()))
		}
	}

	// Mark it as static in the caller provided map
	staticList[vpnAddr] = struct{}{}
	return nil
}

// addCalculatedRemotes adds any calculated remotes based on the
// lighthouse.calculated_remotes configuration. It returns true if any
// calculated remotes were added
func (lh *LightHouse) addCalculatedRemotes(vpnAddr netip.Addr) bool {
	tree := lh.getCalculatedRemotes()
	if tree == nil {
		return false
	}
	calculatedRemotes, ok := tree.Lookup(vpnAddr)
	if !ok {
		return false
	}

	var calculatedV4 []*V4AddrPort
	var calculatedV6 []*V6AddrPort
	for _, cr := range calculatedRemotes {
		if vpnAddr.Is4() {
			c := cr.ApplyV4(vpnAddr)
			if c != nil {
				calculatedV4 = append(calculatedV4, c)
			}
		} else if vpnAddr.Is6() {
			c := cr.ApplyV6(vpnAddr)
			if c != nil {
				calculatedV6 = append(calculatedV6, c)
			}
		}
	}

	lh.Lock()
	am := lh.unlockedGetRemoteList([]netip.Addr{vpnAddr})
	am.Lock()
	defer am.Unlock()
	lh.Unlock()

	if len(calculatedV4) > 0 {
		am.unlockedSetV4(lh.myVpnNetworks[0].Addr(), vpnAddr, calculatedV4, lh.unlockedShouldAddV4)
	}

	if len(calculatedV6) > 0 {
		am.unlockedSetV6(lh.myVpnNetworks[0].Addr(), vpnAddr, calculatedV6, lh.unlockedShouldAddV6)
	}

	return len(calculatedV4) > 0 || len(calculatedV6) > 0
}

// unlockedGetRemoteList assumes you have the lh lock
func (lh *LightHouse) unlockedGetRemoteList(allAddrs []netip.Addr) *RemoteList {
	// before we go and make a new remotelist, we need to make sure we don't have one for any of this set of vpnaddrs yet
	for i, addr := range allAddrs {
		am, ok := lh.addrMap[addr]
		if ok {
			if i != 0 {
				lh.addrMap[allAddrs[0]] = am
			}
			return am
		}
	}

	am := NewRemoteList(allAddrs, lh.shouldAdd)
	for _, addr := range allAddrs {
		lh.addrMap[addr] = am
	}
	return am
}

func (lh *LightHouse) shouldAdd(vpnAddrs []netip.Addr, to netip.Addr) bool {
	allow := lh.GetRemoteAllowList().AllowAll(vpnAddrs, to)
	if lh.l.Level >= logrus.TraceLevel {
		lh.l.WithField("vpnAddrs", vpnAddrs).WithField("udpAddr", to).WithField("allow", allow).
			Trace("remoteAllowList.Allow")
	}
	if !allow {
		return false
	}

	if lh.myVpnNetworksTable.Contains(to) {
		return false
	}

	return true
}

// unlockedShouldAddV4 checks if to is allowed by our allow list
func (lh *LightHouse) unlockedShouldAddV4(vpnAddr netip.Addr, to *V4AddrPort) bool {
	udpAddr := protoV4AddrPortToNetAddrPort(to)
	allow := lh.GetRemoteAllowList().Allow(vpnAddr, udpAddr.Addr())
	if lh.l.Level >= logrus.TraceLevel {
		lh.l.WithField("vpnAddr", vpnAddr).WithField("udpAddr", udpAddr).WithField("allow", allow).
			Trace("remoteAllowList.Allow")
	}

	if !allow {
		return false
	}

	if lh.myVpnNetworksTable.Contains(udpAddr.Addr()) {
		return false
	}

	return true
}

// unlockedShouldAddV6 checks if to is allowed by our allow list
func (lh *LightHouse) unlockedShouldAddV6(vpnAddr netip.Addr, to *V6AddrPort) bool {
	udpAddr := protoV6AddrPortToNetAddrPort(to)
	allow := lh.GetRemoteAllowList().Allow(vpnAddr, udpAddr.Addr())
	if lh.l.Level >= logrus.TraceLevel {
		lh.l.WithField("vpnAddr", vpnAddr).WithField("udpAddr", udpAddr).WithField("allow", allow).
			Trace("remoteAllowList.Allow")
	}

	if !allow {
		return false
	}

	if lh.myVpnNetworksTable.Contains(udpAddr.Addr()) {
		return false
	}

	return true
}

func (lh *LightHouse) IsLighthouseAddr(vpnAddr netip.Addr) bool {
	l := lh.GetLighthouses()
	for i := range l {
		if l[i] == vpnAddr {
			return true
		}
	}
	return false
}

func (lh *LightHouse) IsAnyLighthouseAddr(vpnAddrs []netip.Addr) bool {
	l := lh.GetLighthouses()
	for i := range vpnAddrs {
		for j := range l {
			if l[j] == vpnAddrs[i] {
				return true
			}
		}
	}
	return false
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
			case addr := <-lh.queryChan:
				lh.innerQueryServer(addr, nb, out)
			}
		}
	}()
}

func (lh *LightHouse) innerQueryServer(addr netip.Addr, nb, out []byte) {
	if lh.IsLighthouseAddr(addr) {
		return
	}

	msg := &NebulaMeta{
		Type:    NebulaMeta_HostQuery,
		Details: &NebulaMetaDetails{},
	}

	var v1Query, v2Query []byte
	var err error
	var v cert.Version
	queried := 0
	lighthouses := lh.GetLighthouses()

	for _, lhVpnAddr := range lighthouses {
		hi := lh.ifce.GetHostInfo(lhVpnAddr)
		if hi != nil {
			v = hi.ConnectionState.myCert.Version()
		} else {
			v = lh.ifce.GetCertState().initiatingVersion
		}

		if v == cert.Version1 {
			if !addr.Is4() {
				lh.l.WithField("queryVpnAddr", addr).WithField("lighthouseAddr", lhVpnAddr).
					Error("Can't query lighthouse for v6 address using a v1 protocol")
				continue
			}

			if v1Query == nil {
				b := addr.As4()
				msg.Details.VpnAddr = nil
				msg.Details.OldVpnAddr = binary.BigEndian.Uint32(b[:])

				v1Query, err = msg.Marshal()
				if err != nil {
					lh.l.WithError(err).WithField("queryVpnAddr", addr).
						WithField("lighthouseAddr", lhVpnAddr).
						Error("Failed to marshal lighthouse v1 query payload")
					continue
				}
			}

			lh.ifce.SendMessageToVpnAddr(header.LightHouse, 0, lhVpnAddr, v1Query, nb, out)
			queried++

		} else if v == cert.Version2 {
			if v2Query == nil {
				msg.Details.OldVpnAddr = 0
				msg.Details.VpnAddr = netAddrToProtoAddr(addr)

				v2Query, err = msg.Marshal()
				if err != nil {
					lh.l.WithError(err).WithField("queryVpnAddr", addr).
						WithField("lighthouseAddr", lhVpnAddr).
						Error("Failed to marshal lighthouse v2 query payload")
					continue
				}
			}

			lh.ifce.SendMessageToVpnAddr(header.LightHouse, 0, lhVpnAddr, v2Query, nb, out)
			queried++

		} else {
			lh.l.Debugf("Can not query lighthouse for %v using unknown protocol version: %v", addr, v)
			continue
		}
	}

	lh.metricTx(NebulaMeta_HostQuery, int64(queried))
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
	var v4 []*V4AddrPort
	var v6 []*V6AddrPort

	for _, e := range lh.GetAdvertiseAddrs() {
		if e.Addr().Is4() {
			v4 = append(v4, netAddrToProtoV4AddrPort(e.Addr(), e.Port()))
		} else {
			v6 = append(v6, netAddrToProtoV6AddrPort(e.Addr(), e.Port()))
		}
	}

	lal := lh.GetLocalAllowList()
	for _, e := range localAddrs(lh.l, lal) {
		if lh.myVpnNetworksTable.Contains(e) {
			continue
		}

		// Only add addrs that aren't my VPN/tun networks
		if e.Is4() {
			v4 = append(v4, netAddrToProtoV4AddrPort(e, uint16(lh.nebulaPort)))
		} else {
			v6 = append(v6, netAddrToProtoV6AddrPort(e, uint16(lh.nebulaPort)))
		}
	}

	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	var v1Update, v2Update []byte
	var err error
	updated := 0
	lighthouses := lh.GetLighthouses()

	for _, lhVpnAddr := range lighthouses {
		var v cert.Version
		hi := lh.ifce.GetHostInfo(lhVpnAddr)
		if hi != nil {
			v = hi.ConnectionState.myCert.Version()
		} else {
			v = lh.ifce.GetCertState().initiatingVersion
		}
		if v == cert.Version1 {
			if v1Update == nil {
				if !lh.myVpnNetworks[0].Addr().Is4() {
					lh.l.WithField("lighthouseAddr", lhVpnAddr).
						Warn("cannot update lighthouse using v1 protocol without an IPv4 address")
					continue
				}
				var relays []uint32
				for _, r := range lh.GetRelaysForMe() {
					if !r.Is4() {
						continue
					}
					b := r.As4()
					relays = append(relays, binary.BigEndian.Uint32(b[:]))
				}
				b := lh.myVpnNetworks[0].Addr().As4()
				msg := NebulaMeta{
					Type: NebulaMeta_HostUpdateNotification,
					Details: &NebulaMetaDetails{
						V4AddrPorts:      v4,
						V6AddrPorts:      v6,
						OldRelayVpnAddrs: relays,
						OldVpnAddr:       binary.BigEndian.Uint32(b[:]),
					},
				}

				v1Update, err = msg.Marshal()
				if err != nil {
					lh.l.WithError(err).WithField("lighthouseAddr", lhVpnAddr).
						Error("Error while marshaling for lighthouse v1 update")
					continue
				}
			}

			lh.ifce.SendMessageToVpnAddr(header.LightHouse, 0, lhVpnAddr, v1Update, nb, out)
			updated++

		} else if v == cert.Version2 {
			if v2Update == nil {
				var relays []*Addr
				for _, r := range lh.GetRelaysForMe() {
					relays = append(relays, netAddrToProtoAddr(r))
				}

				msg := NebulaMeta{
					Type: NebulaMeta_HostUpdateNotification,
					Details: &NebulaMetaDetails{
						V4AddrPorts:   v4,
						V6AddrPorts:   v6,
						RelayVpnAddrs: relays,
					},
				}

				v2Update, err = msg.Marshal()
				if err != nil {
					lh.l.WithError(err).WithField("lighthouseAddr", lhVpnAddr).
						Error("Error while marshaling for lighthouse v2 update")
					continue
				}
			}

			lh.ifce.SendMessageToVpnAddr(header.LightHouse, 0, lhVpnAddr, v2Update, nb, out)
			updated++

		} else {
			lh.l.Debugf("Can not update lighthouse using unknown protocol version: %v", v)
			continue
		}
	}

	lh.metricTx(NebulaMeta_HostUpdateNotification, int64(updated))
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
	details.V4AddrPorts = details.V4AddrPorts[:0]
	details.V6AddrPorts = details.V6AddrPorts[:0]
	details.RelayVpnAddrs = details.RelayVpnAddrs[:0]
	details.OldRelayVpnAddrs = details.OldRelayVpnAddrs[:0]
	details.OldVpnAddr = 0
	details.VpnAddr = nil
	lhh.meta.Details = details

	return lhh.meta
}

func (lhh *LightHouseHandler) HandleRequest(rAddr netip.AddrPort, fromVpnAddrs []netip.Addr, p []byte, w EncWriter) {
	n := lhh.resetMeta()
	err := n.Unmarshal(p)
	if err != nil {
		lhh.l.WithError(err).WithField("vpnAddrs", fromVpnAddrs).WithField("udpAddr", rAddr).
			Error("Failed to unmarshal lighthouse packet")
		return
	}

	if n.Details == nil {
		lhh.l.WithField("vpnAddrs", fromVpnAddrs).WithField("udpAddr", rAddr).
			Error("Invalid lighthouse update")
		return
	}

	lhh.lh.metricRx(n.Type, 1)

	switch n.Type {
	case NebulaMeta_HostQuery:
		lhh.handleHostQuery(n, fromVpnAddrs, rAddr, w)

	case NebulaMeta_HostQueryReply:
		lhh.handleHostQueryReply(n, fromVpnAddrs)

	case NebulaMeta_HostUpdateNotification:
		lhh.handleHostUpdateNotification(n, fromVpnAddrs, w)

	case NebulaMeta_HostMovedNotification:
	case NebulaMeta_HostPunchNotification:
		lhh.handleHostPunchNotification(n, fromVpnAddrs, w)

	case NebulaMeta_HostUpdateNotificationAck:
		// noop
	}
}

func (lhh *LightHouseHandler) handleHostQuery(n *NebulaMeta, fromVpnAddrs []netip.Addr, addr netip.AddrPort, w EncWriter) {
	// Exit if we don't answer queries
	if !lhh.lh.amLighthouse {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.Debugln("I don't answer queries, but received from: ", addr)
		}
		return
	}

	queryVpnAddr, useVersion, err := n.Details.GetVpnAddrAndVersion()
	if err != nil {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.WithField("from", fromVpnAddrs).WithField("details", n.Details).
				Debugln("Dropping malformed HostQuery")
		}
		return
	}
	if useVersion == cert.Version1 && queryVpnAddr.Is6() {
		// this case really shouldn't be possible to represent, but reject it anyway.
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.WithField("vpnAddrs", fromVpnAddrs).WithField("queryVpnAddr", queryVpnAddr).
				Debugln("invalid vpn addr for v1 handleHostQuery")
		}
		return
	}

	found, ln, err := lhh.lh.queryAndPrepMessage(queryVpnAddr, func(c *cache) (int, error) {
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostQueryReply
		if useVersion == cert.Version1 {
			b := queryVpnAddr.As4()
			n.Details.OldVpnAddr = binary.BigEndian.Uint32(b[:])
		} else {
			n.Details.VpnAddr = netAddrToProtoAddr(queryVpnAddr)
		}

		lhh.coalesceAnswers(useVersion, c, n)

		return n.MarshalTo(lhh.pb)
	})

	if !found {
		return
	}

	if err != nil {
		lhh.l.WithError(err).WithField("vpnAddrs", fromVpnAddrs).Error("Failed to marshal lighthouse host query reply")
		return
	}

	lhh.lh.metricTx(NebulaMeta_HostQueryReply, 1)
	w.SendMessageToVpnAddr(header.LightHouse, 0, fromVpnAddrs[0], lhh.pb[:ln], lhh.nb, lhh.out[:0])

	lhh.sendHostPunchNotification(n, fromVpnAddrs, queryVpnAddr, w)
}

// sendHostPunchNotification signals the other side to punch some zero byte udp packets
func (lhh *LightHouseHandler) sendHostPunchNotification(n *NebulaMeta, fromVpnAddrs []netip.Addr, punchNotifDest netip.Addr, w EncWriter) {
	whereToPunch := fromVpnAddrs[0]
	found, ln, err := lhh.lh.queryAndPrepMessage(whereToPunch, func(c *cache) (int, error) {
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostPunchNotification
		targetHI := lhh.lh.ifce.GetHostInfo(punchNotifDest)
		var useVersion cert.Version
		if targetHI == nil {
			useVersion = lhh.lh.ifce.GetCertState().initiatingVersion
		} else {
			crt := targetHI.GetCert().Certificate
			useVersion = crt.Version()
			// we can only retarget if we have a hostinfo
			newDest, ok := findNetworkUnion(crt.Networks(), fromVpnAddrs)
			if ok {
				whereToPunch = newDest
			} else {
				if lhh.l.Level >= logrus.DebugLevel {
					lhh.l.WithField("to", crt.Networks()).Debugln("unable to punch to host, no addresses in common")
				}
			}
		}

		if useVersion == cert.Version1 {
			if !whereToPunch.Is4() {
				return 0, fmt.Errorf("invalid vpn addr for v1 handleHostQuery")
			}
			b := whereToPunch.As4()
			n.Details.OldVpnAddr = binary.BigEndian.Uint32(b[:])
		} else if useVersion == cert.Version2 {
			n.Details.VpnAddr = netAddrToProtoAddr(whereToPunch)
		} else {
			return 0, errors.New("unsupported version")
		}
		lhh.coalesceAnswers(useVersion, c, n)

		return n.MarshalTo(lhh.pb)
	})

	if !found {
		return
	}

	if err != nil {
		lhh.l.WithError(err).WithField("vpnAddrs", fromVpnAddrs).Error("Failed to marshal lighthouse host was queried for")
		return
	}

	lhh.lh.metricTx(NebulaMeta_HostPunchNotification, 1)
	w.SendMessageToVpnAddr(header.LightHouse, 0, punchNotifDest, lhh.pb[:ln], lhh.nb, lhh.out[:0])
}

func (lhh *LightHouseHandler) coalesceAnswers(v cert.Version, c *cache, n *NebulaMeta) {
	if c.v4 != nil {
		if c.v4.learned != nil {
			n.Details.V4AddrPorts = append(n.Details.V4AddrPorts, c.v4.learned)
		}
		if c.v4.reported != nil && len(c.v4.reported) > 0 {
			n.Details.V4AddrPorts = append(n.Details.V4AddrPorts, c.v4.reported...)
		}
	}

	if c.v6 != nil {
		if c.v6.learned != nil {
			n.Details.V6AddrPorts = append(n.Details.V6AddrPorts, c.v6.learned)
		}
		if c.v6.reported != nil && len(c.v6.reported) > 0 {
			n.Details.V6AddrPorts = append(n.Details.V6AddrPorts, c.v6.reported...)
		}
	}

	if c.relay != nil {
		if v == cert.Version1 {
			b := [4]byte{}
			for _, r := range c.relay.relay {
				if !r.Is4() {
					continue
				}
				b = r.As4()
				n.Details.OldRelayVpnAddrs = append(n.Details.OldRelayVpnAddrs, binary.BigEndian.Uint32(b[:]))
			}
		} else if v == cert.Version2 {
			for _, r := range c.relay.relay {
				n.Details.RelayVpnAddrs = append(n.Details.RelayVpnAddrs, netAddrToProtoAddr(r))
			}
		} else {
			if lhh.l.Level >= logrus.DebugLevel {
				lhh.l.WithField("version", v).Debug("unsupported protocol version")
			}
		}
	}
}

func (lhh *LightHouseHandler) handleHostQueryReply(n *NebulaMeta, fromVpnAddrs []netip.Addr) {
	if !lhh.lh.IsAnyLighthouseAddr(fromVpnAddrs) {
		return
	}

	certVpnAddr, _, err := n.Details.GetVpnAddrAndVersion()
	if err != nil {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.WithError(err).WithField("vpnAddrs", fromVpnAddrs).Error("dropping malformed HostQueryReply")
		}
		return
	}
	relays := n.Details.GetRelays()

	lhh.lh.Lock()
	am := lhh.lh.unlockedGetRemoteList([]netip.Addr{certVpnAddr})
	am.Lock()
	lhh.lh.Unlock()

	am.unlockedSetV4(fromVpnAddrs[0], certVpnAddr, n.Details.V4AddrPorts, lhh.lh.unlockedShouldAddV4)
	am.unlockedSetV6(fromVpnAddrs[0], certVpnAddr, n.Details.V6AddrPorts, lhh.lh.unlockedShouldAddV6)
	am.unlockedSetRelay(fromVpnAddrs[0], relays)
	am.Unlock()

	// Non-blocking attempt to trigger, skip if it would block
	select {
	case lhh.lh.handshakeTrigger <- certVpnAddr:
	default:
	}
}

func (lhh *LightHouseHandler) handleHostUpdateNotification(n *NebulaMeta, fromVpnAddrs []netip.Addr, w EncWriter) {
	if !lhh.lh.amLighthouse {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.Debugln("I am not a lighthouse, do not take host updates: ", fromVpnAddrs)
		}
		return
	}

	// not using GetVpnAddrAndVersion because we don't want to error on a blank detailsVpnAddr
	var detailsVpnAddr netip.Addr
	var useVersion cert.Version
	if n.Details.OldVpnAddr != 0 { //v1 always sets this field
		b := [4]byte{}
		binary.BigEndian.PutUint32(b[:], n.Details.OldVpnAddr)
		detailsVpnAddr = netip.AddrFrom4(b)
		useVersion = cert.Version1
	} else if n.Details.VpnAddr != nil { //this field is "optional" in v2, but if it's set, we should enforce it
		detailsVpnAddr = protoAddrToNetAddr(n.Details.VpnAddr)
		useVersion = cert.Version2
	} else {
		detailsVpnAddr = netip.Addr{}
		useVersion = cert.Version2
	}

	//Simple check that the host sent this not someone else, if detailsVpnAddr is filled
	if detailsVpnAddr.IsValid() && !slices.Contains(fromVpnAddrs, detailsVpnAddr) {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.WithField("vpnAddrs", fromVpnAddrs).WithField("answer", detailsVpnAddr).Debugln("Host sent invalid update")
		}
		return
	}

	relays := n.Details.GetRelays()

	lhh.lh.Lock()
	am := lhh.lh.unlockedGetRemoteList(fromVpnAddrs)
	am.Lock()
	lhh.lh.Unlock()

	am.unlockedSetV4(fromVpnAddrs[0], fromVpnAddrs[0], n.Details.V4AddrPorts, lhh.lh.unlockedShouldAddV4)
	am.unlockedSetV6(fromVpnAddrs[0], fromVpnAddrs[0], n.Details.V6AddrPorts, lhh.lh.unlockedShouldAddV6)
	am.unlockedSetRelay(fromVpnAddrs[0], relays)
	am.Unlock()

	n = lhh.resetMeta()
	n.Type = NebulaMeta_HostUpdateNotificationAck
	switch useVersion {
	case cert.Version1:
		if !fromVpnAddrs[0].Is4() {
			lhh.l.WithField("vpnAddrs", fromVpnAddrs).Error("Can not send HostUpdateNotificationAck for a ipv6 vpn ip in a v1 message")
			return
		}
		vpnAddrB := fromVpnAddrs[0].As4()
		n.Details.OldVpnAddr = binary.BigEndian.Uint32(vpnAddrB[:])
	case cert.Version2:
		// do nothing, we want to send a blank message
	default:
		lhh.l.WithField("useVersion", useVersion).Error("invalid protocol version")
		return
	}

	ln, err := n.MarshalTo(lhh.pb)
	if err != nil {
		lhh.l.WithError(err).WithField("vpnAddrs", fromVpnAddrs).Error("Failed to marshal lighthouse host update ack")
		return
	}

	lhh.lh.metricTx(NebulaMeta_HostUpdateNotificationAck, 1)
	w.SendMessageToVpnAddr(header.LightHouse, 0, fromVpnAddrs[0], lhh.pb[:ln], lhh.nb, lhh.out[:0])
}

func (lhh *LightHouseHandler) handleHostPunchNotification(n *NebulaMeta, fromVpnAddrs []netip.Addr, w EncWriter) {
	//It's possible the lighthouse is communicating with us using a non primary vpn addr,
	//which means we need to compare all fromVpnAddrs against all configured lighthouse vpn addrs.
	if !lhh.lh.IsAnyLighthouseAddr(fromVpnAddrs) {
		return
	}

	detailsVpnAddr, _, err := n.Details.GetVpnAddrAndVersion()
	if err != nil {
		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.WithField("details", n.Details).WithError(err).Debugln("dropping invalid HostPunchNotification")
		}
		return
	}

	empty := []byte{0}
	punch := func(vpnPeer netip.AddrPort, logVpnAddr netip.Addr) {
		if !vpnPeer.IsValid() {
			return
		}

		go func() {
			time.Sleep(lhh.lh.punchy.GetDelay())
			lhh.lh.metricHolepunchTx.Inc(1)
			lhh.lh.punchConn.WriteTo(empty, vpnPeer)
		}()

		if lhh.l.Level >= logrus.DebugLevel {
			lhh.l.Debugf("Punching on %v for %v", vpnPeer, logVpnAddr)
		}
	}

	remoteAllowList := lhh.lh.GetRemoteAllowList()
	for _, a := range n.Details.V4AddrPorts {
		b := protoV4AddrPortToNetAddrPort(a)
		if remoteAllowList.Allow(detailsVpnAddr, b.Addr()) {
			punch(b, detailsVpnAddr)
		}
	}

	for _, a := range n.Details.V6AddrPorts {
		b := protoV6AddrPortToNetAddrPort(a)
		if remoteAllowList.Allow(detailsVpnAddr, b.Addr()) {
			punch(b, detailsVpnAddr)
		}
	}

	// This sends a nebula test packet to the host trying to contact us. In the case
	// of a double nat or other difficult scenario, this may help establish
	// a tunnel.
	if lhh.lh.punchy.GetRespond() {
		go func() {
			time.Sleep(lhh.lh.punchy.GetRespondDelay())
			if lhh.l.Level >= logrus.DebugLevel {
				lhh.l.Debugf("Sending a nebula test packet to vpn addr %s", detailsVpnAddr)
			}
			//NOTE: we have to allocate a new output buffer here since we are spawning a new goroutine
			// for each punchBack packet. We should move this into a timerwheel or a single goroutine
			// managed by a channel.
			w.SendMessageToVpnAddr(header.Test, header.TestRequest, detailsVpnAddr, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
		}()
	}
}

func protoAddrToNetAddr(addr *Addr) netip.Addr {
	b := [16]byte{}
	binary.BigEndian.PutUint64(b[:8], addr.Hi)
	binary.BigEndian.PutUint64(b[8:], addr.Lo)
	return netip.AddrFrom16(b).Unmap()
}

func protoV4AddrPortToNetAddrPort(ap *V4AddrPort) netip.AddrPort {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], ap.Addr)
	return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(ap.Port))
}

func protoV6AddrPortToNetAddrPort(ap *V6AddrPort) netip.AddrPort {
	b := [16]byte{}
	binary.BigEndian.PutUint64(b[:8], ap.Hi)
	binary.BigEndian.PutUint64(b[8:], ap.Lo)
	return netip.AddrPortFrom(netip.AddrFrom16(b), uint16(ap.Port))
}

func netAddrToProtoAddr(addr netip.Addr) *Addr {
	b := addr.As16()
	return &Addr{
		Hi: binary.BigEndian.Uint64(b[:8]),
		Lo: binary.BigEndian.Uint64(b[8:]),
	}
}

func netAddrToProtoV4AddrPort(addr netip.Addr, port uint16) *V4AddrPort {
	v4Addr := addr.As4()
	return &V4AddrPort{
		Addr: binary.BigEndian.Uint32(v4Addr[:]),
		Port: uint32(port),
	}
}

func netAddrToProtoV6AddrPort(addr netip.Addr, port uint16) *V6AddrPort {
	v6Addr := addr.As16()
	return &V6AddrPort{
		Hi:   binary.BigEndian.Uint64(v6Addr[:8]),
		Lo:   binary.BigEndian.Uint64(v6Addr[8:]),
		Port: uint32(port),
	}
}

func (d *NebulaMetaDetails) GetRelays() []netip.Addr {
	var relays []netip.Addr
	if len(d.OldRelayVpnAddrs) > 0 {
		b := [4]byte{}
		for _, r := range d.OldRelayVpnAddrs {
			binary.BigEndian.PutUint32(b[:], r)
			relays = append(relays, netip.AddrFrom4(b))
		}
	}

	if len(d.RelayVpnAddrs) > 0 {
		for _, r := range d.RelayVpnAddrs {
			relays = append(relays, protoAddrToNetAddr(r))
		}
	}
	return relays
}

// FindNetworkUnion returns the first netip.Addr contained in the list of provided netip.Prefix, if able
func findNetworkUnion(prefixes []netip.Prefix, addrs []netip.Addr) (netip.Addr, bool) {
	for i := range prefixes {
		for j := range addrs {
			if prefixes[i].Contains(addrs[j]) {
				return addrs[j], true
			}
		}
	}
	return netip.Addr{}, false
}

func (d *NebulaMetaDetails) GetVpnAddrAndVersion() (netip.Addr, cert.Version, error) {
	if d.OldVpnAddr != 0 {
		b := [4]byte{}
		binary.BigEndian.PutUint32(b[:], d.OldVpnAddr)
		detailsVpnAddr := netip.AddrFrom4(b)
		return detailsVpnAddr, cert.Version1, nil
	} else if d.VpnAddr != nil {
		detailsVpnAddr := protoAddrToNetAddr(d.VpnAddr)
		return detailsVpnAddr, cert.Version2, nil
	} else {
		return netip.Addr{}, cert.Version1, ErrBadDetailsVpnAddr
	}
}
