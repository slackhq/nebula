package nebula

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/udp"
)

// forEachFunc is used to benefit folks that want to do work inside the lock
type forEachFunc func(addr *udp.Addr, preferred bool)

// The checkFuncs here are to simplify bulk importing LH query response logic into a single function (reset slice and iterate)
type checkFuncV4 func(vpnIp iputil.VpnIp, to *Ip4AndPort) bool
type checkFuncV6 func(vpnIp iputil.VpnIp, to *Ip6AndPort) bool

// CacheMap is a struct that better represents the lighthouse cache for humans
// The string key is the owners vpnIp
type CacheMap map[string]*Cache

// Cache is the other part of CacheMap to better represent the lighthouse cache for humans
// We don't reason about ipv4 vs ipv6 here
type Cache struct {
	Learned  []*udp.Addr `json:"learned,omitempty"`
	Reported []*udp.Addr `json:"reported,omitempty"`
	Relay    []*net.IP   `json:"relay"`
}

//TODO: Seems like we should plop static host entries in here too since the are protected by the lighthouse from deletion
// We will never clean learned/reported information for them as it stands today

// cache is an internal struct that splits v4 and v6 addresses inside the cache map
type cache struct {
	v4    *cacheV4
	v6    *cacheV6
	relay *cacheRelay
}

type cacheRelay struct {
	relay []uint32
}

// cacheV4 stores learned and reported ipv4 records under cache
type cacheV4 struct {
	learned  *Ip4AndPort
	reported []*Ip4AndPort
}

// cacheV4 stores learned and reported ipv6 records under cache
type cacheV6 struct {
	learned  *Ip6AndPort
	reported []*Ip6AndPort
}

type hostnamePort struct {
	name string
	port uint16
}

type hostnamesResults struct {
	hostnames     []hostnamePort
	network       string
	lookupTimeout time.Duration
	cancelFn      func()
	l             *logrus.Logger
	ips           atomic.Pointer[map[netip.AddrPort]struct{}]
}

func NewHostnameResults(ctx context.Context, l *logrus.Logger, d time.Duration, network string, timeout time.Duration, hostPorts []string, onUpdate func()) (*hostnamesResults, error) {
	r := &hostnamesResults{
		hostnames:     make([]hostnamePort, len(hostPorts)),
		network:       network,
		lookupTimeout: timeout,
		l:             l,
	}

	// Fastrack IP addresses to ensure they're immediately available for use.
	// DNS lookups for hostnames that aren't hardcoded IP's will happen in a background goroutine.
	performBackgroundLookup, ips, err := preprocessHostPorts(hostPorts, r)
	if err != nil {
		return nil, err
	}
	r.ips.Store(&ips)

	if performBackgroundLookup {
		setupBackgroundLookup(ctx, r, d, onUpdate)
	}

	return r, nil
}

func preprocessHostPorts(hostPorts []string, results *hostnamesResults) (bool, map[netip.AddrPort]struct{}, error) {
	performBackgroundLookup := false
	ips := map[netip.AddrPort]struct{}{}

	for idx, hostPort := range hostPorts {
		if isSRV(hostPort) {
			results.hostnames[idx] = hostnamePort{name: hostPort, port: uint16(0)}
			performBackgroundLookup = true
			continue
		}

		rIp, sPort, err := net.SplitHostPort(hostPort)
		if err != nil {
			return false, nil, err
		}

		iPort, err := strconv.Atoi(sPort)
		if err != nil {
			return false, nil, err
		}

		results.hostnames[idx] = hostnamePort{name: rIp, port: uint16(iPort)}
		addr, err := netip.ParseAddr(rIp)
		if err != nil {
			// This address is a hostname, not an IP address
			performBackgroundLookup = true
			continue
		}

		// Save the IP address immediately
		ips[netip.AddrPortFrom(addr, uint16(iPort))] = struct{}{}
	}

	return performBackgroundLookup, ips, nil
}

func isSRV(s string) bool {
	re := regexp.MustCompile(`^_[A-Za-z0-9-]+?\._[A-Za-z0-9-]+?\..+$`)
	return re.MatchString(s)
}

func setupBackgroundLookup(ctx context.Context, r *hostnamesResults, duration time.Duration, onUpdate func()) {
	newCtx, cancel := context.WithCancel(ctx)
	r.cancelFn = cancel
	ticker := time.NewTicker(duration)
	go performLookup(newCtx, r, ticker, onUpdate)
}

func performLookup(ctx context.Context, results *hostnamesResults, ticker *time.Ticker, onUpdate func()) {
	defer ticker.Stop()
	for {
		if lookupAndUpdate(ctx, results) {
			onUpdate()
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			continue
		}
	}
}

func lookupAndUpdate(ctx context.Context, results *hostnamesResults) bool {
	var netipAddrs map[netip.AddrPort]struct{}
	for _, hostPort := range results.hostnames {
		netipAddrs = resolveHostPort(ctx, hostPort, results.network, results.lookupTimeout, results.l)
	}

	if len(netipAddrs) == 0 {
		return false
	}

	origSet := results.ips.Load()
	different := isDifferent(origSet, netipAddrs)
	if different {
		results.l.WithFields(logrus.Fields{"origSet": origSet, "newSet": netipAddrs}).Info("DNS results changed for host list")
		results.ips.Store(&netipAddrs)
	}

	return different
}

func isDifferent(origSet *map[netip.AddrPort]struct{}, newSet map[netip.AddrPort]struct{}) bool {
	for a := range *origSet {
		if _, ok := newSet[a]; !ok {
			return true
		}
	}

	for a := range newSet {
		if _, ok := (*origSet)[a]; !ok {
			return true
		}
	}

	return false
}

func resolveHostPort(ctx context.Context, hostPort hostnamePort, network string, timeout time.Duration, logger *logrus.Logger) map[netip.AddrPort]struct{} {
	if isSRV(hostPort.name) {
		return resolveSRV(ctx, hostPort, network, timeout, logger)
	} else {
		return resolveIP(ctx, hostPort, network, timeout, logger)
	}
}

func resolveSRV(ctx context.Context, hostPort hostnamePort, network string, timeout time.Duration, logger *logrus.Logger) map[netip.AddrPort]struct{} {
	netipAddrs := make(map[netip.AddrPort]struct{})

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	_, srvs, err := net.DefaultResolver.LookupSRV(timeoutCtx, "", "", hostPort.name)
	if err != nil {
		logger.WithFields(logrus.Fields{"srv": hostPort.name, "network": network}).WithError(err).Error("SRV resolution failed for static_map host")
		return netipAddrs
	}

	for _, srv := range srvs {
		var domain string
		if strings.HasSuffix(srv.Target, ".") {
			domain = srv.Target[:len(srv.Target)-1]
		} else {
			domain = srv.Target
		}

		ipTimeoutCtx, ipTimeoutCancel := context.WithTimeout(ctx, timeout)
		addrs, err := net.DefaultResolver.LookupNetIP(ipTimeoutCtx, network, domain)
		ipTimeoutCancel()
		if err != nil {
			logger.WithFields(logrus.Fields{"hostname": srv.Target, "network": network}).WithError(err).Error("DNS resolution failed for static_map host")
			continue
		}

		for _, addr := range addrs {
			netipAddrs[netip.AddrPortFrom(addr, srv.Port)] = struct{}{}
		}
	}

	return netipAddrs
}

func resolveIP(ctx context.Context, hostPort hostnamePort, network string, timeout time.Duration, logger *logrus.Logger) map[netip.AddrPort]struct{} {
	netipAddrs := make(map[netip.AddrPort]struct{})

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(timeoutCtx, network, hostPort.name)
	if err != nil {
		logger.WithFields(logrus.Fields{"hostname": hostPort.name, "network": network}).WithError(err).Error("DNS resolution failed")
		return netipAddrs
	}

	for _, addr := range addrs {
		netipAddrs[netip.AddrPortFrom(addr, hostPort.port)] = struct{}{}
	}

	return netipAddrs
}

func (hr *hostnamesResults) Cancel() {
	if hr != nil && hr.cancelFn != nil {
		hr.cancelFn()
	}
}

func (hr *hostnamesResults) GetIPs() []netip.AddrPort {
	var retSlice []netip.AddrPort
	if hr != nil {
		p := hr.ips.Load()
		if p != nil {
			for k := range *p {
				retSlice = append(retSlice, k)
			}
		}
	}
	return retSlice
}

// RemoteList is a unifying concept for lighthouse servers and clients as well as hostinfos.
// It serves as a local cache of query replies, host update notifications, and locally learned addresses
type RemoteList struct {
	// Every interaction with internals requires a lock!
	sync.RWMutex

	// A deduplicated set of addresses. Any accessor should lock beforehand.
	addrs []*udp.Addr

	// A set of relay addresses. VpnIp addresses that the remote identified as relays.
	relays []*iputil.VpnIp

	// These are maps to store v4 and v6 addresses per lighthouse
	// Map key is the vpnIp of the person that told us about this the cached entries underneath.
	// For learned addresses, this is the vpnIp that sent the packet
	cache map[iputil.VpnIp]*cache

	hr        *hostnamesResults
	shouldAdd func(netip.Addr) bool

	// This is a list of remotes that we have tried to handshake with and have returned from the wrong vpn ip.
	// They should not be tried again during a handshake
	badRemotes []*udp.Addr

	// A flag that the cache may have changed and addrs needs to be rebuilt
	shouldRebuild bool
}

// NewRemoteList creates a new empty RemoteList
func NewRemoteList(shouldAdd func(netip.Addr) bool) *RemoteList {
	return &RemoteList{
		addrs:     make([]*udp.Addr, 0),
		relays:    make([]*iputil.VpnIp, 0),
		cache:     make(map[iputil.VpnIp]*cache),
		shouldAdd: shouldAdd,
	}
}

func (r *RemoteList) unlockedSetHostnamesResults(hr *hostnamesResults) {
	// Cancel any existing hostnamesResults DNS goroutine to release resources
	r.hr.Cancel()
	r.hr = hr
}

// Len locks and reports the size of the deduplicated address list
// The deduplication work may need to occur here, so you must pass preferredRanges
func (r *RemoteList) Len(preferredRanges []*net.IPNet) int {
	r.Rebuild(preferredRanges)
	r.RLock()
	defer r.RUnlock()
	return len(r.addrs)
}

// ForEach locks and will call the forEachFunc for every deduplicated address in the list
// The deduplication work may need to occur here, so you must pass preferredRanges
func (r *RemoteList) ForEach(preferredRanges []*net.IPNet, forEach forEachFunc) {
	r.Rebuild(preferredRanges)
	r.RLock()
	for _, v := range r.addrs {
		forEach(v, isPreferred(v.IP, preferredRanges))
	}
	r.RUnlock()
}

// CopyAddrs locks and makes a deep copy of the deduplicated address list
// The deduplication work may need to occur here, so you must pass preferredRanges
func (r *RemoteList) CopyAddrs(preferredRanges []*net.IPNet) []*udp.Addr {
	if r == nil {
		return nil
	}

	r.Rebuild(preferredRanges)

	r.RLock()
	defer r.RUnlock()
	c := make([]*udp.Addr, len(r.addrs))
	for i, v := range r.addrs {
		c[i] = v.Copy()
	}
	return c
}

// LearnRemote locks and sets the learned slot for the owner vpn ip to the provided addr
// Currently this is only needed when HostInfo.SetRemote is called as that should cover both handshaking and roaming.
// It will mark the deduplicated address list as dirty, so do not call it unless new information is available
// TODO: this needs to support the allow list list
func (r *RemoteList) LearnRemote(ownerVpnIp iputil.VpnIp, addr *udp.Addr) {
	r.Lock()
	defer r.Unlock()
	if v4 := addr.IP.To4(); v4 != nil {
		r.unlockedSetLearnedV4(ownerVpnIp, NewIp4AndPort(v4, uint32(addr.Port)))
	} else {
		r.unlockedSetLearnedV6(ownerVpnIp, NewIp6AndPort(addr.IP, uint32(addr.Port)))
	}
}

// CopyCache locks and creates a more human friendly form of the internal address cache.
// This may contain duplicates and blocked addresses
func (r *RemoteList) CopyCache() *CacheMap {
	r.RLock()
	defer r.RUnlock()

	cm := make(CacheMap)
	getOrMake := func(vpnIp string) *Cache {
		c := cm[vpnIp]
		if c == nil {
			c = &Cache{
				Learned:  make([]*udp.Addr, 0),
				Reported: make([]*udp.Addr, 0),
				Relay:    make([]*net.IP, 0),
			}
			cm[vpnIp] = c
		}
		return c
	}

	for owner, mc := range r.cache {
		c := getOrMake(owner.String())

		if mc.v4 != nil {
			if mc.v4.learned != nil {
				c.Learned = append(c.Learned, NewUDPAddrFromLH4(mc.v4.learned))
			}

			for _, a := range mc.v4.reported {
				c.Reported = append(c.Reported, NewUDPAddrFromLH4(a))
			}
		}

		if mc.v6 != nil {
			if mc.v6.learned != nil {
				c.Learned = append(c.Learned, NewUDPAddrFromLH6(mc.v6.learned))
			}

			for _, a := range mc.v6.reported {
				c.Reported = append(c.Reported, NewUDPAddrFromLH6(a))
			}
		}

		if mc.relay != nil {
			for _, a := range mc.relay.relay {
				nip := iputil.VpnIp(a).ToIP()
				c.Relay = append(c.Relay, &nip)
			}
		}
	}

	return &cm
}

// BlockRemote locks and records the address as bad, it will be excluded from the deduplicated address list
func (r *RemoteList) BlockRemote(bad *udp.Addr) {
	if bad == nil {
		// relays can have nil udp Addrs
		return
	}
	r.Lock()
	defer r.Unlock()

	// Check if we already blocked this addr
	if r.unlockedIsBad(bad) {
		return
	}

	// We copy here because we are taking something else's memory and we can't trust everything
	r.badRemotes = append(r.badRemotes, bad.Copy())

	// Mark the next interaction must recollect/dedupe
	r.shouldRebuild = true
}

// CopyBlockedRemotes locks and makes a deep copy of the blocked remotes list
func (r *RemoteList) CopyBlockedRemotes() []*udp.Addr {
	r.RLock()
	defer r.RUnlock()

	c := make([]*udp.Addr, len(r.badRemotes))
	for i, v := range r.badRemotes {
		c[i] = v.Copy()
	}
	return c
}

// ResetBlockedRemotes locks and clears the blocked remotes list
func (r *RemoteList) ResetBlockedRemotes() {
	r.Lock()
	r.badRemotes = nil
	r.Unlock()
}

// Rebuild locks and generates the deduplicated address list only if there is work to be done
// There is generally no reason to call this directly but it is safe to do so
func (r *RemoteList) Rebuild(preferredRanges []*net.IPNet) {
	r.Lock()
	defer r.Unlock()

	// Only rebuild if the cache changed
	//TODO: shouldRebuild is probably pointless as we don't check for actual change when lighthouse updates come in
	if r.shouldRebuild {
		r.unlockedCollect()
		r.shouldRebuild = false
	}

	// Always re-sort, preferredRanges can change via HUP
	r.unlockedSort(preferredRanges)
}

// unlockedIsBad assumes you have the write lock and checks if the remote matches any entry in the blocked address list
func (r *RemoteList) unlockedIsBad(remote *udp.Addr) bool {
	for _, v := range r.badRemotes {
		if v.Equals(remote) {
			return true
		}
	}
	return false
}

// unlockedSetLearnedV4 assumes you have the write lock and sets the current learned address for this owner and marks the
// deduplicated address list as dirty
func (r *RemoteList) unlockedSetLearnedV4(ownerVpnIp iputil.VpnIp, to *Ip4AndPort) {
	r.shouldRebuild = true
	r.unlockedGetOrMakeV4(ownerVpnIp).learned = to
}

// unlockedSetV4 assumes you have the write lock and resets the reported list of ips for this owner to the list provided
// and marks the deduplicated address list as dirty
func (r *RemoteList) unlockedSetV4(ownerVpnIp iputil.VpnIp, vpnIp iputil.VpnIp, to []*Ip4AndPort, check checkFuncV4) {
	r.shouldRebuild = true
	c := r.unlockedGetOrMakeV4(ownerVpnIp)

	// Reset the slice
	c.reported = c.reported[:0]

	// We can't take their array but we can take their pointers
	for _, v := range to[:minInt(len(to), MaxRemotes)] {
		if check(vpnIp, v) {
			c.reported = append(c.reported, v)
		}
	}
}

func (r *RemoteList) unlockedSetRelay(ownerVpnIp iputil.VpnIp, vpnIp iputil.VpnIp, to []uint32) {
	r.shouldRebuild = true
	c := r.unlockedGetOrMakeRelay(ownerVpnIp)

	// Reset the slice
	c.relay = c.relay[:0]

	// We can't take their array but we can take their pointers
	c.relay = append(c.relay, to[:minInt(len(to), MaxRemotes)]...)
}

// unlockedPrependV4 assumes you have the write lock and prepends the address in the reported list for this owner
// This is only useful for establishing static hosts
func (r *RemoteList) unlockedPrependV4(ownerVpnIp iputil.VpnIp, to *Ip4AndPort) {
	r.shouldRebuild = true
	c := r.unlockedGetOrMakeV4(ownerVpnIp)

	// We are doing the easy append because this is rarely called
	c.reported = append([]*Ip4AndPort{to}, c.reported...)
	if len(c.reported) > MaxRemotes {
		c.reported = c.reported[:MaxRemotes]
	}
}

// unlockedSetLearnedV6 assumes you have the write lock and sets the current learned address for this owner and marks the
// deduplicated address list as dirty
func (r *RemoteList) unlockedSetLearnedV6(ownerVpnIp iputil.VpnIp, to *Ip6AndPort) {
	r.shouldRebuild = true
	r.unlockedGetOrMakeV6(ownerVpnIp).learned = to
}

// unlockedSetV6 assumes you have the write lock and resets the reported list of ips for this owner to the list provided
// and marks the deduplicated address list as dirty
func (r *RemoteList) unlockedSetV6(ownerVpnIp iputil.VpnIp, vpnIp iputil.VpnIp, to []*Ip6AndPort, check checkFuncV6) {
	r.shouldRebuild = true
	c := r.unlockedGetOrMakeV6(ownerVpnIp)

	// Reset the slice
	c.reported = c.reported[:0]

	// We can't take their array but we can take their pointers
	for _, v := range to[:minInt(len(to), MaxRemotes)] {
		if check(vpnIp, v) {
			c.reported = append(c.reported, v)
		}
	}
}

// unlockedPrependV6 assumes you have the write lock and prepends the address in the reported list for this owner
// This is only useful for establishing static hosts
func (r *RemoteList) unlockedPrependV6(ownerVpnIp iputil.VpnIp, to *Ip6AndPort) {
	r.shouldRebuild = true
	c := r.unlockedGetOrMakeV6(ownerVpnIp)

	// We are doing the easy append because this is rarely called
	c.reported = append([]*Ip6AndPort{to}, c.reported...)
	if len(c.reported) > MaxRemotes {
		c.reported = c.reported[:MaxRemotes]
	}
}

func (r *RemoteList) unlockedGetOrMakeRelay(ownerVpnIp iputil.VpnIp) *cacheRelay {
	am := r.cache[ownerVpnIp]
	if am == nil {
		am = &cache{}
		r.cache[ownerVpnIp] = am
	}
	// Avoid occupying memory for relay if we never have any
	if am.relay == nil {
		am.relay = &cacheRelay{}
	}
	return am.relay
}

// unlockedGetOrMakeV4 assumes you have the write lock and builds the cache and owner entry. Only the v4 pointer is established.
// The caller must dirty the learned address cache if required
func (r *RemoteList) unlockedGetOrMakeV4(ownerVpnIp iputil.VpnIp) *cacheV4 {
	am := r.cache[ownerVpnIp]
	if am == nil {
		am = &cache{}
		r.cache[ownerVpnIp] = am
	}
	// Avoid occupying memory for v6 addresses if we never have any
	if am.v4 == nil {
		am.v4 = &cacheV4{}
	}
	return am.v4
}

// unlockedGetOrMakeV6 assumes you have the write lock and builds the cache and owner entry. Only the v6 pointer is established.
// The caller must dirty the learned address cache if required
func (r *RemoteList) unlockedGetOrMakeV6(ownerVpnIp iputil.VpnIp) *cacheV6 {
	am := r.cache[ownerVpnIp]
	if am == nil {
		am = &cache{}
		r.cache[ownerVpnIp] = am
	}
	// Avoid occupying memory for v4 addresses if we never have any
	if am.v6 == nil {
		am.v6 = &cacheV6{}
	}
	return am.v6
}

// unlockedCollect assumes you have the write lock and collects/transforms the cache into the deduped address list.
// The result of this function can contain duplicates. unlockedSort handles cleaning it.
func (r *RemoteList) unlockedCollect() {
	addrs := r.addrs[:0]
	relays := r.relays[:0]

	for _, c := range r.cache {
		if c.v4 != nil {
			if c.v4.learned != nil {
				u := NewUDPAddrFromLH4(c.v4.learned)
				if !r.unlockedIsBad(u) {
					addrs = append(addrs, u)
				}
			}

			for _, v := range c.v4.reported {
				u := NewUDPAddrFromLH4(v)
				if !r.unlockedIsBad(u) {
					addrs = append(addrs, u)
				}
			}
		}

		if c.v6 != nil {
			if c.v6.learned != nil {
				u := NewUDPAddrFromLH6(c.v6.learned)
				if !r.unlockedIsBad(u) {
					addrs = append(addrs, u)
				}
			}

			for _, v := range c.v6.reported {
				u := NewUDPAddrFromLH6(v)
				if !r.unlockedIsBad(u) {
					addrs = append(addrs, u)
				}
			}
		}

		if c.relay != nil {
			for _, v := range c.relay.relay {
				ip := iputil.VpnIp(v)
				relays = append(relays, &ip)
			}
		}
	}

	dnsAddrs := r.hr.GetIPs()
	for _, addr := range dnsAddrs {
		if r.shouldAdd == nil || r.shouldAdd(addr.Addr()) {
			v6 := addr.Addr().As16()
			addrs = append(addrs, &udp.Addr{
				IP:   v6[:],
				Port: addr.Port(),
			})
		}
	}

	r.addrs = addrs
	r.relays = relays

}

// unlockedSort assumes you have the write lock and performs the deduping and sorting of the address list
func (r *RemoteList) unlockedSort(preferredRanges []*net.IPNet) {
	n := len(r.addrs)
	if n < 2 {
		return
	}

	lessFunc := func(i, j int) bool {
		a := r.addrs[i]
		b := r.addrs[j]
		// Preferred addresses first

		aPref := isPreferred(a.IP, preferredRanges)
		bPref := isPreferred(b.IP, preferredRanges)
		switch {
		case aPref && !bPref:
			// If i is preferred and j is not, i is less than j
			return true

		case !aPref && bPref:
			// If j is preferred then i is not due to the else, i is not less than j
			return false

		default:
			// Both i an j are either preferred or not, sort within that
		}

		// ipv6 addresses 2nd
		a4 := a.IP.To4()
		b4 := b.IP.To4()
		switch {
		case a4 == nil && b4 != nil:
			// If i is v6 and j is v4, i is less than j
			return true

		case a4 != nil && b4 == nil:
			// If j is v6 and i is v4, i is not less than j
			return false

		case a4 != nil && b4 != nil:
			// Special case for ipv4, a4 and b4 are not nil
			aPrivate := isPrivateIP(a4)
			bPrivate := isPrivateIP(b4)
			switch {
			case !aPrivate && bPrivate:
				// If i is a public ip (not private) and j is a private ip, i is less then j
				return true

			case aPrivate && !bPrivate:
				// If j is public (not private) then i is private due to the else, i is not less than j
				return false

			default:
				// Both i an j are either public or private, sort within that
			}

		default:
			// Both i an j are either ipv4 or ipv6, sort within that
		}

		// lexical order of ips 3rd
		c := bytes.Compare(a.IP, b.IP)
		if c == 0 {
			// Ips are the same, Lexical order of ports 4th
			return a.Port < b.Port
		}

		// Ip wasn't the same
		return c < 0
	}

	// Sort it
	sort.Slice(r.addrs, lessFunc)

	// Deduplicate
	a, b := 0, 1
	for b < n {
		if !r.addrs[a].Equals(r.addrs[b]) {
			a++
			if a != b {
				r.addrs[a], r.addrs[b] = r.addrs[b], r.addrs[a]
			}
		}
		b++
	}

	r.addrs = r.addrs[:a+1]
	return
}

// minInt returns the minimum integer of a or b
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isPreferred returns true of the ip is contained in the preferredRanges list
func isPreferred(ip net.IP, preferredRanges []*net.IPNet) bool {
	//TODO: this would be better in a CIDR6Tree
	for _, p := range preferredRanges {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var _, private24BitBlock, _ = net.ParseCIDR("10.0.0.0/8")
var _, private20BitBlock, _ = net.ParseCIDR("172.16.0.0/12")
var _, private16BitBlock, _ = net.ParseCIDR("192.168.0.0/16")

// isPrivateIP returns true if the ip is contained by a rfc 1918 private range
func isPrivateIP(ip net.IP) bool {
	//TODO: another great cidrtree option
	//TODO: Private for ipv6 or just let it ride?
	return private24BitBlock.Contains(ip) || private20BitBlock.Contains(ip) || private16BitBlock.Contains(ip)
}
