package nebula

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
)

type FirewallInterface interface {
	AddRule(incoming bool, proto uint8, startPort int32, endPort int32, groups []string, host string, cidr, localCidr string, caName string, caSha string) error
}

type conn struct {
	Expires time.Time // Time when this conntrack entry will expire

	// record why the original connection passed the firewall, so we can re-validate
	// after ruleset changes. Note, rulesVersion is a uint16 so that these two
	// fields pack for free after the uint32 above
	incoming     bool
	rulesVersion uint16
}

// TODO: need conntrack max tracked connections handling
type Firewall struct {
	Conntrack *FirewallConntrack

	InRules  *FirewallTable
	OutRules *FirewallTable

	InSendReject  bool
	OutSendReject bool

	//TODO: we should have many more options for TCP, an option for ICMP, and mimic the kernel a bit better
	// https://www.kernel.org/doc/Documentation/networking/nf_conntrack-sysctl.txt
	TCPTimeout     time.Duration //linux: 5 days max
	UDPTimeout     time.Duration //linux: 180s max
	DefaultTimeout time.Duration //linux: 600s

	// routableNetworks describes the vpn addresses as well as any unsafe networks issued to us in the certificate.
	// The vpn addresses are a full bit match while the unsafe networks only match the prefix
	routableNetworks *bart.Lite

	// assignedNetworks is a list of vpn networks assigned to us in the certificate.
	assignedNetworks  []netip.Prefix
	hasUnsafeNetworks bool

	rules        string
	rulesVersion uint16

	defaultLocalCIDRAny bool
	incomingMetrics     firewallMetrics
	outgoingMetrics     firewallMetrics

	l *logrus.Logger
}

type firewallMetrics struct {
	droppedLocalAddr  metrics.Counter
	droppedRemoteAddr metrics.Counter
	droppedNoRule     metrics.Counter
}

type FirewallConntrack struct {
	sync.Mutex

	Conns      map[firewall.Packet]*conn
	TimerWheel *TimerWheel[firewall.Packet]
}

// FirewallTable is the entry point for a rule, the evaluation order is:
// Proto AND port AND (CA SHA or CA name) AND local CIDR AND (group OR groups OR name OR remote CIDR)
type FirewallTable struct {
	TCP      firewallPort
	UDP      firewallPort
	ICMP     firewallPort
	AnyProto firewallPort
}

func newFirewallTable() *FirewallTable {
	return &FirewallTable{
		TCP:      firewallPort{},
		UDP:      firewallPort{},
		ICMP:     firewallPort{},
		AnyProto: firewallPort{},
	}
}

type FirewallCA struct {
	Any     *FirewallRule
	CANames map[string]*FirewallRule
	CAShas  map[string]*FirewallRule
}

type FirewallRule struct {
	// Any makes Hosts, Groups, and CIDR irrelevant
	Any    *firewallLocalCIDR
	Hosts  map[string]*firewallLocalCIDR
	Groups []*firewallGroups
	CIDR   *bart.Table[*firewallLocalCIDR]
}

type firewallGroups struct {
	Groups    []string
	LocalCIDR *firewallLocalCIDR
}

// Even though ports are uint16, int32 maps are faster for lookup
// Plus we can use `-1` for fragment rules
type firewallPort map[int32]*FirewallCA

type firewallLocalCIDR struct {
	Any       bool
	LocalCIDR *bart.Lite
}

// NewFirewall creates a new Firewall object. A TimerWheel is created for you from the provided timeouts.
// The certificate provided should be the highest version loaded in memory.
func NewFirewall(l *logrus.Logger, tcpTimeout, UDPTimeout, defaultTimeout time.Duration, c cert.Certificate) *Firewall {
	//TODO: error on 0 duration
	var tmin, tmax time.Duration

	if tcpTimeout < UDPTimeout {
		tmin = tcpTimeout
		tmax = UDPTimeout
	} else {
		tmin = UDPTimeout
		tmax = tcpTimeout
	}

	if defaultTimeout < tmin {
		tmin = defaultTimeout
	} else if defaultTimeout > tmax {
		tmax = defaultTimeout
	}

	routableNetworks := new(bart.Lite)
	var assignedNetworks []netip.Prefix
	for _, network := range c.Networks() {
		nprefix := netip.PrefixFrom(network.Addr(), network.Addr().BitLen())
		routableNetworks.Insert(nprefix)
		assignedNetworks = append(assignedNetworks, network)
	}

	hasUnsafeNetworks := false
	for _, n := range c.UnsafeNetworks() {
		routableNetworks.Insert(n)
		hasUnsafeNetworks = true
	}

	return &Firewall{
		Conntrack: &FirewallConntrack{
			Conns:      make(map[firewall.Packet]*conn),
			TimerWheel: NewTimerWheel[firewall.Packet](tmin, tmax),
		},
		InRules:           newFirewallTable(),
		OutRules:          newFirewallTable(),
		TCPTimeout:        tcpTimeout,
		UDPTimeout:        UDPTimeout,
		DefaultTimeout:    defaultTimeout,
		routableNetworks:  routableNetworks,
		assignedNetworks:  assignedNetworks,
		hasUnsafeNetworks: hasUnsafeNetworks,
		l:                 l,

		incomingMetrics: firewallMetrics{
			droppedLocalAddr:  metrics.GetOrRegisterCounter("firewall.incoming.dropped.local_addr", nil),
			droppedRemoteAddr: metrics.GetOrRegisterCounter("firewall.incoming.dropped.remote_addr", nil),
			droppedNoRule:     metrics.GetOrRegisterCounter("firewall.incoming.dropped.no_rule", nil),
		},
		outgoingMetrics: firewallMetrics{
			droppedLocalAddr:  metrics.GetOrRegisterCounter("firewall.outgoing.dropped.local_addr", nil),
			droppedRemoteAddr: metrics.GetOrRegisterCounter("firewall.outgoing.dropped.remote_addr", nil),
			droppedNoRule:     metrics.GetOrRegisterCounter("firewall.outgoing.dropped.no_rule", nil),
		},
	}
}

func NewFirewallFromConfig(l *logrus.Logger, cs *CertState, c *config.C) (*Firewall, error) {
	certificate := cs.getCertificate(cert.Version2)
	if certificate == nil {
		certificate = cs.getCertificate(cert.Version1)
	}

	if certificate == nil {
		panic("No certificate available to reconfigure the firewall")
	}

	fw := NewFirewall(
		l,
		c.GetDuration("firewall.conntrack.tcp_timeout", time.Minute*12),
		c.GetDuration("firewall.conntrack.udp_timeout", time.Minute*3),
		c.GetDuration("firewall.conntrack.default_timeout", time.Minute*10),
		certificate,
		//TODO: max_connections
	)

	fw.defaultLocalCIDRAny = c.GetBool("firewall.default_local_cidr_any", false)

	inboundAction := c.GetString("firewall.inbound_action", "drop")
	switch inboundAction {
	case "reject":
		fw.InSendReject = true
	case "drop":
		fw.InSendReject = false
	default:
		l.WithField("action", inboundAction).Warn("invalid firewall.inbound_action, defaulting to `drop`")
		fw.InSendReject = false
	}

	outboundAction := c.GetString("firewall.outbound_action", "drop")
	switch outboundAction {
	case "reject":
		fw.OutSendReject = true
	case "drop":
		fw.OutSendReject = false
	default:
		l.WithField("action", inboundAction).Warn("invalid firewall.outbound_action, defaulting to `drop`")
		fw.OutSendReject = false
	}

	err := AddFirewallRulesFromConfig(l, false, c, fw)
	if err != nil {
		return nil, err
	}

	err = AddFirewallRulesFromConfig(l, true, c, fw)
	if err != nil {
		return nil, err
	}

	return fw, nil
}

// AddRule properly creates the in memory rule structure for a firewall table.
func (f *Firewall) AddRule(incoming bool, proto uint8, startPort int32, endPort int32, groups []string, host string, cidr, localCidr, caName string, caSha string) error {
	// We need this rule string because we generate a hash. Removing this will break firewall reload.
	ruleString := fmt.Sprintf(
		"incoming: %v, proto: %v, startPort: %v, endPort: %v, groups: %v, host: %v, ip: %v, localIp: %v, caName: %v, caSha: %s",
		incoming, proto, startPort, endPort, groups, host, cidr, localCidr, caName, caSha,
	)
	f.rules += ruleString + "\n"

	direction := "incoming"
	if !incoming {
		direction = "outgoing"
	}
	f.l.WithField("firewallRule", m{"direction": direction, "proto": proto, "startPort": startPort, "endPort": endPort, "groups": groups, "host": host, "cidr": cidr, "localCidr": localCidr, "caName": caName, "caSha": caSha}).
		Info("Firewall rule added")

	var (
		ft *FirewallTable
		fp firewallPort
	)

	if incoming {
		ft = f.InRules
	} else {
		ft = f.OutRules
	}

	switch proto {
	case firewall.ProtoTCP:
		fp = ft.TCP
	case firewall.ProtoUDP:
		fp = ft.UDP
	case firewall.ProtoICMP, firewall.ProtoICMPv6:
		fp = ft.ICMP
	case firewall.ProtoAny:
		fp = ft.AnyProto
	default:
		return fmt.Errorf("unknown protocol %v", proto)
	}

	return fp.addRule(f, startPort, endPort, groups, host, cidr, localCidr, caName, caSha)
}

// GetRuleHash returns a hash representation of all inbound and outbound rules
func (f *Firewall) GetRuleHash() string {
	sum := sha256.Sum256([]byte(f.rules))
	return hex.EncodeToString(sum[:])
}

// GetRuleHashFNV returns a uint32 FNV-1 hash representation the rules, for use as a metric value
func (f *Firewall) GetRuleHashFNV() uint32 {
	h := fnv.New32a()
	h.Write([]byte(f.rules))
	return h.Sum32()
}

// GetRuleHashes returns both the sha256 and FNV-1 hashes, suitable for logging
func (f *Firewall) GetRuleHashes() string {
	return "SHA:" + f.GetRuleHash() + ",FNV:" + strconv.FormatUint(uint64(f.GetRuleHashFNV()), 10)
}

func AddFirewallRulesFromConfig(l *logrus.Logger, inbound bool, c *config.C, fw FirewallInterface) error {
	var table string
	if inbound {
		table = "firewall.inbound"
	} else {
		table = "firewall.outbound"
	}

	r := c.Get(table)
	if r == nil {
		return nil
	}

	rs, ok := r.([]any)
	if !ok {
		return fmt.Errorf("%s failed to parse, should be an array of rules", table)
	}

	for i, t := range rs {
		r, err := convertRule(l, t, table, i)
		if err != nil {
			return fmt.Errorf("%s rule #%v; %s", table, i, err)
		}

		if r.Code != "" && r.Port != "" {
			return fmt.Errorf("%s rule #%v; only one of port or code should be provided", table, i)
		}

		if r.Host == "" && len(r.Groups) == 0 && r.Cidr == "" && r.LocalCidr == "" && r.CAName == "" && r.CASha == "" {
			return fmt.Errorf("%s rule #%v; at least one of host, group, cidr, local_cidr, ca_name, or ca_sha must be provided", table, i)
		}

		var sPort, errPort string
		if r.Code != "" {
			errPort = "code"
			sPort = r.Code
		} else {
			errPort = "port"
			sPort = r.Port
		}

		startPort, endPort, err := parsePort(sPort)
		if err != nil {
			return fmt.Errorf("%s rule #%v; %s %s", table, i, errPort, err)
		}

		var proto uint8
		switch r.Proto {
		case "any":
			proto = firewall.ProtoAny
		case "tcp":
			proto = firewall.ProtoTCP
		case "udp":
			proto = firewall.ProtoUDP
		case "icmp":
			proto = firewall.ProtoICMP
		default:
			return fmt.Errorf("%s rule #%v; proto was not understood; `%s`", table, i, r.Proto)
		}

		if r.Cidr != "" && r.Cidr != "any" {
			_, err = netip.ParsePrefix(r.Cidr)
			if err != nil {
				return fmt.Errorf("%s rule #%v; cidr did not parse; %s", table, i, err)
			}
		}

		if r.LocalCidr != "" && r.LocalCidr != "any" {
			_, err = netip.ParsePrefix(r.LocalCidr)
			if err != nil {
				return fmt.Errorf("%s rule #%v; local_cidr did not parse; %s", table, i, err)
			}
		}

		if warning := r.sanity(); warning != nil {
			l.Warnf("%s rule #%v; %s", table, i, warning)
		}

		err = fw.AddRule(inbound, proto, startPort, endPort, r.Groups, r.Host, r.Cidr, r.LocalCidr, r.CAName, r.CASha)
		if err != nil {
			return fmt.Errorf("%s rule #%v; `%s`", table, i, err)
		}
	}

	return nil
}

var ErrUnknownNetworkType = errors.New("unknown network type")
var ErrPeerRejected = errors.New("remote address is not within a network that we handle")
var ErrInvalidRemoteIP = errors.New("remote address is not in remote certificate networks")
var ErrInvalidLocalIP = errors.New("local address is not in list of handled local addresses")
var ErrNoMatchingRule = errors.New("no matching rule in firewall table")

// Drop returns an error if the packet should be dropped, explaining why. It
// returns nil if the packet should not be dropped.
func (f *Firewall) Drop(fp firewall.Packet, incoming bool, h *HostInfo, caPool *cert.CAPool, localCache firewall.ConntrackCache) error {
	// Check if we spoke to this tuple, if we did then allow this packet
	if f.inConns(fp, h, caPool, localCache) {
		return nil
	}

	// Make sure remote address matches nebula certificate, and determine how to treat it
	if h.networks == nil {
		// Simple case: Certificate has one address and no unsafe networks
		if h.vpnAddrs[0] != fp.RemoteAddr {
			f.metrics(incoming).droppedRemoteAddr.Inc(1)
			return ErrInvalidRemoteIP
		}
	} else {
		nwType, ok := h.networks.Lookup(fp.RemoteAddr)
		if !ok {
			f.metrics(incoming).droppedRemoteAddr.Inc(1)
			return ErrInvalidRemoteIP
		}
		switch nwType {
		case NetworkTypeVPN:
			break // nothing special
		case NetworkTypeVPNPeer:
			f.metrics(incoming).droppedRemoteAddr.Inc(1)
			return ErrPeerRejected // reject for now, one day this may have different FW rules
		case NetworkTypeUnsafe:
			break // nothing special, one day this may have different FW rules
		default:
			f.metrics(incoming).droppedRemoteAddr.Inc(1)
			return ErrUnknownNetworkType //should never happen
		}
	}

	// Make sure we are supposed to be handling this local ip address
	if !f.routableNetworks.Contains(fp.LocalAddr) {
		f.metrics(incoming).droppedLocalAddr.Inc(1)
		return ErrInvalidLocalIP
	}

	table := f.OutRules
	if incoming {
		table = f.InRules
	}

	// We now know which firewall table to check against
	if !table.match(fp, incoming, h.ConnectionState.peerCert, caPool) {
		f.metrics(incoming).droppedNoRule.Inc(1)
		return ErrNoMatchingRule
	}

	// We always want to conntrack since it is a faster operation
	f.addConn(fp, incoming)

	return nil
}

func (f *Firewall) metrics(incoming bool) firewallMetrics {
	if incoming {
		return f.incomingMetrics
	} else {
		return f.outgoingMetrics
	}
}

// Destroy cleans up any known cyclical references so the object can be free'd my GC. This should be called if a new
// firewall object is created
func (f *Firewall) Destroy() {
	//TODO: clean references if/when needed
}

func (f *Firewall) EmitStats() {
	conntrack := f.Conntrack
	conntrack.Lock()
	conntrackCount := len(conntrack.Conns)
	conntrack.Unlock()
	metrics.GetOrRegisterGauge("firewall.conntrack.count", nil).Update(int64(conntrackCount))
	metrics.GetOrRegisterGauge("firewall.rules.version", nil).Update(int64(f.rulesVersion))
	metrics.GetOrRegisterGauge("firewall.rules.hash", nil).Update(int64(f.GetRuleHashFNV()))
}

func (f *Firewall) inConns(fp firewall.Packet, h *HostInfo, caPool *cert.CAPool, localCache firewall.ConntrackCache) bool {
	if localCache != nil {
		if _, ok := localCache[fp]; ok {
			return true
		}
	}
	conntrack := f.Conntrack
	conntrack.Lock()

	// Purge every time we test
	ep, has := conntrack.TimerWheel.Purge()
	if has {
		f.evict(ep)
	}

	c, ok := conntrack.Conns[fp]

	if !ok {
		conntrack.Unlock()
		return false
	}

	if c.rulesVersion != f.rulesVersion {
		// This conntrack entry was for an older rule set, validate
		// it still passes with the current rule set
		table := f.OutRules
		if c.incoming {
			table = f.InRules
		}

		// We now know which firewall table to check against
		if !table.match(fp, c.incoming, h.ConnectionState.peerCert, caPool) {
			if f.l.Level >= logrus.DebugLevel {
				h.logger(f.l).
					WithField("fwPacket", fp).
					WithField("incoming", c.incoming).
					WithField("rulesVersion", f.rulesVersion).
					WithField("oldRulesVersion", c.rulesVersion).
					Debugln("dropping old conntrack entry, does not match new ruleset")
			}
			delete(conntrack.Conns, fp)
			conntrack.Unlock()
			return false
		}

		if f.l.Level >= logrus.DebugLevel {
			h.logger(f.l).
				WithField("fwPacket", fp).
				WithField("incoming", c.incoming).
				WithField("rulesVersion", f.rulesVersion).
				WithField("oldRulesVersion", c.rulesVersion).
				Debugln("keeping old conntrack entry, does match new ruleset")
		}

		c.rulesVersion = f.rulesVersion
	}

	switch fp.Protocol {
	case firewall.ProtoTCP:
		c.Expires = time.Now().Add(f.TCPTimeout)
	case firewall.ProtoUDP:
		c.Expires = time.Now().Add(f.UDPTimeout)
	default:
		c.Expires = time.Now().Add(f.DefaultTimeout)
	}

	conntrack.Unlock()

	if localCache != nil {
		localCache[fp] = struct{}{}
	}

	return true
}

func (f *Firewall) addConn(fp firewall.Packet, incoming bool) {
	var timeout time.Duration
	c := &conn{}

	switch fp.Protocol {
	case firewall.ProtoTCP:
		timeout = f.TCPTimeout
	case firewall.ProtoUDP:
		timeout = f.UDPTimeout
	default:
		timeout = f.DefaultTimeout
	}

	conntrack := f.Conntrack
	conntrack.Lock()
	if _, ok := conntrack.Conns[fp]; !ok {
		conntrack.TimerWheel.Advance(time.Now())
		conntrack.TimerWheel.Add(fp, timeout)
	}

	// Record which rulesVersion allowed this connection, so we can retest after
	// firewall reload
	c.incoming = incoming
	c.rulesVersion = f.rulesVersion
	c.Expires = time.Now().Add(timeout)
	conntrack.Conns[fp] = c
	conntrack.Unlock()
}

// Evict checks if a conntrack entry has expired, if so it is removed, if not it is re-added to the wheel
// Caller must own the connMutex lock!
func (f *Firewall) evict(p firewall.Packet) {
	// Are we still tracking this conn?
	conntrack := f.Conntrack
	t, ok := conntrack.Conns[p]
	if !ok {
		return
	}

	newT := t.Expires.Sub(time.Now())

	// Timeout is in the future, re-add the timer
	if newT > 0 {
		conntrack.TimerWheel.Advance(time.Now())
		conntrack.TimerWheel.Add(p, newT)
		return
	}

	// This conn is done
	delete(conntrack.Conns, p)
}

func (ft *FirewallTable) match(p firewall.Packet, incoming bool, c *cert.CachedCertificate, caPool *cert.CAPool) bool {
	if ft.AnyProto.match(p, incoming, c, caPool) {
		return true
	}

	switch p.Protocol {
	case firewall.ProtoTCP:
		if ft.TCP.match(p, incoming, c, caPool) {
			return true
		}
	case firewall.ProtoUDP:
		if ft.UDP.match(p, incoming, c, caPool) {
			return true
		}
	case firewall.ProtoICMP, firewall.ProtoICMPv6:
		if ft.ICMP.match(p, incoming, c, caPool) {
			return true
		}
	}

	return false
}

func (fp firewallPort) addRule(f *Firewall, startPort int32, endPort int32, groups []string, host string, cidr, localCidr, caName string, caSha string) error {
	if startPort > endPort {
		return fmt.Errorf("start port was lower than end port")
	}

	for i := startPort; i <= endPort; i++ {
		if _, ok := fp[i]; !ok {
			fp[i] = &FirewallCA{
				CANames: make(map[string]*FirewallRule),
				CAShas:  make(map[string]*FirewallRule),
			}
		}

		if err := fp[i].addRule(f, groups, host, cidr, localCidr, caName, caSha); err != nil {
			return err
		}
	}

	return nil
}

func (fp firewallPort) match(p firewall.Packet, incoming bool, c *cert.CachedCertificate, caPool *cert.CAPool) bool {
	// We don't have any allowed ports, bail
	if fp == nil {
		return false
	}

	var port int32

	if p.Fragment {
		port = firewall.PortFragment
	} else if incoming {
		port = int32(p.LocalPort)
	} else {
		port = int32(p.RemotePort)
	}

	if fp[port].match(p, c, caPool) {
		return true
	}

	return fp[firewall.PortAny].match(p, c, caPool)
}

func (fc *FirewallCA) addRule(f *Firewall, groups []string, host string, cidr, localCidr, caName, caSha string) error {
	fr := func() *FirewallRule {
		return &FirewallRule{
			Hosts:  make(map[string]*firewallLocalCIDR),
			Groups: make([]*firewallGroups, 0),
			CIDR:   new(bart.Table[*firewallLocalCIDR]),
		}
	}

	if caSha == "" && caName == "" {
		if fc.Any == nil {
			fc.Any = fr()
		}

		return fc.Any.addRule(f, groups, host, cidr, localCidr)
	}

	if caSha != "" {
		if _, ok := fc.CAShas[caSha]; !ok {
			fc.CAShas[caSha] = fr()
		}
		err := fc.CAShas[caSha].addRule(f, groups, host, cidr, localCidr)
		if err != nil {
			return err
		}
	}

	if caName != "" {
		if _, ok := fc.CANames[caName]; !ok {
			fc.CANames[caName] = fr()
		}
		err := fc.CANames[caName].addRule(f, groups, host, cidr, localCidr)
		if err != nil {
			return err
		}
	}

	return nil
}

func (fc *FirewallCA) match(p firewall.Packet, c *cert.CachedCertificate, caPool *cert.CAPool) bool {
	if fc == nil {
		return false
	}

	if fc.Any.match(p, c) {
		return true
	}

	if t, ok := fc.CAShas[c.Certificate.Issuer()]; ok {
		if t.match(p, c) {
			return true
		}
	}

	s, err := caPool.GetCAForCert(c.Certificate)
	if err != nil {
		return false
	}

	return fc.CANames[s.Certificate.Name()].match(p, c)
}

func (fr *FirewallRule) addRule(f *Firewall, groups []string, host, cidr, localCidr string) error {
	flc := func() *firewallLocalCIDR {
		return &firewallLocalCIDR{
			LocalCIDR: new(bart.Lite),
		}
	}

	if fr.isAny(groups, host, cidr) {
		if fr.Any == nil {
			fr.Any = flc()
		}

		return fr.Any.addRule(f, localCidr)
	}

	if len(groups) > 0 {
		nlc := flc()
		err := nlc.addRule(f, localCidr)
		if err != nil {
			return err
		}

		fr.Groups = append(fr.Groups, &firewallGroups{
			Groups:    groups,
			LocalCIDR: nlc,
		})
	}

	if host != "" {
		nlc := fr.Hosts[host]
		if nlc == nil {
			nlc = flc()
		}
		err := nlc.addRule(f, localCidr)
		if err != nil {
			return err
		}
		fr.Hosts[host] = nlc
	}

	if cidr != "" {
		c, err := netip.ParsePrefix(cidr)
		if err != nil {
			return err
		}
		nlc, _ := fr.CIDR.Get(c)
		if nlc == nil {
			nlc = flc()
		}
		err = nlc.addRule(f, localCidr)
		if err != nil {
			return err
		}
		fr.CIDR.Insert(c, nlc)
	}

	return nil
}

func (fr *FirewallRule) isAny(groups []string, host string, cidr string) bool {
	if len(groups) == 0 && host == "" && cidr == "" {
		return true
	}

	for _, group := range groups {
		if group == "any" {
			return true
		}
	}

	if host == "any" {
		return true
	}

	if cidr == "any" {
		return true
	}

	return false
}

func (fr *FirewallRule) match(p firewall.Packet, c *cert.CachedCertificate) bool {
	if fr == nil {
		return false
	}

	// Shortcut path for if groups, hosts, or cidr contained an `any`
	if fr.Any.match(p, c) {
		return true
	}

	// Need any of group, host, or cidr to match
	for _, sg := range fr.Groups {
		found := false

		for _, g := range sg.Groups {
			if _, ok := c.InvertedGroups[g]; !ok {
				found = false
				break
			}

			found = true
		}

		if found && sg.LocalCIDR.match(p, c) {
			return true
		}
	}

	if fr.Hosts != nil {
		if flc, ok := fr.Hosts[c.Certificate.Name()]; ok {
			if flc.match(p, c) {
				return true
			}
		}
	}

	for _, v := range fr.CIDR.Supernets(netip.PrefixFrom(p.RemoteAddr, p.RemoteAddr.BitLen())) {
		if v.match(p, c) {
			return true
		}
	}

	return false
}

func (flc *firewallLocalCIDR) addRule(f *Firewall, localCidr string) error {
	if localCidr == "any" {
		flc.Any = true
		return nil
	}

	if localCidr == "" {
		if !f.hasUnsafeNetworks || f.defaultLocalCIDRAny {
			flc.Any = true
			return nil
		}

		for _, network := range f.assignedNetworks {
			flc.LocalCIDR.Insert(network)
		}
		return nil

	}

	c, err := netip.ParsePrefix(localCidr)
	if err != nil {
		return err
	}
	flc.LocalCIDR.Insert(c)
	return nil
}

func (flc *firewallLocalCIDR) match(p firewall.Packet, c *cert.CachedCertificate) bool {
	if flc == nil {
		return false
	}

	if flc.Any {
		return true
	}

	return flc.LocalCIDR.Contains(p.LocalAddr)
}

type rule struct {
	Port      string
	Code      string
	Proto     string
	Host      string
	Groups    []string
	Cidr      string
	LocalCidr string
	CAName    string
	CASha     string
}

func convertRule(l *logrus.Logger, p any, table string, i int) (rule, error) {
	r := rule{}

	m, ok := p.(map[string]any)
	if !ok {
		return r, errors.New("could not parse rule")
	}

	toString := func(k string, m map[string]any) string {
		v, ok := m[k]
		if !ok {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}

	r.Port = toString("port", m)
	r.Code = toString("code", m)
	r.Proto = toString("proto", m)
	r.Host = toString("host", m)
	r.Cidr = toString("cidr", m)
	r.LocalCidr = toString("local_cidr", m)
	r.CAName = toString("ca_name", m)
	r.CASha = toString("ca_sha", m)

	// Make sure group isn't an array
	if v, ok := m["group"].([]any); ok {
		if len(v) > 1 {
			return r, errors.New("group should contain a single value, an array with more than one entry was provided")
		}

		l.Warnf("%s rule #%v; group was an array with a single value, converting to simple value", table, i)
		m["group"] = v[0]
	}

	singleGroup := toString("group", m)

	if rg, ok := m["groups"]; ok {
		switch reflect.TypeOf(rg).Kind() {
		case reflect.Slice:
			v := reflect.ValueOf(rg)
			r.Groups = make([]string, v.Len())
			for i := 0; i < v.Len(); i++ {
				r.Groups[i] = v.Index(i).Interface().(string)
			}
		case reflect.String:
			r.Groups = []string{rg.(string)}
		default:
			r.Groups = []string{fmt.Sprintf("%v", rg)}
		}
	}

	//flatten group vs groups
	if singleGroup != "" {
		// Check if we have both groups and group provided in the rule config
		if len(r.Groups) > 0 {
			return r, fmt.Errorf("only one of group or groups should be defined, both provided")
		}
		r.Groups = []string{singleGroup}
	}

	return r, nil
}

// sanity returns an error if the rule would be evaluated in a way that would short-circuit a configured check on a wildcard value
// rules are evaluated as "port AND proto AND (ca_sha OR ca_name) AND (host OR group OR groups OR cidr) AND local_cidr"
func (r *rule) sanity() error {
	//port, proto, local_cidr are AND, no need to check here
	//ca_sha and ca_name don't have a wildcard value, no need to check here
	groupsEmpty := len(r.Groups) == 0
	hostEmpty := r.Host == ""
	cidrEmpty := r.Cidr == ""

	if (groupsEmpty && hostEmpty && cidrEmpty) == true {
		return nil //no content!
	}

	groupsHasAny := slices.Contains(r.Groups, "any")
	if groupsHasAny && len(r.Groups) > 1 {
		return fmt.Errorf("groups spec [%s] contains the group '\"any\". This rule will ignore the other groups specified", r.Groups)
	}

	if r.Host == "any" {
		if !groupsEmpty {
			return fmt.Errorf("groups specified as %s, but host=any will match any host, regardless of groups", r.Groups)
		}

		if !cidrEmpty {
			return fmt.Errorf("cidr specified as %s, but host=any will match any host, regardless of cidr", r.Cidr)
		}
	}

	if groupsHasAny {
		if !hostEmpty && r.Host != "any" {
			return fmt.Errorf("groups spec [%s] contains the group '\"any\". This rule will ignore the specified host %s", r.Groups, r.Host)
		}
		if !cidrEmpty {
			return fmt.Errorf("groups spec [%s] contains the group '\"any\". This rule will ignore the specified cidr %s", r.Groups, r.Cidr)
		}
	}

	//todo alert on cidr-any

	return nil
}

func parsePort(s string) (startPort, endPort int32, err error) {
	if s == "any" {
		startPort = firewall.PortAny
		endPort = firewall.PortAny

	} else if s == "fragment" {
		startPort = firewall.PortFragment
		endPort = firewall.PortFragment

	} else if strings.Contains(s, `-`) {
		sPorts := strings.SplitN(s, `-`, 2)
		sPorts[0] = strings.Trim(sPorts[0], " ")
		sPorts[1] = strings.Trim(sPorts[1], " ")

		if len(sPorts) != 2 || sPorts[0] == "" || sPorts[1] == "" {
			return 0, 0, fmt.Errorf("appears to be a range but could not be parsed; `%s`", s)
		}

		rStartPort, err := strconv.Atoi(sPorts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("beginning range was not a number; `%s`", sPorts[0])
		}

		rEndPort, err := strconv.Atoi(sPorts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("ending range was not a number; `%s`", sPorts[1])
		}

		startPort = int32(rStartPort)
		endPort = int32(rEndPort)

		if startPort == firewall.PortAny {
			endPort = firewall.PortAny
		}

	} else {
		rPort, err := strconv.Atoi(s)
		if err != nil {
			return 0, 0, fmt.Errorf("was not a number; `%s`", s)
		}
		startPort = int32(rPort)
		endPort = startPort
	}

	return
}
