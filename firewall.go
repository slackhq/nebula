package nebula

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/iputil"
)

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

	InRules  *firewall.Table
	OutRules *firewall.Table

	InboundSendReject  bool
	OutboundSendReject bool

	//TODO: we should have many more options for TCP, an option for ICMP, and mimic the kernel a bit better
	// https://www.kernel.org/doc/Documentation/networking/nf_conntrack-sysctl.txt
	TCPTimeout     time.Duration //linux: 5 days max
	UDPTimeout     time.Duration //linux: 180s max
	DefaultTimeout time.Duration //linux: 600s

	// routableNetworks describes the vpn addresses as well as any unsafe networks issued to us in the certificate.
	// The vpn addresses are a full bit match while the unsafe networks only match the prefix
	routableNetworks *bart.Lite

	// assignedNetworks is a list of vpn networks assigned to us in the certificate.
	assignedNetworks []netip.Prefix
	// unsafeNetworks is the list of unsafe networks issued to us in the certificate
	unsafeNetworks []netip.Prefix

	// ruleHash and ruleHashFNV identify the rules, see firewall.Rules
	ruleHash     string
	ruleHashFNV  uint32
	rulesVersion uint16

	incomingMetrics firewallMetrics
	outgoingMetrics firewallMetrics

	l *slog.Logger
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

// NewFirewall creates a new Firewall object. A TimerWheel is created for you from the provided timeouts.
// The certificate provided should be the highest version loaded in memory.
func NewFirewall(l *slog.Logger, tcpTimeout, UDPTimeout, defaultTimeout time.Duration, c cert.Certificate) *Firewall {
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

	unsafeNetworks := c.UnsafeNetworks()
	for _, n := range unsafeNetworks {
		routableNetworks.Insert(n)
	}

	fw := &Firewall{
		Conntrack: &FirewallConntrack{
			Conns:      make(map[firewall.Packet]*conn),
			TimerWheel: NewTimerWheel[firewall.Packet](tmin, tmax),
		},
		TCPTimeout:       tcpTimeout,
		UDPTimeout:       UDPTimeout,
		DefaultTimeout:   defaultTimeout,
		routableNetworks: routableNetworks,
		assignedNetworks: assignedNetworks,
		unsafeNetworks:   unsafeNetworks,
		l:                l,

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

	// Nothing is allowed until there are rules
	fw.setRules(firewall.NewRulesBuilder(l))
	return fw
}

func NewFirewallFromConfig(l *slog.Logger, cs *CertState, c *config.C) (*Firewall, error) {
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

	inboundAction := c.GetString("firewall.inbound_action", "drop")
	switch inboundAction {
	case "reject":
		fw.InboundSendReject = true
	case "drop":
		fw.InboundSendReject = false
	default:
		l.Warn("invalid firewall.inbound_action, defaulting to `drop`", "action", inboundAction)
		fw.InboundSendReject = false
	}

	outboundAction := c.GetString("firewall.outbound_action", "drop")
	switch outboundAction {
	case "reject":
		fw.OutboundSendReject = true
	case "drop":
		fw.OutboundSendReject = false
	default:
		l.Warn("invalid firewall.outbound_action, defaulting to `drop`", "action", outboundAction)
		fw.OutboundSendReject = false
	}

	rules, err := firewall.RulesFromConfig(l, c)
	if err != nil {
		return nil, err
	}
	fw.setRules(rules)

	return fw, nil
}

// setRules builds rules into InRules and OutRules
func (f *Firewall) setRules(rb *firewall.RulesBuilder) {
	rules := rb.Build(f.assignedNetworks, f.unsafeNetworks)
	f.InRules, f.OutRules = rules.In, rules.Out
	f.ruleHash, f.ruleHashFNV = rules.Hash, rules.HashFNV
}

// GetRuleHash returns a hash representation of all inbound and outbound rules
func (f *Firewall) GetRuleHash() string {
	return f.ruleHash
}

// GetRuleHashFNV returns a uint32 FNV-1 hash representation the rules, for use as a metric value
func (f *Firewall) GetRuleHashFNV() uint32 {
	return f.ruleHashFNV
}

// GetRuleHashes returns both the sha256 and FNV-1 hashes, suitable for logging
func (f *Firewall) GetRuleHashes() string {
	return "SHA:" + f.GetRuleHash() + ",FNV:" + strconv.FormatUint(uint64(f.GetRuleHashFNV()), 10)
}

var ErrUnknownNetworkType = errors.New("unknown network type")
var ErrPeerRejected = errors.New("remote address is not within a network that we handle")
var ErrInvalidRemoteIP = errors.New("remote address is not in remote certificate networks")
var ErrInvalidLocalIP = errors.New("local address is not in list of handled local addresses")
var ErrNoMatchingRule = errors.New("no matching rule in firewall table")

// Drop returns an error if the packet should be dropped, explaining why. It
// returns nil if the packet should not be dropped.
func (f *Firewall) Drop(fp firewall.Packet, incoming bool, h *HostInfo, caPool *cert.CAPool, localCache firewall.ConntrackCache) error {
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

	// Check if we spoke to this tuple, if we did then allow this packet
	if f.inConns(&fp, h, caPool, localCache) {
		return nil
	}

	table := f.OutRules
	if incoming {
		table = f.InRules
	}

	// We now know which firewall table to check against
	if !table.Match(&fp, incoming, h.ConnectionState.peerCert, caPool) {
		f.metrics(incoming).droppedNoRule.Inc(1)
		return ErrNoMatchingRule
	}

	// We always want to conntrack since it is a faster operation
	f.addConn(&fp, incoming)

	return nil
}

func (f *Firewall) metrics(incoming bool) firewallMetrics {
	if incoming {
		return f.incomingMetrics
	} else {
		return f.outgoingMetrics
	}
}

// Destroy cleans up any known cyclical references so the object can be freed by GC. This should be called if a new
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

func (f *Firewall) inConns(fp *firewall.Packet, h *HostInfo, caPool *cert.CAPool, localCache firewall.ConntrackCache) bool {
	if localCache != nil {
		if _, ok := localCache[*fp]; ok {
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

	c, ok := conntrack.Conns[*fp]

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
		if !table.Match(fp, c.incoming, h.ConnectionState.peerCert, caPool) {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				h.logger(f.l).Debug("dropping old conntrack entry, does not match new ruleset",
					"fwPacket", *fp,
					"incoming", c.incoming,
					"rulesVersion", f.rulesVersion,
					"oldRulesVersion", c.rulesVersion,
				)
			}
			delete(conntrack.Conns, *fp)
			conntrack.Unlock()
			return false
		}

		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			h.logger(f.l).Debug("keeping old conntrack entry, does match new ruleset",
				"fwPacket", *fp,
				"incoming", c.incoming,
				"rulesVersion", f.rulesVersion,
				"oldRulesVersion", c.rulesVersion,
			)
		}

		c.rulesVersion = f.rulesVersion
	}

	c.Expires = time.Now().Add(f.conntrackTimeout(fp.Protocol))

	conntrack.Unlock()

	if localCache != nil {
		localCache[*fp] = struct{}{}
	}

	return true
}

// conntrackTimeout returns how long a conntrack entry for proto lives without traffic.
// Connection oriented protocols share the tcp timeout, datagram protocols share the udp timeout.
func (f *Firewall) conntrackTimeout(proto uint8) time.Duration {
	switch proto {
	case iputil.IPProtocolTCP, iputil.IPProtocolSCTP, iputil.IPProtocolDCCP:
		return f.TCPTimeout
	case iputil.IPProtocolUDP, iputil.IPProtocolUDPLite:
		return f.UDPTimeout
	default:
		return f.DefaultTimeout
	}
}

func (f *Firewall) addConn(fp *firewall.Packet, incoming bool) {
	timeout := f.conntrackTimeout(fp.Protocol)
	c := &conn{}

	conntrack := f.Conntrack
	conntrack.Lock()
	if _, ok := conntrack.Conns[*fp]; !ok {
		conntrack.TimerWheel.Advance(time.Now())
		conntrack.TimerWheel.Add(*fp, timeout)
	}

	// Record which rulesVersion allowed this connection, so we can retest after
	// firewall reload
	c.incoming = incoming
	c.rulesVersion = f.rulesVersion
	c.Expires = time.Now().Add(timeout)
	conntrack.Conns[*fp] = c
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
