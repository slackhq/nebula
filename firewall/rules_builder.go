package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"slices"

	"github.com/slackhq/nebula/iputil"
)

// RulesBuilder collects the inbound and outbound rules, Build turns them into a Table for each direction
type RulesBuilder struct {
	in, out tableRules

	// defaultLocalCIDRAny makes rules without a local cidr allow any local address, even with unsafe networks
	defaultLocalCIDRAny bool

	// ruleSHA and ruleFNV hash every rule as it's added, see Rules
	ruleSHA hash.Hash
	ruleFNV hash.Hash32

	l *slog.Logger
}

// tableRules are one direction's rules, waiting to be built into a Table
type tableRules struct {
	anyRules []rule
	// protoRules holds the rules for each protocol besides proto `any`, ICMPv6 rules are kept with ICMP
	protoRules [256][]rule
}

func NewRulesBuilder(l *slog.Logger) *RulesBuilder {
	return &RulesBuilder{
		ruleSHA: sha256.New(),
		ruleFNV: fnv.New32a(),
		l:       l,
	}
}

// AddRule adds a rule for incoming or outgoing traffic, on proto or on every protocol when proto is ProtoAny.
// The rule is parsed now, so a bad rule is reported when it's added rather than when the Tables are built.
func (b *RulesBuilder) AddRule(incoming bool, proto uint8, startPort int32, endPort int32, groups []string, host string, cidr, localCidr, caName string, caSha string) error {
	if proto == iputil.IPProtocolICMP || proto == iputil.IPProtocolICMPv6 {
		//ICMP traffic doesn't have ports, so we always coerce to "any", even if a value is provided
		if startPort != PortAny {
			b.l.Warn("ignoring port specification for ICMP firewall rule", "startPort", startPort)
		}
		startPort = PortAny
		endPort = PortAny
	}

	r, err := parseRule(startPort, endPort, groups, host, cidr, localCidr, caName, caSha)
	if err != nil {
		return err
	}

	if incoming {
		b.in.add(proto, r)
	} else {
		b.out.add(proto, r)
	}

	// The rule hashes are of these lines, changing them changes every hash
	fmt.Fprintf(io.MultiWriter(b.ruleSHA, b.ruleFNV),
		"incoming: %v, proto: %v, startPort: %v, endPort: %v, groups: %v, host: %v, ip: %v, localIp: %v, caName: %v, caSha: %s\n",
		incoming, proto, startPort, endPort, groups, host, cidr, localCidr, caName, caSha,
	)

	direction := "incoming"
	if !incoming {
		direction = "outgoing"
	}
	b.l.Info("Firewall rule added",
		"firewallRule", m{"direction": direction, "proto": proto, "startPort": startPort, "endPort": endPort, "groups": groups, "host": host, "cidr": cidr, "localCidr": localCidr, "caName": caName, "caSha": caSha},
	)

	return nil
}

// Build turns the rules into a Table for each direction, and hashes them. Rules without a local cidr allow
// vpnNetworks when there are unsafe networks, otherwise any local address.
func (b *RulesBuilder) Build(vpnNetworks, unsafeNetworks []netip.Prefix) Rules {
	var defaultLocal []netip.Prefix
	if len(unsafeNetworks) > 0 && !b.defaultLocalCIDRAny {
		// Never nil, even when there are no vpn networks, so that the rules allow nothing rather than everything.
		defaultLocal = append([]netip.Prefix{}, vpnNetworks...)
	}

	return Rules{
		In:      b.in.build(defaultLocal),
		Out:     b.out.build(defaultLocal),
		Hash:    hex.EncodeToString(b.ruleSHA.Sum(nil)),
		HashFNV: b.ruleFNV.Sum32(),
	}
}

func parseRule(startPort, endPort int32, groups []string, host, cidr, localCidr, caName, caSha string) (rule, error) {
	if startPort > endPort {
		return rule{}, fmt.Errorf("start port was lower than end port")
	}
	if startPort < PortFragment || endPort > math.MaxUint16 {
		return rule{}, fmt.Errorf("port range %d-%d is outside of %d-%d", startPort, endPort, PortFragment, math.MaxUint16)
	}
	// A range that includes port 0 is port `any`.
	if startPort <= PortAny && PortAny <= endPort {
		startPort, endPort = PortAny, PortAny
	}

	r := rule{
		startPort: startPort,
		endPort:   endPort,
		groups:    groups,
		host:      host,
		caName:    caName,
		caSha:     caSha,
	}

	var anyCIDR bool
	var err error
	r.cidr, anyCIDR, err = parseCIDR(cidr)
	if err != nil {
		return rule{}, fmt.Errorf("cidr did not parse; %w", err)
	}

	// A rule with no group, host, or cidr allows any host, as does a rule with `any` for one of them.
	r.remoteAny = anyCIDR || host == "any" || slices.Contains(groups, "any") ||
		(len(groups) == 0 && host == "" && !r.cidr.IsValid())

	var localCIDR netip.Prefix
	localCIDR, r.localAny, err = parseCIDR(localCidr)
	if err != nil {
		return rule{}, fmt.Errorf("local_cidr did not parse; %w", err)
	}
	if localCIDR.IsValid() {
		r.local = []netip.Prefix{localCIDR}
	}

	return r, nil
}

// add keeps r for proto, or for every protocol when proto is ProtoAny
func (tr *tableRules) add(proto uint8, r rule) {
	switch proto {
	case ProtoAny:
		tr.anyRules = append(tr.anyRules, r)
	case iputil.IPProtocolICMPv6:
		tr.protoRules[iputil.IPProtocolICMP] = append(tr.protoRules[iputil.IPProtocolICMP], r)
	default:
		tr.protoRules[proto] = append(tr.protoRules[proto], r)
	}
}

// build turns the rules into a Table. Rules without a local cidr allow defaultLocal,
// or any local address when defaultLocal is nil.
func (tr *tableRules) build(defaultLocal []netip.Prefix) *Table {
	t := &Table{}

	// A rule's id is its index in t.rules.
	add := func(rules []rule) []int {
		ids := make([]int, 0, len(rules))
		for _, r := range rules {
			ids = append(ids, len(t.rules))
			t.rules = append(t.rules, r.withDefaultLocal(defaultLocal))
		}
		return ids
	}
	anyIDs := add(tr.anyRules)
	var protoIDs [256][]int
	for proto, rules := range tr.protoRules {
		protoIDs[proto] = add(rules)
	}

	// Every protocol starts out sharing an index of the proto `any` rules, including protos[ProtoAny]. There is
	// one for protocols with ports and one for protocols without.
	anyPorts := newProtoIndex(true, t.rules, anyIDs)
	anyNoPorts := newProtoIndex(false, t.rules, anyIDs)
	for proto := range t.protos {
		if hasPorts(uint8(proto)) {
			t.protos[proto] = anyPorts
		} else {
			t.protos[proto] = anyNoPorts
		}
	}

	// A protocol with rules of its own gets an index of those rules plus the proto `any` rules, so a packet
	// checks a single index.
	for proto, ids := range protoIDs {
		if len(ids) > 0 {
			t.protos[proto] = newProtoIndex(hasPorts(uint8(proto)), t.rules, anyIDs, ids)
		}
	}

	// ICMP and ICMPv6 share one set of rules; add keeps them together under ICMP.
	t.protos[iputil.IPProtocolICMPv6] = t.protos[iputil.IPProtocolICMP]

	return t
}

// newProtoIndex builds an index of the rules with the given ids for a protocol with or without ports, or
// returns nil when there are none.
func newProtoIndex(hasPorts bool, rules []rule, idSets ...[]int) *protoIndex {
	ids := slices.Concat(idSets...)
	if len(ids) == 0 {
		return nil
	}

	pi := &protoIndex{hasPorts: hasPorts, fragment: newRuleSet(len(rules))}
	if hasPorts {
		pi.byPort = newRuleSets(math.MaxUint16+1, len(rules))
	} else {
		pi.packet = newRuleSet(len(rules))
	}

	for _, id := range ids {
		pi.add(&rules[id], id)
	}
	return pi
}

// add puts id in every set that r's port clause covers.
func (pi *protoIndex) add(r *rule, id int) {
	switch r.startPort {
	case PortAny:
		pi.fragment.add(id)
		if pi.hasPorts {
			pi.addPorts(0, math.MaxUint16, id)
		} else {
			pi.packet.add(id)
		}
	case PortFragment:
		pi.fragment.add(id)
	default:
		// A range only applies to a protocol with ports.
		if pi.hasPorts {
			pi.addPorts(int(r.startPort), int(r.endPort), id)
		}
	}
}

// addPorts puts id in the set of every port from lo through hi.
func (pi *protoIndex) addPorts(lo, hi, id int) {
	for port := lo; port <= hi; port++ {
		pi.byPort.at(port).add(id)
	}
}

// parseCIDR parses a rule's cidr, which is empty, `any`, or a prefix
func parseCIDR(s string) (prefix netip.Prefix, isAny bool, err error) {
	switch s {
	case "":
		return netip.Prefix{}, false, nil
	case "any":
		return netip.Prefix{}, true, nil
	}

	prefix, err = netip.ParsePrefix(s)
	return prefix, false, err
}

// withDefaultLocal returns r allowing defaultLocal, or any local address when defaultLocal is nil,
// unless r has a local cidr of its own
func (r rule) withDefaultLocal(defaultLocal []netip.Prefix) rule {
	if !r.localAny && r.local == nil {
		r.localAny = defaultLocal == nil
		r.local = defaultLocal
	}
	return r
}
