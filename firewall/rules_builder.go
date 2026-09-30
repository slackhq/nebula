package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/gaissmai/bart"
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

// rule is a parsed rule, so adding it to a Table can't fail
type rule struct {
	startPort, endPort int32
	groups             []string
	host               string
	caName, caSha      string

	// cidr is the remote cidr, not valid when the rule doesn't have one
	cidr    netip.Prefix
	anyCIDR bool

	// localCIDR is the local addresses the rule allows, anyLocalCIDR allows all of them.
	// Neither is set for a rule without a local cidr until the Table is built and it gets the default.
	// localCIDR is shared by every localRules the rule is added to, so it's never changed, see localRules.add
	localCIDR    *bart.Lite
	anyLocalCIDR bool
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
	var defaultLocal *bart.Lite
	if len(unsafeNetworks) > 0 && !b.defaultLocalCIDRAny {
		defaultLocal = new(bart.Lite)
		for _, network := range vpnNetworks {
			defaultLocal.Insert(network)
		}
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

	r := rule{
		startPort: startPort,
		endPort:   endPort,
		groups:    groups,
		host:      host,
		caName:    caName,
		caSha:     caSha,
	}

	var err error
	r.cidr, r.anyCIDR, err = parseCIDR(cidr)
	if err != nil {
		return rule{}, fmt.Errorf("cidr did not parse; %w", err)
	}

	var localCIDR netip.Prefix
	localCIDR, r.anyLocalCIDR, err = parseCIDR(localCidr)
	if err != nil {
		return rule{}, fmt.Errorf("local_cidr did not parse; %w", err)
	}
	if localCIDR.IsValid() {
		r.localCIDR = new(bart.Lite)
		r.localCIDR.Insert(localCIDR)
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
func (tr *tableRules) build(defaultLocal *bart.Lite) *Table {
	t := &Table{}

	// Every protocol starts out sharing the proto `any` rules, including protos[ProtoAny]
	anyProto := newPortRules(defaultLocal, tr.anyRules)
	for proto := range t.protos {
		t.protos[proto] = anyProto
	}

	// Protocols with rules of their own get a copy of the proto `any` rules too, so a packet only checks one set
	for proto, rules := range tr.protoRules {
		if len(rules) > 0 {
			t.protos[proto] = newPortRules(defaultLocal, tr.anyRules, rules)
		}
	}

	// ICMP and ICMPv6 share one set of rules, add keeps them together under ICMP
	t.protos[iputil.IPProtocolICMPv6] = t.protos[iputil.IPProtocolICMP]

	return t
}

// newPortRules builds portRules from each set of rules, or returns nil when there are none
func newPortRules(defaultLocal *bart.Lite, ruleSets ...[]rule) portRules {
	var pr portRules
	for _, rules := range ruleSets {
		for _, r := range rules {
			if pr == nil {
				pr = portRules{}
			}
			pr.add(r.withDefaultLocal(defaultLocal))
		}
	}
	return pr
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

// isAny reports whether r matches any host, making its groups, host, and cidr irrelevant
func (r rule) isAny() bool {
	if len(r.groups) == 0 && r.host == "" && !r.cidr.IsValid() {
		return true
	}

	return slices.Contains(r.groups, "any") || r.host == "any" || r.anyCIDR
}

// withDefaultLocal returns r allowing defaultLocal, or any local address when defaultLocal is nil,
// unless r has a local cidr of its own
func (r rule) withDefaultLocal(defaultLocal *bart.Lite) rule {
	if !r.anyLocalCIDR && r.localCIDR == nil {
		r.anyLocalCIDR = defaultLocal == nil
		r.localCIDR = defaultLocal
	}
	return r
}

func (pr portRules) add(r rule) {
	for i := r.startPort; i <= r.endPort; i++ {
		cr := pr[i]
		if cr == nil {
			cr = &caRules{}
			pr[i] = cr
		}
		cr.add(r)
	}
}

func (cr *caRules) add(r rule) {
	if r.caSha == "" && r.caName == "" {
		if cr.Any == nil {
			cr.Any = &remoteRules{}
		}
		cr.Any.add(r)
		return
	}

	if r.caSha != "" {
		getOrNew(&cr.CAShas, r.caSha).add(r)
	}

	if r.caName != "" {
		getOrNew(&cr.CANames, r.caName).add(r)
	}
}

func (rr *remoteRules) add(r rule) {
	if r.isAny() {
		if rr.Any == nil {
			rr.Any = &localRules{}
		}
		rr.Any.add(r)
		return
	}

	if len(r.groups) > 0 {
		lr := &localRules{}
		lr.add(r)
		rr.Groups = append(rr.Groups, &groupsRule{
			Groups:    r.groups,
			LocalCIDR: lr,
		})
	}

	if r.host != "" {
		getOrNew(&rr.Hosts, r.host).add(r)
	}

	if r.cidr.IsValid() {
		if rr.CIDR == nil {
			rr.CIDR = new(bart.Table[*localRules])
		}
		lr, ok := rr.CIDR.Get(r.cidr)
		if !ok {
			lr = &localRules{}
			rr.CIDR.Insert(r.cidr, lr)
		}
		lr.add(r)
	}
}

func (lr *localRules) add(r rule) {
	if r.anyLocalCIDR {
		lr.Any = true
		return
	}

	// Share the rule's local cidrs until another rule's need adding, then copy them instead of changing them
	if lr.LocalCIDR == nil {
		lr.LocalCIDR = r.localCIDR
		return
	}
	for prefix := range r.localCIDR.All() {
		lr.LocalCIDR = lr.LocalCIDR.InsertPersist(prefix)
	}
}

// getOrNew returns m[k], adding a new value for k first when there isn't one. m is made if it's nil.
func getOrNew[M ~map[K]*V, K comparable, V any](m *M, k K) *V {
	if *m == nil {
		*m = make(M)
	}
	v := (*m)[k]
	if v == nil {
		v = new(V)
		(*m)[k] = v
	}
	return v
}
