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

// Rules are the Tables built for each direction, with hashes of the rules they were built from
type Rules struct {
	In, Out *Table

	// Hash is a sha256 of the rules, HashFNV is an FNV-1a of them for use as a metric value.
	// Rule sets with the same rules have the same hashes.
	Hash    string
	HashFNV uint32
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

	// localCIDRs are the local addresses the rule allows, anyLocalCIDR allows all of them.
	// Neither is set for a rule without a local cidr until the Table is built and it gets the default.
	localCIDRs   []netip.Prefix
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
	anyLocal := len(unsafeNetworks) == 0 || b.defaultLocalCIDRAny
	return Rules{
		In:      b.in.build(anyLocal, vpnNetworks),
		Out:     b.out.build(anyLocal, vpnNetworks),
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
		return rule{}, err
	}

	var localCIDR netip.Prefix
	localCIDR, r.anyLocalCIDR, err = parseCIDR(localCidr)
	if err != nil {
		return rule{}, err
	}
	if localCIDR.IsValid() {
		r.localCIDRs = []netip.Prefix{localCIDR}
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

// build turns the rules into a Table. Rules without a local cidr allow defaultLocalCIDRs,
// or any local address when defaultLocalAny is set.
func (tr *tableRules) build(defaultLocalAny bool, defaultLocalCIDRs []netip.Prefix) *Table {
	add := func(pr portRules, rules []rule) {
		for _, r := range rules {
			if !r.anyLocalCIDR && r.localCIDRs == nil {
				r.anyLocalCIDR, r.localCIDRs = defaultLocalAny, defaultLocalCIDRs
			}
			pr.add(r)
		}
	}

	var anyProto portRules
	if len(tr.anyRules) > 0 {
		anyProto = portRules{}
		add(anyProto, tr.anyRules)
	}

	t := &Table{}
	for proto := range t.Protos {
		rules := tr.protoRules[proto]
		if len(rules) == 0 {
			t.Protos[proto] = anyProto
			continue
		}

		pr := portRules{}
		add(pr, tr.anyRules)
		add(pr, rules)
		t.Protos[proto] = pr
	}
	t.Protos[iputil.IPProtocolICMPv6] = t.Protos[iputil.IPProtocolICMP]

	return t
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

func (pr portRules) add(r rule) {
	for i := r.startPort; i <= r.endPort; i++ {
		if _, ok := pr[i]; !ok {
			pr[i] = &caRules{
				CANames: make(map[string]*remoteRules),
				CAShas:  make(map[string]*remoteRules),
			}
		}

		pr[i].add(r)
	}
}

func (cr *caRules) add(r rule) {
	newRemoteRules := func() *remoteRules {
		return &remoteRules{
			Hosts:  make(map[string]*localRules),
			Groups: make([]*groupsRule, 0),
			CIDR:   new(bart.Table[*localRules]),
		}
	}

	if r.caSha == "" && r.caName == "" {
		if cr.Any == nil {
			cr.Any = newRemoteRules()
		}

		cr.Any.add(r)
		return
	}

	if r.caSha != "" {
		if _, ok := cr.CAShas[r.caSha]; !ok {
			cr.CAShas[r.caSha] = newRemoteRules()
		}
		cr.CAShas[r.caSha].add(r)
	}

	if r.caName != "" {
		if _, ok := cr.CANames[r.caName]; !ok {
			cr.CANames[r.caName] = newRemoteRules()
		}
		cr.CANames[r.caName].add(r)
	}
}

func (rr *remoteRules) add(r rule) {
	newLocalRules := func() *localRules {
		return &localRules{
			LocalCIDR: new(bart.Lite),
		}
	}

	if r.isAny() {
		if rr.Any == nil {
			rr.Any = newLocalRules()
		}

		rr.Any.add(r)
		return
	}

	if len(r.groups) > 0 {
		lr := newLocalRules()
		lr.add(r)

		rr.Groups = append(rr.Groups, &groupsRule{
			Groups:    r.groups,
			LocalCIDR: lr,
		})
	}

	if r.host != "" {
		lr := rr.Hosts[r.host]
		if lr == nil {
			lr = newLocalRules()
		}
		lr.add(r)
		rr.Hosts[r.host] = lr
	}

	if r.cidr.IsValid() {
		lr, _ := rr.CIDR.Get(r.cidr)
		if lr == nil {
			lr = newLocalRules()
		}
		lr.add(r)
		rr.CIDR.Insert(r.cidr, lr)
	}
}

func (lr *localRules) add(r rule) {
	if r.anyLocalCIDR {
		lr.Any = true
		return
	}

	for _, prefix := range r.localCIDRs {
		lr.LocalCIDR.Insert(prefix)
	}
}
