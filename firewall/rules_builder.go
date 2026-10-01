package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"net/netip"
	"slices"
	"strings"

	"github.com/slackhq/nebula/iputil"
)

// RulesBuilder collects the inbound and outbound rules, Build turns them into a Table for each direction
type RulesBuilder struct {
	// in and out are each direction's rules in the order they were added
	in, out []rule

	// defaultLocalCIDRAny makes rules without a local cidr allow any local address, even with unsafe networks
	defaultLocalCIDRAny bool

	// ruleText describes every rule as it is added, one line each. Build hashes it; see Rules.
	ruleText strings.Builder

	l *slog.Logger
}

func NewRulesBuilder(l *slog.Logger) *RulesBuilder {
	return &RulesBuilder{l: l}
}

// AddRule adds a rule for incoming or outgoing traffic, on proto or on every protocol when proto is ProtoAny.
// The rule is parsed now, so a bad rule is reported when it's added rather than when the Tables are built.
func (b *RulesBuilder) AddRule(incoming bool, proto uint8, startPort int32, endPort int32, groups []string, host string, cidr, localCidr, caName string, caSha string) error {
	// ICMPv6 rules are ICMP rules, and a packet of either protocol is checked against both
	if proto == iputil.IPProtocolICMPv6 {
		proto = iputil.IPProtocolICMP
	}

	if proto == iputil.IPProtocolICMP {
		//ICMP traffic doesn't have ports, so we always coerce to "any", even if a value is provided
		if startPort != PortAny {
			b.l.Warn("ignoring port specification for ICMP firewall rule", "startPort", startPort)
		}
		startPort = PortAny
		endPort = PortAny
	}

	r, err := parseRule(proto, startPort, endPort, groups, host, cidr, localCidr, caName, caSha)
	if err != nil {
		return err
	}

	if incoming {
		b.in = append(b.in, r)
	} else {
		b.out = append(b.out, r)
	}

	// The rule hashes are of these lines, changing them changes every hash
	fmt.Fprintf(&b.ruleText,
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

	text := []byte(b.ruleText.String())
	sha := sha256.Sum256(text)
	h := fnv.New32a()
	h.Write(text)

	return Rules{
		In:      buildTable(b.in, defaultLocal),
		Out:     buildTable(b.out, defaultLocal),
		Hash:    hex.EncodeToString(sha[:]),
		HashFNV: h.Sum32(),
	}
}

func parseRule(proto uint8, startPort, endPort int32, groups []string, host, cidr, localCidr, caName, caSha string) (rule, error) {
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
	// A port rule on a protocol without ports could never match. ICMP rules were coerced to `any` by AddRule,
	// and a proto `any` rule with a port applies to the protocols that have them.
	if startPort > PortAny && proto != ProtoAny && !iputil.HasPorts(proto) {
		return rule{}, fmt.Errorf("protocol %d has no ports, port must be any or fragment", proto)
	}

	r := rule{
		proto:     proto,
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

// buildTable turns one direction's rules into a Table. Rules without a local cidr allow defaultLocal,
// or any local address when defaultLocal is nil.
func buildTable(rules []rule, defaultLocal []netip.Prefix) *Table {
	t := &Table{rules: make([]rule, len(rules))}
	var hasOwn [256]bool
	for id, r := range rules {
		t.rules[id] = r.withDefaultLocal(defaultLocal)
		if r.proto != ProtoAny {
			hasOwn[r.proto] = true
		}
	}

	// A protocol with rules of its own gets an index of those rules plus the proto `any` rules, so a packet
	// checks a single index. The other protocols share an index of the proto `any` rules, one for protocols with
	// ports and one for protocols without.
	anyPorts := newProtoIndex(true, t.rules, ProtoAny)
	anyNoPorts := newProtoIndex(false, t.rules, ProtoAny)
	for proto := range t.protos {
		switch {
		case hasOwn[proto]:
			t.protos[proto] = newProtoIndex(iputil.HasPorts(uint8(proto)), t.rules, uint8(proto))
		case iputil.HasPorts(uint8(proto)):
			t.protos[proto] = anyPorts
		default:
			t.protos[proto] = anyNoPorts
		}
	}

	// ICMPv6 rules are ICMP rules, see AddRule, so ICMPv6 packets are checked against the ICMP index
	t.protos[iputil.IPProtocolICMPv6] = t.protos[iputil.IPProtocolICMP]

	return t
}

// newProtoIndex builds an index of the proto `any` rules and proto's own rules, for a protocol with or without
// ports, or returns nil when there are none. With ProtoAny, it indexes only the proto `any` rules.
func newProtoIndex(hasPorts bool, rules []rule, proto uint8) *protoIndex {
	var pi *protoIndex
	for id := range rules {
		r := &rules[id]
		if r.proto != ProtoAny && r.proto != proto {
			continue
		}

		if pi == nil {
			pi = &protoIndex{hasPorts: hasPorts, fragment: newRuleSet(len(rules))}
			if hasPorts {
				pi.byPort = newRuleSets(math.MaxUint16+1, len(rules))
			} else {
				pi.packet = newRuleSet(len(rules))
			}
		}
		pi.add(r, id)
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
		// A proto `any` rule with a port is indexed for the protocols that have ports, parseRule rejects a port on
		// a protocol without them.
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
