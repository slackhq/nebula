package firewall

import (
	"net/netip"

	"github.com/slackhq/nebula/cert"
)

// Rules are the Tables built for each direction, with hashes of the rules they were built from
type Rules struct {
	In, Out *Table

	// Hash is a sha256 of the rules, HashFNV is an FNV-1a of them for use as a metric value.
	// Rule sets with the same rules have the same hashes.
	Hash    string
	HashFNV uint32
}

// Table holds the rules for one direction. A packet is allowed when every clause of a single rule allows it:
// proto AND port AND (CA SHA or CA name) AND local CIDR AND (group OR groups OR name OR remote CIDR).
// A Table does not change once built; see RulesBuilder.
type Table struct {
	// rules holds every rule for the direction, in the order they were added. A rule's index in this slice is
	// its id in the ruleSets.
	rules []rule

	// protos holds the index for each IP protocol number, so a packet is checked against a single index.
	// A protocol with rules of its own has an index that also includes every proto `any` rule. The remaining
	// protocols share an index of only the proto `any` rules: one for protocols with ports and one for
	// protocols without; see hasPorts. An entry is nil when the protocol has no rules at all.
	// ICMP and ICMPv6 share one index.
	protos [256]*protoIndex
}

// protoIndex holds the rules that can apply to one protocol, in a set for each kind of packet.
type protoIndex struct {
	// hasPorts reports whether the protocol has ports; see iputil.HasPorts.
	hasPorts bool
	// byPort has a set for every port number of a protocol with ports. Port 0 is covered only by port `any`
	// rules, since a range starts at 1.
	byPort ruleSets
	// packet holds the rules for a packet of a protocol without ports: the port `any` rules.
	packet ruleSet
	// fragment holds the rules for a fragment of any protocol: the port `any` and port `fragment` rules.
	fragment ruleSet
}

// whichMatch returns the set of rules whose proto and port clauses allow p.
func (pi *protoIndex) whichMatch(p *Packet, incoming bool) ruleSet {
	switch {
	case p.Fragment:
		// The ports of a fragmented packet are in its first fragment, and this is a later one.
		return pi.fragment
	case !pi.hasPorts:
		// The port fields are zero, or for ICMP the identifier, which is only for connection tracking.
		return pi.packet
	case incoming:
		return pi.byPort.at(int(p.LocalPort))
	default:
		return pi.byPort.at(int(p.RemotePort))
	}
}

// rule is a parsed rule. A packet is allowed by the rule when its port, certificate, and address clauses all pass.
type rule struct {
	// proto is the IP protocol number the rule applies to, or ProtoAny for every protocol. ICMPv6 rules are kept
	// as ICMP. The protoIndex checks it, so match does not.
	proto uint8

	// startPort and endPort are the port clause. A startPort of PortAny covers every port, every packet of a
	// protocol without ports, and every fragment. PortFragment covers only fragments. A range covers the ports
	// in it, so it never applies to a protocol without ports.
	startPort, endPort int32

	// caSha and caName pass a certificate issued by either CA. When neither is set, any CA passes.
	caSha, caName string

	// remoteAny makes host, groups, and cidr irrelevant. Otherwise, the peer passes when any one of them matches.
	remoteAny bool
	host      string
	groups    []string
	cidr      netip.Prefix // Invalid when the rule has no cidr.

	// localAny allows any local address. Otherwise, local must contain the address. Neither is set for a rule
	// without a local cidr until the Table is built and the rule gets the default; see withDefaultLocal.
	localAny bool
	local    []netip.Prefix
}

// Match reports whether a rule for the direction p is going allows it
func (r *Rules) Match(p *Packet, incoming bool, c *cert.CachedCertificate, caPool *cert.CAPool) bool {
	t := r.Out
	if incoming {
		t = r.In
	}
	return t.Match(p, incoming, c, caPool)
}

// Match reports whether a rule allows p
func (t *Table) Match(p *Packet, incoming bool, c *cert.CachedCertificate, caPool *cert.CAPool) bool {
	proto := t.protos[p.Protocol]
	if proto == nil {
		// The protocol has no rules of its own, and there are no proto `any` rules.
		return false
	}

	// The index yields every rule whose proto and port clauses allow p.
	// The packet is allowed when the remaining clauses of any of those rules allow it as well.
	for id := range proto.whichMatch(p, incoming).all() {
		if t.rules[id].match(p, c, caPool) {
			return true
		}
	}

	return false
}

// match reports whether r allows p from the peer with certificate c. The port clause is not checked here; the
// protoIndex has already done so.
func (r *rule) match(p *Packet, c *cert.CachedCertificate, caPool *cert.CAPool) bool {
	return r.matchLocal(p.LocalAddr) && r.matchRemote(p.RemoteAddr, c) && r.matchCA(c, caPool)
}

// matchLocal reports whether r allows the local address addr.
func (r *rule) matchLocal(addr netip.Addr) bool {
	if r.localAny {
		return true
	}

	for _, prefix := range r.local {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

// matchRemote reports whether r allows the peer with certificate c, sending from addr. The cidr is checked with
// Prefix.Contains, so 0.0.0.0/0 allows any IPv4 address and ::/0 allows any IPv6 address; neither allows the
// other family.
func (r *rule) matchRemote(addr netip.Addr, c *cert.CachedCertificate) bool {
	if r.remoteAny {
		return true
	}

	if r.cidr.IsValid() && r.cidr.Contains(addr) {
		return true
	}

	if r.host != "" && r.host == c.Certificate.Name() {
		return true
	}

	// Every group must be present.
	if len(r.groups) == 0 {
		return false
	}
	for _, g := range r.groups {
		if _, ok := c.InvertedGroups[g]; !ok {
			return false
		}
	}

	return true
}

// matchCA reports whether c was issued by a CA that r allows.
func (r *rule) matchCA(c *cert.CachedCertificate, caPool *cert.CAPool) bool {
	if r.caSha == "" && r.caName == "" {
		return true
	}

	if r.caSha != "" && r.caSha == c.Certificate.Issuer() {
		return true
	}

	if r.caName != "" {
		s, err := caPool.GetCAForCert(c.Certificate)
		if err != nil {
			return false
		}
		return r.caName == s.Certificate.Name()
	}

	return false
}
