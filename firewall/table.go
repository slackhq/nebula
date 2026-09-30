package firewall

import (
	"net/netip"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/iputil"
)

// Rules are the Tables built for each direction, with hashes of the rules they were built from
type Rules struct {
	In, Out *Table

	// Hash is a sha256 of the rules, HashFNV is an FNV-1a of them for use as a metric value.
	// Rule sets with the same rules have the same hashes.
	Hash    string
	HashFNV uint32
}

// Table holds the rules for one direction, the evaluation order is:
// Proto AND port AND (CA SHA or CA name) AND local CIDR AND (group OR groups OR name OR remote CIDR)
// A Table doesn't change once built, see RulesBuilder.
type Table struct {
	// protos holds the rules for each IP protocol number, so a packet is only checked against one set of rules.
	// A protocol with rules of its own also holds a copy of every proto `any` rule, the rest share the proto `any`
	// rules, which are at protos[ProtoAny]. nil when a protocol has no rules at all.
	// ICMP and ICMPv6 share one set of rules.
	protos [256]portRules
}

// Even though ports are uint16, int32 maps are faster for lookup
// Plus we can use `-1` for fragment rules
type portRules map[int32]*caRules

// caRules and the types below it only make their maps and tables once a rule needs them, a range of ports
// gets a copy for every port so empty ones add up
type caRules struct {
	Any     *remoteRules
	CANames map[string]*remoteRules
	CAShas  map[string]*remoteRules
}

type remoteRules struct {
	// Any makes Hosts, Groups, and CIDR irrelevant
	Any    *localRules
	Hosts  map[string]*localRules
	Groups []*groupsRule
	CIDR   *bart.Table[*localRules]
}

type groupsRule struct {
	Groups    []string
	LocalCIDR *localRules
}

type localRules struct {
	Any bool
	// LocalCIDR is always set when Any isn't
	LocalCIDR *bart.Lite
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
	return t.protos[p.Protocol].match(p, incoming, c, caPool)
}

func (pr portRules) match(p *Packet, incoming bool, c *cert.CachedCertificate, caPool *cert.CAPool) bool {
	// We don't have any allowed ports, bail
	if pr == nil {
		return false
	}

	// ICMP has no ports, only the port `any` rules apply, including the ones copied in from proto `any` rules
	if p.Protocol == iputil.IPProtocolICMP || p.Protocol == iputil.IPProtocolICMPv6 {
		// port numbers are re-used for connection tracking of ICMP,
		// but we don't want to actually filter on them.
		return pr[PortAny].match(p, c, caPool)
	}

	var port int32

	if p.Fragment {
		port = PortFragment
	} else if incoming {
		port = int32(p.LocalPort)
	} else {
		port = int32(p.RemotePort)
	}

	// Packets without ports (gre, esp, etc) have port 0, which is PortAny, don't check those rules twice
	if port != PortAny && pr[port].match(p, c, caPool) {
		return true
	}

	return pr[PortAny].match(p, c, caPool)
}

func (cr *caRules) match(p *Packet, c *cert.CachedCertificate, caPool *cert.CAPool) bool {
	if cr == nil {
		return false
	}

	if cr.Any.match(p, c) {
		return true
	}

	if t, ok := cr.CAShas[c.Certificate.Issuer()]; ok {
		if t.match(p, c) {
			return true
		}
	}

	s, err := caPool.GetCAForCert(c.Certificate)
	if err != nil {
		return false
	}

	return cr.CANames[s.Certificate.Name()].match(p, c)
}

func (rr *remoteRules) match(p *Packet, c *cert.CachedCertificate) bool {
	if rr == nil {
		return false
	}

	// Shortcut path for if groups, hosts, or cidr contained an `any`
	if rr.Any.match(p, c) {
		return true
	}

	// Need any of group, host, or cidr to match
	for _, sg := range rr.Groups {
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

	if rr.Hosts != nil {
		if lr, ok := rr.Hosts[c.Certificate.Name()]; ok {
			if lr.match(p, c) {
				return true
			}
		}
	}

	if rr.CIDR != nil {
		for _, v := range rr.CIDR.Supernets(netip.PrefixFrom(p.RemoteAddr, p.RemoteAddr.BitLen())) {
			if v.match(p, c) {
				return true
			}
		}
	}

	return false
}

func (lr *localRules) match(p *Packet, c *cert.CachedCertificate) bool {
	if lr == nil {
		return false
	}

	if lr.Any {
		return true
	}

	return lr.LocalCIDR.Contains(p.LocalAddr)
}
