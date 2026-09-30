package firewall

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
)

// ruleAdder takes firewall rules, it lets tests see what addRulesFromConfig adds
type ruleAdder interface {
	AddRule(incoming bool, proto uint8, startPort int32, endPort int32, groups []string, host string, cidr, localCidr string, caName string, caSha string) error
}

// RulesFromConfig reads the inbound and outbound firewall rules from c and builds them, see RulesBuilder.Build
func RulesFromConfig(l *slog.Logger, c *config.C, vpnNetworks, unsafeNetworks []netip.Prefix) (Rules, error) {
	b := NewRulesBuilder(l)
	b.defaultLocalCIDRAny = c.GetBool("firewall.default_local_cidr_any", false)

	if err := addRulesFromConfig(l, false, c, b); err != nil {
		return Rules{}, err
	}
	if err := addRulesFromConfig(l, true, c, b); err != nil {
		return Rules{}, err
	}

	return b.Build(vpnNetworks, unsafeNetworks), nil
}

func addRulesFromConfig(l *slog.Logger, inbound bool, c *config.C, ra ruleAdder) error {
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
		r, err := yamlToConfigRule(l, t, table, i)
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

		var proto uint8
		switch r.Proto {
		case "any":
			proto = ProtoAny
		case "tcp":
			proto = iputil.IPProtocolTCP
		case "udp":
			proto = iputil.IPProtocolUDP
		case "udplite":
			proto = iputil.IPProtocolUDPLite
		case "dccp":
			proto = iputil.IPProtocolDCCP
		case "sctp":
			proto = iputil.IPProtocolSCTP
		case "icmp":
			proto = iputil.IPProtocolICMP
		default:
			// Any other protocol by number. 0 is reserved for `any`.
			n, perr := strconv.ParseUint(r.Proto, 10, 8)
			if perr != nil || n == 0 {
				return fmt.Errorf("%s rule #%v; proto was not understood; `%s`", table, i, r.Proto)
			}
			proto = uint8(n)
		}

		var startPort, endPort int32
		if proto == iputil.IPProtocolICMP || proto == iputil.IPProtocolICMPv6 {
			startPort = PortAny
			endPort = PortAny
			if sPort != "" {
				l.Warn("ignoring port specification for ICMP firewall rule", "port", sPort)
			}
		} else {
			startPort, endPort, err = parsePort(sPort)
		}
		if err != nil {
			return fmt.Errorf("%s rule #%v; %s %s", table, i, errPort, err)
		}

		if warning := r.sanity(); warning != nil {
			l.Warn("firewall rule sanity check",
				"table", table,
				"rule", i,
				"warning", warning,
			)
		}

		err = ra.AddRule(inbound, proto, startPort, endPort, r.Groups, r.Host, r.Cidr, r.LocalCidr, r.CAName, r.CASha)
		if err != nil {
			return fmt.Errorf("%s rule #%v; %s", table, i, err)
		}
	}

	return nil
}

type configRule struct {
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

func yamlToConfigRule(l *slog.Logger, p any, table string, i int) (configRule, error) {
	r := configRule{}

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

		l.Warn("group was an array with a single value, converting to simple value",
			"table", table,
			"rule", i,
		)
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
func (r *configRule) sanity() error {
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

	if r.Code != "" {
		return fmt.Errorf("code specified as [%s]. Support for 'code' will be dropped in a future release, as it has never been functional", r.Code)
	}

	//todo alert on cidr-any

	return nil
}

func parsePort(s string) (int32, int32, error) {
	const notAPort int32 = -2
	if s == "any" {
		return PortAny, PortAny, nil
	}
	if s == "fragment" {
		return PortFragment, PortFragment, nil
	}
	if !strings.Contains(s, `-`) {
		rPort, err := parsePortValue("", s)
		if err != nil {
			return notAPort, notAPort, err
		}
		return rPort, rPort, nil
	}

	sPorts := strings.SplitN(s, `-`, 2)
	for i := range sPorts {
		sPorts[i] = strings.Trim(sPorts[i], " ")
	}
	if len(sPorts) != 2 || sPorts[0] == "" || sPorts[1] == "" {
		return notAPort, notAPort, fmt.Errorf("appears to be a range but could not be parsed; `%s`", s)
	}

	startPort, err := parsePortValue("beginning range ", sPorts[0])
	if err != nil {
		return notAPort, notAPort, err
	}

	endPort, err := parsePortValue("ending range ", sPorts[1])
	if err != nil {
		return notAPort, notAPort, err
	}

	if startPort == PortAny {
		endPort = PortAny
	}

	return startPort, endPort, nil
}

// parsePortValue accepts a base-10 decimal in [0, 65535] and returns it
// widened to int32. Using strconv.ParseUint with bitSize 16 rejects
// negative input, out-of-range input (>65535), and any non-decimal byte
// by construction, so the int32 widening that follows is provably safe
// and cannot collide with PortAny (0) or PortFragment
// (-1) via integer truncation.
//
// prefix is prepended to both error messages so callers can disambiguate
// the single-port path (prefix="") from the range bounds (prefix="beginning
// range " / "ending range "), preserving the historical error strings.
func parsePortValue(prefix, s string) (int32, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err == nil {
		return int32(n), nil
	}
	if errors.Is(err, strconv.ErrRange) {
		return 0, fmt.Errorf("%sout of range [0,65535]; `%s`", prefix, s)
	}
	return 0, fmt.Errorf("%swas not a number; `%s`", prefix, s)
}
