package nebula

import (
	"fmt"
	"net/netip"
	"regexp"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
)

type AllowList struct {
	// The values of this cidrTree are `bool`, signifying allow/deny
	cidrTree *bart.Table[bool]
}

type RemoteAllowList struct {
	AllowList *AllowList

	// Inside Range Specific, keys of this tree are inside CIDRs and values
	// are *AllowList
	insideAllowLists *bart.Table[*AllowList]
}

type LocalAllowList struct {
	AllowList *AllowList

	// To avoid ambiguity, all rules must be true, or all rules must be false.
	nameRules []AllowListNameRule
}

type AllowListNameRule struct {
	Name  *regexp.Regexp
	Allow bool
}

func NewLocalAllowListFromConfig(c *config.C, k string) (*LocalAllowList, error) {
	var nameRules []AllowListNameRule
	handleKey := func(key string, value any) (bool, error) {
		if key == "interfaces" {
			var err error
			nameRules, err = getAllowListInterfaces(k, value)
			if err != nil {
				return false, err
			}

			return true, nil
		}
		return false, nil
	}

	al, err := newAllowListFromConfig(c, k, handleKey)
	if err != nil {
		return nil, err
	}
	return &LocalAllowList{AllowList: al, nameRules: nameRules}, nil
}

func NewRemoteAllowListFromConfig(c *config.C, k, rangesKey string) (*RemoteAllowList, error) {
	al, err := newAllowListFromConfig(c, k, nil)
	if err != nil {
		return nil, err
	}
	remoteAllowRanges, err := getRemoteAllowRanges(c, rangesKey)
	if err != nil {
		return nil, err
	}
	return &RemoteAllowList{AllowList: al, insideAllowLists: remoteAllowRanges}, nil
}

// If the handleKey func returns true, the rest of the parsing is skipped
// for this key. This allows parsing of special values like `interfaces`.
func newAllowListFromConfig(c *config.C, k string, handleKey func(key string, value any) (bool, error)) (*AllowList, error) {
	r := c.Get(k)
	if r == nil {
		return nil, nil
	}

	return newAllowList(k, r, handleKey)
}

// If the handleKey func returns true, the rest of the parsing is skipped
// for this key. This allows parsing of special values like `interfaces`.
func newAllowList(k string, raw any, handleKey func(key string, value any) (bool, error)) (*AllowList, error) {
	rawMap, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config `%s` has invalid type: %T", k, raw)
	}

	tree := new(bart.Table[bool])

	// Keep track of the rules we have added for both ipv4 and ipv6
	type allowListRules struct {
		firstValue     bool
		allValuesMatch bool
		defaultSet     bool
		allValues      bool
	}

	rules4 := allowListRules{firstValue: true, allValuesMatch: true, defaultSet: false}
	rules6 := allowListRules{firstValue: true, allValuesMatch: true, defaultSet: false}

	for rawCIDR, rawValue := range rawMap {
		if handleKey != nil {
			handled, err := handleKey(rawCIDR, rawValue)
			if err != nil {
				return nil, err
			}
			if handled {
				continue
			}
		}

		value, ok := config.AsBool(rawValue)
		if !ok {
			return nil, fmt.Errorf("config `%s` has invalid value (type %T): %v", k, rawValue, rawValue)
		}

		ipNet, err := netip.ParsePrefix(rawCIDR)
		if err != nil {
			return nil, fmt.Errorf("config `%s` has invalid CIDR: %s. %w", k, rawCIDR, err)
		}

		ipNet = netip.PrefixFrom(ipNet.Addr().Unmap(), ipNet.Bits())

		tree.Insert(ipNet, value)

		maskBits := ipNet.Bits()

		var rules *allowListRules
		if ipNet.Addr().Is4() {
			rules = &rules4
		} else {
			rules = &rules6
		}

		if rules.firstValue {
			rules.allValues = value
			rules.firstValue = false
		} else {
			if value != rules.allValues {
				rules.allValuesMatch = false
			}
		}

		// Check if this is 0.0.0.0/0 or ::/0
		if maskBits == 0 {
			rules.defaultSet = true
		}
	}

	if !rules4.defaultSet {
		if rules4.allValuesMatch {
			tree.Insert(netip.PrefixFrom(netip.IPv4Unspecified(), 0), !rules4.allValues)
		} else {
			return nil, fmt.Errorf("config `%s` contains both true and false rules, but no default set for 0.0.0.0/0", k)
		}
	}

	if !rules6.defaultSet {
		if rules6.allValuesMatch {
			tree.Insert(netip.PrefixFrom(netip.IPv6Unspecified(), 0), !rules6.allValues)
		} else {
			return nil, fmt.Errorf("config `%s` contains both true and false rules, but no default set for ::/0", k)
		}
	}

	return &AllowList{cidrTree: tree}, nil
}

func getAllowListInterfaces(k string, v any) ([]AllowListNameRule, error) {
	var nameRules []AllowListNameRule

	rawRules, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config `%s.interfaces` is invalid (type %T): %v", k, v, v)
	}

	firstEntry := true
	var allValues bool
	for name, rawAllow := range rawRules {
		allow, ok := config.AsBool(rawAllow)
		if !ok {
			return nil, fmt.Errorf("config `%s.interfaces` has invalid value (type %T): %v", k, rawAllow, rawAllow)
		}

		nameRE, err := regexp.Compile("^" + name + "$")
		if err != nil {
			return nil, fmt.Errorf("config `%s.interfaces` has invalid key: %s: %v", k, name, err)
		}

		nameRules = append(nameRules, AllowListNameRule{
			Name:  nameRE,
			Allow: allow,
		})

		if firstEntry {
			allValues = allow
			firstEntry = false
		} else {
			if allow != allValues {
				return nil, fmt.Errorf("config `%s.interfaces` values must all be the same true/false value", k)
			}
		}
	}

	return nameRules, nil
}

func getRemoteAllowRanges(c *config.C, k string) (*bart.Table[*AllowList], error) {
	value := c.Get(k)
	if value == nil {
		return nil, nil
	}

	remoteAllowRanges := new(bart.Table[*AllowList])

	rawMap, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config `%s` has invalid type: %T", k, value)
	}
	for rawCIDR, rawValue := range rawMap {
		allowList, err := newAllowList(fmt.Sprintf("%s.%s", k, rawCIDR), rawValue, nil)
		if err != nil {
			return nil, err
		}

		ipNet, err := netip.ParsePrefix(rawCIDR)
		if err != nil {
			return nil, fmt.Errorf("config `%s` has invalid CIDR: %s. %w", k, rawCIDR, err)
		}

		remoteAllowRanges.Insert(netip.PrefixFrom(ipNet.Addr().Unmap(), ipNet.Bits()), allowList)
	}

	return remoteAllowRanges, nil
}

func (al *AllowList) Allow(addr netip.Addr) bool {
	if al == nil {
		return true
	}

	result, _ := al.cidrTree.Lookup(addr)
	return result
}

func (al *LocalAllowList) Allow(udpAddr netip.Addr) bool {
	if al == nil {
		return true
	}
	return al.AllowList.Allow(udpAddr)
}

func (al *LocalAllowList) AllowName(name string) bool {
	if al == nil || len(al.nameRules) == 0 {
		return true
	}

	for _, rule := range al.nameRules {
		if rule.Name.MatchString(name) {
			return rule.Allow
		}
	}

	// If no rules match, return the default, which is the inverse of the rules
	return !al.nameRules[0].Allow
}

func (al *RemoteAllowList) AllowUnknownVpnAddr(vpnAddr netip.Addr) bool {
	if al == nil {
		return true
	}
	return al.AllowList.Allow(vpnAddr)
}

func (al *RemoteAllowList) Allow(vpnAddr netip.Addr, udpAddr netip.Addr) bool {
	if !al.getInsideAllowList(vpnAddr).Allow(udpAddr) {
		return false
	}
	return al.AllowList.Allow(udpAddr)
}

func (al *RemoteAllowList) AllowAll(vpnAddrs []netip.Addr, udpAddr netip.Addr) bool {
	if !al.AllowList.Allow(udpAddr) {
		return false
	}

	for _, vpnAddr := range vpnAddrs {
		if !al.getInsideAllowList(vpnAddr).Allow(udpAddr) {
			return false
		}
	}

	return true
}

func (al *RemoteAllowList) getInsideAllowList(vpnAddr netip.Addr) *AllowList {
	if al.insideAllowLists != nil {
		inside, ok := al.insideAllowLists.Lookup(vpnAddr)
		if ok {
			return inside
		}
	}
	return nil
}
