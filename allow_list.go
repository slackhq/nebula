package nebula

import (
	"fmt"
	"net"
	"regexp"

	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
)

type AllowList struct {
	// The values of this cidrTree are `bool`, signifying allow/deny
	cidrTree *cidr.Tree6[bool]
}

type RemoteAllowList struct {
	AllowList *AllowList

	// Inside Range Specific, keys of this tree are inside CIDRs and values
	// are *AllowList
	insideAllowLists *cidr.Tree6[*AllowList]
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
	handleKey := func(key string, value interface{}) (bool, error) {
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
func newAllowListFromConfig(c *config.C, k string, handleKey func(key string, value interface{}) (bool, error)) (*AllowList, error) {
	r := c.Get(k).UnwrapOrDefault()

	if r == nil {
		return nil, nil
	}

	return newAllowList(k, r, handleKey)
}

// If the handleKey func returns true, the rest of the parsing is skipped
// for this key. This allows parsing of special values like `interfaces`.
func newAllowList(k string, raw interface{}, handleKey func(key string, value interface{}) (bool, error)) (*AllowList, error) {
	rawMap, ok := raw.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("config `%s` has invalid type: %T", k, raw)
	}

	tree := cidr.NewTree6[bool]()

	// Keep track of the rules we have added for both ipv4 and ipv6
	type allowListRules struct {
		firstValue     bool
		allValuesMatch bool
		defaultSet     bool
		allValues      bool
	}

	rules4 := allowListRules{firstValue: true, allValuesMatch: true, defaultSet: false}
	rules6 := allowListRules{firstValue: true, allValuesMatch: true, defaultSet: false}

	for rawKey, rawValue := range rawMap {
		rawCIDR, ok := rawKey.(string)
		if !ok {
			return nil, fmt.Errorf("config `%s` has invalid key (type %T): %v", k, rawKey, rawKey)
		}

		if handleKey != nil {
			handled, err := handleKey(rawCIDR, rawValue)
			if err != nil {
				return nil, err
			}
			if handled {
				continue
			}
		}

		value, ok := rawValue.(bool)
		if !ok {
			return nil, fmt.Errorf("config `%s` has invalid value (type %T): %v", k, rawValue, rawValue)
		}

		_, ipNet, err := net.ParseCIDR(rawCIDR)
		if err != nil {
			return nil, fmt.Errorf("config `%s` has invalid CIDR: %s", k, rawCIDR)
		}

		// TODO: should we error on duplicate CIDRs in the config?
		tree.AddCIDR(ipNet, value)

		maskBits, maskSize := ipNet.Mask.Size()

		var rules *allowListRules
		if maskSize == 32 {
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
			_, zeroCIDR, _ := net.ParseCIDR("0.0.0.0/0")
			tree.AddCIDR(zeroCIDR, !rules4.allValues)
		} else {
			return nil, fmt.Errorf("config `%s` contains both true and false rules, but no default set for 0.0.0.0/0", k)
		}
	}

	if !rules6.defaultSet {
		if rules6.allValuesMatch {
			_, zeroCIDR, _ := net.ParseCIDR("::/0")
			tree.AddCIDR(zeroCIDR, !rules6.allValues)
		} else {
			return nil, fmt.Errorf("config `%s` contains both true and false rules, but no default set for ::/0", k)
		}
	}

	return &AllowList{cidrTree: tree}, nil
}

func getAllowListInterfaces(k string, v interface{}) ([]AllowListNameRule, error) {
	var nameRules []AllowListNameRule

	rawRules, ok := v.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("config `%s.interfaces` is invalid (type %T): %v", k, v, v)
	}

	firstEntry := true
	var allValues bool
	for rawName, rawAllow := range rawRules {
		name, ok := rawName.(string)
		if !ok {
			return nil, fmt.Errorf("config `%s.interfaces` has invalid key (type %T): %v", k, rawName, rawName)
		}
		allow, ok := rawAllow.(bool)
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

func getRemoteAllowRanges(c *config.C, k string) (*cidr.Tree6[*AllowList], error) {
	value := c.Get(k).UnwrapOrDefault()

	if value == nil {
		return nil, nil
	}

	remoteAllowRanges := cidr.NewTree6[*AllowList]()

	rawMap, ok := value.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("config `%s` has invalid type: %T", k, value)
	}
	for rawKey, rawValue := range rawMap {
		rawCIDR, ok := rawKey.(string)
		if !ok {
			return nil, fmt.Errorf("config `%s` has invalid key (type %T): %v", k, rawKey, rawKey)
		}

		allowList, err := newAllowList(fmt.Sprintf("%s.%s", k, rawCIDR), rawValue, nil)
		if err != nil {
			return nil, err
		}

		_, ipNet, err := net.ParseCIDR(rawCIDR)
		if err != nil {
			return nil, fmt.Errorf("config `%s` has invalid CIDR: %s", k, rawCIDR)
		}

		remoteAllowRanges.AddCIDR(ipNet, allowList)
	}

	return remoteAllowRanges, nil
}

func (al *AllowList) Allow(ip net.IP) bool {
	if al == nil {
		return true
	}

	_, result := al.cidrTree.MostSpecificContains(ip)
	return result
}

func (al *AllowList) AllowIpV4(ip iputil.VpnIp) bool {
	if al == nil {
		return true
	}

	_, result := al.cidrTree.MostSpecificContainsIpV4(ip)
	return result
}

func (al *AllowList) AllowIpV6(hi, lo uint64) bool {
	if al == nil {
		return true
	}

	_, result := al.cidrTree.MostSpecificContainsIpV6(hi, lo)
	return result
}

func (al *LocalAllowList) Allow(ip net.IP) bool {
	if al == nil {
		return true
	}
	return al.AllowList.Allow(ip)
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

func (al *RemoteAllowList) AllowUnknownVpnIp(ip net.IP) bool {
	if al == nil {
		return true
	}
	return al.AllowList.Allow(ip)
}

func (al *RemoteAllowList) Allow(vpnIp iputil.VpnIp, ip net.IP) bool {
	if !al.getInsideAllowList(vpnIp).Allow(ip) {
		return false
	}
	return al.AllowList.Allow(ip)
}

func (al *RemoteAllowList) AllowIpV4(vpnIp iputil.VpnIp, ip iputil.VpnIp) bool {
	if al == nil {
		return true
	}
	if !al.getInsideAllowList(vpnIp).AllowIpV4(ip) {
		return false
	}
	return al.AllowList.AllowIpV4(ip)
}

func (al *RemoteAllowList) AllowIpV6(vpnIp iputil.VpnIp, hi, lo uint64) bool {
	if al == nil {
		return true
	}
	if !al.getInsideAllowList(vpnIp).AllowIpV6(hi, lo) {
		return false
	}
	return al.AllowList.AllowIpV6(hi, lo)
}

func (al *RemoteAllowList) getInsideAllowList(vpnIp iputil.VpnIp) *AllowList {
	if al.insideAllowLists != nil {
		ok, inside := al.insideAllowLists.MostSpecificContainsIpV4(vpnIp)
		if ok {
			return inside
		}
	}
	return nil
}
