package nebula

import (
	"fmt"
	"net"
	"regexp"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
)

type AllowList struct {
	// The values of this cidrTree are `bool`, signifying allow/deny
	cidrTree *CIDR6Tree

	// To avoid ambiguity, all rules must be true, or all rules must be false.
	nameRules []AllowListNameRule
}

func NewAllowListFromConfig(c *config.C, k string, allowInterfaces bool) (*AllowList, error) {
	r := c.Get(k)
	if r == nil {
		return nil, nil
	}

	rawMap, ok := r.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("config `%s` has invalid type: %T", k, r)
	}

	tree := NewCIDR6Tree()
	var nameRules []AllowListNameRule

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

		// Special rule for interface names
		if rawCIDR == "interfaces" {
			if !allowInterfaces {
				return nil, fmt.Errorf("config `%s` does not support `interfaces`", k)
			}
			var err error
			nameRules, err = NewAllowListNameRuleFromConfig(c, k, rawValue)
			if err != nil {
				return nil, err
			}

			continue
		}

		value, ok := rawValue.(bool)
		if !ok {
			return nil, fmt.Errorf("config `%s` has invalid value (type %T): %v", k, rawValue, rawValue)
		}

		_, cidr, err := net.ParseCIDR(rawCIDR)
		if err != nil {
			return nil, fmt.Errorf("config `%s` has invalid CIDR: %s", k, rawCIDR)
		}

		// TODO: should we error on duplicate CIDRs in the config?
		tree.AddCIDR(cidr, value)

		maskBits, maskSize := cidr.Mask.Size()

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

	return &AllowList{cidrTree: tree, nameRules: nameRules}, nil
}

func NewAllowListNameRuleFromConfig(c *config.C, k string, v interface{}) ([]AllowListNameRule, error) {
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

type AllowListNameRule struct {
	Name  *regexp.Regexp
	Allow bool
}

func (al *AllowList) Allow(ip net.IP) bool {
	if al == nil {
		return true
	}

	result := al.cidrTree.MostSpecificContains(ip)
	switch v := result.(type) {
	case bool:
		return v
	default:
		panic(fmt.Errorf("invalid state, allowlist returned: %T %v", result, result))
	}
}

func (al *AllowList) AllowIpV4(ip iputil.VpnIp) bool {
	if al == nil {
		return true
	}

	result := al.cidrTree.MostSpecificContainsIpV4(ip)
	switch v := result.(type) {
	case bool:
		return v
	default:
		panic(fmt.Errorf("invalid state, allowlist returned: %T %v", result, result))
	}
}

func (al *AllowList) AllowIpV6(hi, lo uint64) bool {
	if al == nil {
		return true
	}

	result := al.cidrTree.MostSpecificContainsIpV6(hi, lo)
	switch v := result.(type) {
	case bool:
		return v
	default:
		panic(fmt.Errorf("invalid state, allowlist returned: %T %v", result, result))
	}
}

func (al *AllowList) AllowName(name string) bool {
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
