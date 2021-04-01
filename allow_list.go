package nebula

import (
	"fmt"
	"net"
	"regexp"
)

type AllowList struct {
	// The values of this cidrTree are `bool`, signifying allow/deny
	cidrTree *CIDR6Tree

	// To avoid ambiguity, all rules must be true, or all rules must be false.
	nameRules []AllowListNameRule
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

func (al *AllowList) AllowIpV4(ip uint32) bool {
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
