package nebula

import (
	"fmt"
	"regexp"
)

type AllowList struct {
	// The values of this cidrTree are `bool`, signifying allow/deny
	cidrTree *CIDRTree

	nameRules []AllowListNameRule
}

type AllowListNameRule struct {
	Name  *regexp.Regexp
	Allow bool
}

func (al *AllowList) Allow(ip uint32) bool {
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

func (al *AllowList) AllowNamed(name string, ip uint32) bool {
	if al == nil {
		return true
	}

	if len(al.nameRules) > 0 {
		var allowName bool
		defaultRule := !al.nameRules[0].Allow

		for _, rule := range al.nameRules {
			if rule.Name.MatchString(name) {
				if rule.Allow {
					allowName = true
					break
				} else {
					return false
				}
			}
			if !defaultRule && !allowName {
				return false
			}
		}
	}

	return al.Allow(ip)
}
