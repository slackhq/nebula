package nebula

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	c "github.com/slackhq/nebula/config"
)

func getAllowList(c *c.Config, k string, allowInterfaces bool) (*AllowList, error) {
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
			nameRules, err = getAllowListInterfaces(k, rawValue)
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

func configLogger(c *c.Config) error {
	// set up our logging level
	logLevel, err := logrus.ParseLevel(strings.ToLower(c.GetString("logging.level", "info")))
	if err != nil {
		return fmt.Errorf("%s; possible levels: %s", err, logrus.AllLevels)
	}
	l.SetLevel(logLevel)

	disableTimestamp := c.GetBool("logging.disable_timestamp", false)
	timestampFormat := c.GetString("logging.timestamp_format", "")
	fullTimestamp := timestampFormat != ""
	if timestampFormat == "" {
		timestampFormat = time.RFC3339
	}

	logFormat := strings.ToLower(c.GetString("logging.format", "text"))
	switch logFormat {
	case "text":
		l.Formatter = &logrus.TextFormatter{
			TimestampFormat:  timestampFormat,
			FullTimestamp:    fullTimestamp,
			DisableTimestamp: disableTimestamp,
		}
	case "json":
		l.Formatter = &logrus.JSONFormatter{
			TimestampFormat:  timestampFormat,
			DisableTimestamp: disableTimestamp,
		}
	default:
		return fmt.Errorf("unknown log format `%s`. possible formats: %s", logFormat, []string{"text", "json"})
	}

	return nil
}
