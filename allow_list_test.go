package nebula

import (
	"net"
	"regexp"
	"testing"

	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/assert"
)

func TestNewAllowListFromConfig(t *testing.T) {
	l := util.NewTestLogger()
	c := config.NewC(l)
	c.Settings["allowlist"] = map[interface{}]interface{}{
		"192.168.0.0": true,
	}
	r, err := NewAllowListFromConfig(c, "allowlist", false)
	assert.EqualError(t, err, "config `allowlist` has invalid CIDR: 192.168.0.0")
	assert.Nil(t, r)

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"192.168.0.0/16": "abc",
	}
	r, err = NewAllowListFromConfig(c, "allowlist", false)
	assert.EqualError(t, err, "config `allowlist` has invalid value (type string): abc")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"192.168.0.0/16": true,
		"10.0.0.0/8":     false,
	}
	r, err = NewAllowListFromConfig(c, "allowlist", false)
	assert.EqualError(t, err, "config `allowlist` contains both true and false rules, but no default set for 0.0.0.0/0")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"0.0.0.0/0":      true,
		"10.0.0.0/8":     false,
		"10.42.42.0/24":  true,
		"fd00::/8":       true,
		"fd00:fd00::/16": false,
	}
	r, err = NewAllowListFromConfig(c, "allowlist", false)
	assert.EqualError(t, err, "config `allowlist` contains both true and false rules, but no default set for ::/0")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"0.0.0.0/0":     true,
		"10.0.0.0/8":    false,
		"10.42.42.0/24": true,
	}
	r, err = NewAllowListFromConfig(c, "allowlist", false)
	if assert.NoError(t, err) {
		assert.NotNil(t, r)
	}

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"0.0.0.0/0":      true,
		"10.0.0.0/8":     false,
		"10.42.42.0/24":  true,
		"::/0":           false,
		"fd00::/8":       true,
		"fd00:fd00::/16": false,
	}
	r, err = NewAllowListFromConfig(c, "allowlist", false)
	if assert.NoError(t, err) {
		assert.NotNil(t, r)
	}

	// Test interface names

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"interfaces": map[interface{}]interface{}{
			`docker.*`: false,
		},
	}
	r, err = NewAllowListFromConfig(c, "allowlist", false)
	assert.EqualError(t, err, "config `allowlist` does not support `interfaces`")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"interfaces": map[interface{}]interface{}{
			`docker.*`: "foo",
		},
	}
	r, err = NewAllowListFromConfig(c, "allowlist", true)
	assert.EqualError(t, err, "config `allowlist.interfaces` has invalid value (type string): foo")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"interfaces": map[interface{}]interface{}{
			`docker.*`: false,
			`eth.*`:    true,
		},
	}
	r, err = NewAllowListFromConfig(c, "allowlist", true)
	assert.EqualError(t, err, "config `allowlist.interfaces` values must all be the same true/false value")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"interfaces": map[interface{}]interface{}{
			`docker.*`: false,
		},
	}
	r, err = NewAllowListFromConfig(c, "allowlist", true)
	if assert.NoError(t, err) {
		assert.NotNil(t, r)
	}
}

func TestAllowList_Allow(t *testing.T) {
	assert.Equal(t, true, ((*AllowList)(nil)).Allow(net.ParseIP("1.1.1.1")))

	tree := cidr.NewTree6()
	tree.AddCIDR(cidr.Parse("0.0.0.0/0"), true)
	tree.AddCIDR(cidr.Parse("10.0.0.0/8"), false)
	tree.AddCIDR(cidr.Parse("10.42.42.42/32"), true)
	tree.AddCIDR(cidr.Parse("10.42.0.0/16"), true)
	tree.AddCIDR(cidr.Parse("10.42.42.0/24"), true)
	tree.AddCIDR(cidr.Parse("10.42.42.0/24"), false)
	tree.AddCIDR(cidr.Parse("::1/128"), true)
	tree.AddCIDR(cidr.Parse("::2/128"), false)
	al := &AllowList{cidrTree: tree}

	assert.Equal(t, true, al.Allow(net.ParseIP("1.1.1.1")))
	assert.Equal(t, false, al.Allow(net.ParseIP("10.0.0.4")))
	assert.Equal(t, true, al.Allow(net.ParseIP("10.42.42.42")))
	assert.Equal(t, false, al.Allow(net.ParseIP("10.42.42.41")))
	assert.Equal(t, true, al.Allow(net.ParseIP("10.42.0.1")))
	assert.Equal(t, true, al.Allow(net.ParseIP("::1")))
	assert.Equal(t, false, al.Allow(net.ParseIP("::2")))
}

func TestAllowList_AllowName(t *testing.T) {
	assert.Equal(t, true, ((*AllowList)(nil)).AllowName("docker0"))

	rules := []AllowListNameRule{
		{Name: regexp.MustCompile("^docker.*$"), Allow: false},
		{Name: regexp.MustCompile("^tun.*$"), Allow: false},
	}
	al := &AllowList{nameRules: rules}

	assert.Equal(t, false, al.AllowName("docker0"))
	assert.Equal(t, false, al.AllowName("tun0"))
	assert.Equal(t, true, al.AllowName("eth0"))

	rules = []AllowListNameRule{
		{Name: regexp.MustCompile("^eth.*$"), Allow: true},
		{Name: regexp.MustCompile("^ens.*$"), Allow: true},
	}
	al = &AllowList{nameRules: rules}

	assert.Equal(t, false, al.AllowName("docker0"))
	assert.Equal(t, true, al.AllowName("eth0"))
	assert.Equal(t, true, al.AllowName("ens5"))
}
