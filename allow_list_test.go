package nebula

import (
	"net/netip"
	"regexp"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAllowListFromConfig(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	c.Settings["allowlist"] = map[string]any{
		"192.168.0.0": true,
	}
	r, err := newAllowListFromConfig(c, "allowlist", nil)
	require.EqualError(t, err, "config `allowlist` has invalid CIDR: 192.168.0.0. netip.ParsePrefix(\"192.168.0.0\"): no '/'")
	assert.Nil(t, r)

	c.Settings["allowlist"] = map[string]any{
		"192.168.0.0/16": "abc",
	}
	r, err = newAllowListFromConfig(c, "allowlist", nil)
	require.EqualError(t, err, "config `allowlist` has invalid value (type string): abc")

	c.Settings["allowlist"] = map[string]any{
		"192.168.0.0/16": true,
		"10.0.0.0/8":     false,
	}
	r, err = newAllowListFromConfig(c, "allowlist", nil)
	require.EqualError(t, err, "config `allowlist` contains both true and false rules, but no default set for 0.0.0.0/0")

	c.Settings["allowlist"] = map[string]any{
		"0.0.0.0/0":      true,
		"10.0.0.0/8":     false,
		"10.42.42.0/24":  true,
		"fd00::/8":       true,
		"fd00:fd00::/16": false,
	}
	r, err = newAllowListFromConfig(c, "allowlist", nil)
	require.EqualError(t, err, "config `allowlist` contains both true and false rules, but no default set for ::/0")

	c.Settings["allowlist"] = map[string]any{
		"0.0.0.0/0":     true,
		"10.0.0.0/8":    false,
		"10.42.42.0/24": true,
	}
	r, err = newAllowListFromConfig(c, "allowlist", nil)
	if assert.NoError(t, err) {
		assert.NotNil(t, r)
	}

	c.Settings["allowlist"] = map[string]any{
		"0.0.0.0/0":      true,
		"10.0.0.0/8":     false,
		"10.42.42.0/24":  true,
		"::/0":           false,
		"fd00::/8":       true,
		"fd00:fd00::/16": false,
	}
	r, err = newAllowListFromConfig(c, "allowlist", nil)
	if assert.NoError(t, err) {
		assert.NotNil(t, r)
	}

	// Test interface names

	c.Settings["allowlist"] = map[string]any{
		"interfaces": map[string]any{
			`docker.*`: "foo",
		},
	}
	lr, err := NewLocalAllowListFromConfig(c, "allowlist")
	require.EqualError(t, err, "config `allowlist.interfaces` has invalid value (type string): foo")

	c.Settings["allowlist"] = map[string]any{
		"interfaces": map[string]any{
			`docker.*`: false,
			`eth.*`:    true,
		},
	}
	lr, err = NewLocalAllowListFromConfig(c, "allowlist")
	require.EqualError(t, err, "config `allowlist.interfaces` values must all be the same true/false value")

	c.Settings["allowlist"] = map[string]any{
		"interfaces": map[string]any{
			`docker.*`: false,
		},
	}
	lr, err = NewLocalAllowListFromConfig(c, "allowlist")
	if assert.NoError(t, err) {
		assert.NotNil(t, lr)
	}
}

func TestAllowList_Allow(t *testing.T) {
	assert.True(t, ((*AllowList)(nil)).Allow(netip.MustParseAddr("1.1.1.1")))

	tree := new(bart.Table[bool])
	tree.Insert(netip.MustParsePrefix("0.0.0.0/0"), true)
	tree.Insert(netip.MustParsePrefix("10.0.0.0/8"), false)
	tree.Insert(netip.MustParsePrefix("10.42.42.42/32"), true)
	tree.Insert(netip.MustParsePrefix("10.42.0.0/16"), true)
	tree.Insert(netip.MustParsePrefix("10.42.42.0/24"), true)
	tree.Insert(netip.MustParsePrefix("10.42.42.0/24"), false)
	tree.Insert(netip.MustParsePrefix("::1/128"), true)
	tree.Insert(netip.MustParsePrefix("::2/128"), false)
	al := &AllowList{cidrTree: tree}

	assert.True(t, al.Allow(netip.MustParseAddr("1.1.1.1")))
	assert.False(t, al.Allow(netip.MustParseAddr("10.0.0.4")))
	assert.True(t, al.Allow(netip.MustParseAddr("10.42.42.42")))
	assert.False(t, al.Allow(netip.MustParseAddr("10.42.42.41")))
	assert.True(t, al.Allow(netip.MustParseAddr("10.42.0.1")))
	assert.True(t, al.Allow(netip.MustParseAddr("::1")))
	assert.False(t, al.Allow(netip.MustParseAddr("::2")))
}

func TestLocalAllowList_AllowName(t *testing.T) {
	assert.True(t, ((*LocalAllowList)(nil)).AllowName("docker0"))

	rules := []AllowListNameRule{
		{Name: regexp.MustCompile("^docker.*$"), Allow: false},
		{Name: regexp.MustCompile("^tun.*$"), Allow: false},
	}
	al := &LocalAllowList{nameRules: rules}

	assert.False(t, al.AllowName("docker0"))
	assert.False(t, al.AllowName("tun0"))
	assert.True(t, al.AllowName("eth0"))

	rules = []AllowListNameRule{
		{Name: regexp.MustCompile("^eth.*$"), Allow: true},
		{Name: regexp.MustCompile("^ens.*$"), Allow: true},
	}
	al = &LocalAllowList{nameRules: rules}

	assert.False(t, al.AllowName("docker0"))
	assert.True(t, al.AllowName("eth0"))
	assert.True(t, al.AllowName("ens5"))
}
