package nebula

import (
	"net"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllowList_Allow(t *testing.T) {
	assert.Equal(t, true, ((*AllowList)(nil)).Allow(net.ParseIP("1.1.1.1")))

	tree := NewCIDR6Tree()
	tree.AddCIDR(getCIDR("0.0.0.0/0"), true)
	tree.AddCIDR(getCIDR("10.0.0.0/8"), false)
	tree.AddCIDR(getCIDR("10.42.42.42/32"), true)
	tree.AddCIDR(getCIDR("10.42.0.0/16"), true)
	tree.AddCIDR(getCIDR("10.42.42.0/24"), true)
	tree.AddCIDR(getCIDR("10.42.42.0/24"), false)
	tree.AddCIDR(getCIDR("::1/128"), true)
	tree.AddCIDR(getCIDR("::2/128"), false)
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
