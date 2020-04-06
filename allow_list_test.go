package nebula

import (
	"net"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllowList_Allow(t *testing.T) {
	assert.Equal(t, true, ((*AllowList)(nil)).Allow(ip2int(net.ParseIP("1.1.1.1"))))

	tree := NewCIDRTree()
	tree.AddCIDR(getCIDR("0.0.0.0/0"), true)
	tree.AddCIDR(getCIDR("10.0.0.0/8"), false)
	tree.AddCIDR(getCIDR("10.42.42.0/24"), true)
	al := &AllowList{cidrTree: tree}

	assert.Equal(t, true, al.Allow(ip2int(net.ParseIP("1.1.1.1"))))
	assert.Equal(t, false, al.Allow(ip2int(net.ParseIP("10.0.0.4"))))
	assert.Equal(t, true, al.Allow(ip2int(net.ParseIP("10.42.42.42"))))
}

func TestAllowList_AllowNamed(t *testing.T) {
	assert.Equal(t, true, ((*AllowList)(nil)).AllowNamed("docker0", ip2int(net.ParseIP("1.1.1.1"))))

	tree := NewCIDRTree()
	tree.AddCIDR(getCIDR("0.0.0.0/0"), true)
	tree.AddCIDR(getCIDR("10.0.0.0/8"), false)
	tree.AddCIDR(getCIDR("10.42.42.0/24"), true)
	rules := []AllowListNameRule{
		{Name: regexp.MustCompile("^docker.*$"), Allow: false},
	}
	al := &AllowList{cidrTree: tree, nameRules: rules}

	assert.Equal(t, false, al.AllowNamed("docker0", ip2int(net.ParseIP("1.1.1.1"))))
	assert.Equal(t, true, al.AllowNamed("eth0", ip2int(net.ParseIP("1.1.1.1"))))
	assert.Equal(t, false, al.AllowNamed("eth0", ip2int(net.ParseIP("10.0.0.4"))))
	assert.Equal(t, true, al.AllowNamed("eth0", ip2int(net.ParseIP("10.42.42.42"))))

	rules = []AllowListNameRule{
		{Name: regexp.MustCompile("^eth.*$"), Allow: true},
	}
	al = &AllowList{cidrTree: tree, nameRules: rules}

	assert.Equal(t, false, al.AllowNamed("docker0", ip2int(net.ParseIP("1.1.1.1"))))
	assert.Equal(t, true, al.AllowNamed("eth0", ip2int(net.ParseIP("1.1.1.1"))))
	assert.Equal(t, false, al.AllowNamed("eth0", ip2int(net.ParseIP("10.0.0.4"))))
	assert.Equal(t, true, al.AllowNamed("eth0", ip2int(net.ParseIP("10.42.42.42"))))
}
