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
