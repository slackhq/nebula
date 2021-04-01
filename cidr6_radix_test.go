package nebula

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDR6Tree_MostSpecificContains(t *testing.T) {
	tree := NewCIDR6Tree()
	tree.AddCIDR(getCIDR("1.0.0.0/8"), "1")
	tree.AddCIDR(getCIDR("2.1.0.0/16"), "2")
	tree.AddCIDR(getCIDR("3.1.1.0/24"), "3")
	tree.AddCIDR(getCIDR("4.1.1.1/24"), "4a")
	tree.AddCIDR(getCIDR("4.1.1.1/30"), "4b")
	tree.AddCIDR(getCIDR("4.1.1.1/32"), "4c")
	tree.AddCIDR(getCIDR("254.0.0.0/4"), "5")
	tree.AddCIDR(getCIDR("1:2:0:4:5:0:0:0/64"), "6a")
	tree.AddCIDR(getCIDR("1:2:0:4:5:0:0:0/80"), "6b")
	tree.AddCIDR(getCIDR("1:2:0:4:5:0:0:0/96"), "6c")

	tests := []struct {
		Result interface{}
		IP     string
	}{
		{"1", "1.0.0.0"},
		{"1", "1.255.255.255"},
		{"2", "2.1.0.0"},
		{"2", "2.1.255.255"},
		{"3", "3.1.1.0"},
		{"3", "3.1.1.255"},
		{"4a", "4.1.1.255"},
		{"4b", "4.1.1.2"},
		{"4c", "4.1.1.1"},
		{"5", "240.0.0.0"},
		{"5", "255.255.255.255"},
		{"6a", "1:2:0:4:1:1:1:1"},
		{"6b", "1:2:0:4:5:1:1:1"},
		{"6c", "1:2:0:4:5:0:0:0"},
		{nil, "239.0.0.0"},
		{nil, "4.1.2.2"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.Result, tree.MostSpecificContains(net.ParseIP(tt.IP)))
	}

	tree = NewCIDR6Tree()
	tree.AddCIDR(getCIDR("1.1.1.1/0"), "cool")
	tree.AddCIDR(getCIDR("::/0"), "cool6")
	assert.Equal(t, "cool", tree.MostSpecificContains(net.ParseIP("0.0.0.0")))
	assert.Equal(t, "cool", tree.MostSpecificContains(net.ParseIP("255.255.255.255")))
	assert.Equal(t, "cool6", tree.MostSpecificContains(net.ParseIP("::")))
	assert.Equal(t, "cool6", tree.MostSpecificContains(net.ParseIP("1:2:3:4:5:6:7:8")))
}

func TestCIDR6Tree_MostSpecificContainsIpV6(t *testing.T) {
	tree := NewCIDR6Tree()
	tree.AddCIDR(getCIDR("1:2:0:4:5:0:0:0/64"), "6a")
	tree.AddCIDR(getCIDR("1:2:0:4:5:0:0:0/80"), "6b")
	tree.AddCIDR(getCIDR("1:2:0:4:5:0:0:0/96"), "6c")

	tests := []struct {
		Result interface{}
		IP     string
	}{
		{"6a", "1:2:0:4:1:1:1:1"},
		{"6b", "1:2:0:4:5:1:1:1"},
		{"6c", "1:2:0:4:5:0:0:0"},
	}

	for _, tt := range tests {
		ip := NewIp6AndPort(net.ParseIP(tt.IP), 0)
		assert.Equal(t, tt.Result, tree.MostSpecificContainsIpV6(ip.Hi, ip.Lo))
	}
}
