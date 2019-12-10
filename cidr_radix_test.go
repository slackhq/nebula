package nebula

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDRTree_Contains(t *testing.T) {
	tree := NewCIDRTree()
	tree.AddCIDR(getCIDR("1.0.0.0/8"), "1")
	tree.AddCIDR(getCIDR("2.1.0.0/16"), "2")
	tree.AddCIDR(getCIDR("3.1.1.0/24"), "3")
	tree.AddCIDR(getCIDR("4.1.1.0/24"), "4a")
	tree.AddCIDR(getCIDR("4.1.1.1/32"), "4b")
	tree.AddCIDR(getCIDR("4.1.2.1/32"), "4c")
	tree.AddCIDR(getCIDR("254.0.0.0/4"), "5")

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
		{"4a", "4.1.1.1"},
		{"5", "240.0.0.0"},
		{"5", "255.255.255.255"},
		{nil, "239.0.0.0"},
		{nil, "4.1.2.2"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.Result, tree.Contains(ip2int(net.ParseIP(tt.IP))))
	}

	tree = NewCIDRTree()
	tree.AddCIDR(getCIDR("1.1.1.1/0"), "cool")
	assert.Equal(t, "cool", tree.Contains(ip2int(net.ParseIP("0.0.0.0"))))
	assert.Equal(t, "cool", tree.Contains(ip2int(net.ParseIP("255.255.255.255"))))
}

func TestCIDRTree_MostSpecificContains(t *testing.T) {
	tree := NewCIDRTree()
	tree.AddCIDR(getCIDR("1.0.0.0/8"), "1")
	tree.AddCIDR(getCIDR("2.1.0.0/16"), "2")
	tree.AddCIDR(getCIDR("3.1.1.0/24"), "3")
	tree.AddCIDR(getCIDR("4.1.1.0/24"), "4a")
	tree.AddCIDR(getCIDR("4.1.1.0/30"), "4b")
	tree.AddCIDR(getCIDR("4.1.1.1/32"), "4c")
	tree.AddCIDR(getCIDR("254.0.0.0/4"), "5")

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
		{nil, "239.0.0.0"},
		{nil, "4.1.2.2"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.Result, tree.MostSpecificContains(ip2int(net.ParseIP(tt.IP))))
	}

	tree = NewCIDRTree()
	tree.AddCIDR(getCIDR("1.1.1.1/0"), "cool")
	assert.Equal(t, "cool", tree.MostSpecificContains(ip2int(net.ParseIP("0.0.0.0"))))
	assert.Equal(t, "cool", tree.MostSpecificContains(ip2int(net.ParseIP("255.255.255.255"))))
}

func TestCIDRTree_Match(t *testing.T) {
	tree := NewCIDRTree()
	tree.AddCIDR(getCIDR("4.1.1.0/32"), "1a")
	tree.AddCIDR(getCIDR("4.1.1.1/32"), "1b")

	tests := []struct {
		Result interface{}
		IP     string
	}{
		{"1a", "4.1.1.0"},
		{"1b", "4.1.1.1"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.Result, tree.Match(ip2int(net.ParseIP(tt.IP))))
	}

	tree = NewCIDRTree()
	tree.AddCIDR(getCIDR("1.1.1.1/0"), "cool")
	assert.Equal(t, "cool", tree.Contains(ip2int(net.ParseIP("0.0.0.0"))))
	assert.Equal(t, "cool", tree.Contains(ip2int(net.ParseIP("255.255.255.255"))))
}

func BenchmarkCIDRTree_Contains(b *testing.B) {
	tree := NewCIDRTree()
	tree.AddCIDR(getCIDR("1.1.0.0/16"), "1")
	tree.AddCIDR(getCIDR("1.2.1.1/32"), "1")
	tree.AddCIDR(getCIDR("192.2.1.1/32"), "1")
	tree.AddCIDR(getCIDR("172.2.1.1/32"), "1")

	ip := ip2int(net.ParseIP("1.2.1.1"))
	b.Run("found", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.Contains(ip)
		}
	})

	ip = ip2int(net.ParseIP("1.2.1.255"))
	b.Run("not found", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.Contains(ip)
		}
	})
}

func BenchmarkCIDRTree_Match(b *testing.B) {
	tree := NewCIDRTree()
	tree.AddCIDR(getCIDR("1.1.0.0/16"), "1")
	tree.AddCIDR(getCIDR("1.2.1.1/32"), "1")
	tree.AddCIDR(getCIDR("192.2.1.1/32"), "1")
	tree.AddCIDR(getCIDR("172.2.1.1/32"), "1")

	ip := ip2int(net.ParseIP("1.2.1.1"))
	b.Run("found", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.Match(ip)
		}
	})

	ip = ip2int(net.ParseIP("1.2.1.255"))
	b.Run("not found", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.Match(ip)
		}
	})
}

func getCIDR(s string) *net.IPNet {
	_, c, _ := net.ParseCIDR(s)
	return c
}
