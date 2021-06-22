package cidr

import (
	"net"
	"testing"

	"github.com/slackhq/nebula/iputil"
	"github.com/stretchr/testify/assert"
)

func TestCIDRTree_Contains(t *testing.T) {
	tree := NewTree4()
	tree.AddCIDR(Parse("1.0.0.0/8"), "1")
	tree.AddCIDR(Parse("2.1.0.0/16"), "2")
	tree.AddCIDR(Parse("3.1.1.0/24"), "3")
	tree.AddCIDR(Parse("4.1.1.0/24"), "4a")
	tree.AddCIDR(Parse("4.1.1.1/32"), "4b")
	tree.AddCIDR(Parse("4.1.2.1/32"), "4c")
	tree.AddCIDR(Parse("254.0.0.0/4"), "5")

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
		assert.Equal(t, tt.Result, tree.Contains(iputil.Ip2VpnIp(net.ParseIP(tt.IP))))
	}

	tree = NewTree4()
	tree.AddCIDR(Parse("1.1.1.1/0"), "cool")
	assert.Equal(t, "cool", tree.Contains(iputil.Ip2VpnIp(net.ParseIP("0.0.0.0"))))
	assert.Equal(t, "cool", tree.Contains(iputil.Ip2VpnIp(net.ParseIP("255.255.255.255"))))
}

func TestCIDRTree_MostSpecificContains(t *testing.T) {
	tree := NewTree4()
	tree.AddCIDR(Parse("1.0.0.0/8"), "1")
	tree.AddCIDR(Parse("2.1.0.0/16"), "2")
	tree.AddCIDR(Parse("3.1.1.0/24"), "3")
	tree.AddCIDR(Parse("4.1.1.0/24"), "4a")
	tree.AddCIDR(Parse("4.1.1.0/30"), "4b")
	tree.AddCIDR(Parse("4.1.1.1/32"), "4c")
	tree.AddCIDR(Parse("254.0.0.0/4"), "5")

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
		assert.Equal(t, tt.Result, tree.MostSpecificContains(iputil.Ip2VpnIp(net.ParseIP(tt.IP))))
	}

	tree = NewTree4()
	tree.AddCIDR(Parse("1.1.1.1/0"), "cool")
	assert.Equal(t, "cool", tree.MostSpecificContains(iputil.Ip2VpnIp(net.ParseIP("0.0.0.0"))))
	assert.Equal(t, "cool", tree.MostSpecificContains(iputil.Ip2VpnIp(net.ParseIP("255.255.255.255"))))
}

func TestCIDRTree_Match(t *testing.T) {
	tree := NewTree4()
	tree.AddCIDR(Parse("4.1.1.0/32"), "1a")
	tree.AddCIDR(Parse("4.1.1.1/32"), "1b")

	tests := []struct {
		Result interface{}
		IP     string
	}{
		{"1a", "4.1.1.0"},
		{"1b", "4.1.1.1"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.Result, tree.Match(iputil.Ip2VpnIp(net.ParseIP(tt.IP))))
	}

	tree = NewTree4()
	tree.AddCIDR(Parse("1.1.1.1/0"), "cool")
	assert.Equal(t, "cool", tree.Contains(iputil.Ip2VpnIp(net.ParseIP("0.0.0.0"))))
	assert.Equal(t, "cool", tree.Contains(iputil.Ip2VpnIp(net.ParseIP("255.255.255.255"))))
}

func BenchmarkCIDRTree_Contains(b *testing.B) {
	tree := NewTree4()
	tree.AddCIDR(Parse("1.1.0.0/16"), "1")
	tree.AddCIDR(Parse("1.2.1.1/32"), "1")
	tree.AddCIDR(Parse("192.2.1.1/32"), "1")
	tree.AddCIDR(Parse("172.2.1.1/32"), "1")

	ip := iputil.Ip2VpnIp(net.ParseIP("1.2.1.1"))
	b.Run("found", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.Contains(ip)
		}
	})

	ip = iputil.Ip2VpnIp(net.ParseIP("1.2.1.255"))
	b.Run("not found", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.Contains(ip)
		}
	})
}

func BenchmarkCIDRTree_Match(b *testing.B) {
	tree := NewTree4()
	tree.AddCIDR(Parse("1.1.0.0/16"), "1")
	tree.AddCIDR(Parse("1.2.1.1/32"), "1")
	tree.AddCIDR(Parse("192.2.1.1/32"), "1")
	tree.AddCIDR(Parse("172.2.1.1/32"), "1")

	ip := iputil.Ip2VpnIp(net.ParseIP("1.2.1.1"))
	b.Run("found", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.Match(ip)
		}
	})

	ip = iputil.Ip2VpnIp(net.ParseIP("1.2.1.255"))
	b.Run("not found", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.Match(ip)
		}
	})
}
