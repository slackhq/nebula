package cidr

import (
	"net"
	"testing"

	"github.com/slackhq/nebula/iputil"
	"github.com/stretchr/testify/assert"
)

func TestCIDRTree_List(t *testing.T) {
	tree := NewTree4[string]()
	tree.AddCIDR(Parse("1.0.0.0/16"), "1")
	tree.AddCIDR(Parse("1.0.0.0/8"), "2")
	tree.AddCIDR(Parse("1.0.0.0/16"), "3")
	tree.AddCIDR(Parse("1.0.0.0/16"), "4")
	list := tree.List()
	assert.Len(t, list, 2)
	assert.Equal(t, "1.0.0.0/8", list[0].CIDR.String())
	assert.Equal(t, "2", list[0].Value)
	assert.Equal(t, "1.0.0.0/16", list[1].CIDR.String())
	assert.Equal(t, "4", list[1].Value)
}

func TestCIDRTree_Contains(t *testing.T) {
	tree := NewTree4[string]()
	tree.AddCIDR(Parse("1.0.0.0/8"), "1")
	tree.AddCIDR(Parse("2.1.0.0/16"), "2")
	tree.AddCIDR(Parse("3.1.1.0/24"), "3")
	tree.AddCIDR(Parse("4.1.1.0/24"), "4a")
	tree.AddCIDR(Parse("4.1.1.1/32"), "4b")
	tree.AddCIDR(Parse("4.1.2.1/32"), "4c")
	tree.AddCIDR(Parse("254.0.0.0/4"), "5")

	tests := []struct {
		Found  bool
		Result interface{}
		IP     string
	}{
		{true, "1", "1.0.0.0"},
		{true, "1", "1.255.255.255"},
		{true, "2", "2.1.0.0"},
		{true, "2", "2.1.255.255"},
		{true, "3", "3.1.1.0"},
		{true, "3", "3.1.1.255"},
		{true, "4a", "4.1.1.255"},
		{true, "4a", "4.1.1.1"},
		{true, "5", "240.0.0.0"},
		{true, "5", "255.255.255.255"},
		{false, "", "239.0.0.0"},
		{false, "", "4.1.2.2"},
	}

	for _, tt := range tests {
		ok, r := tree.Contains(iputil.Ip2VpnIp(net.ParseIP(tt.IP)))
		assert.Equal(t, tt.Found, ok)
		assert.Equal(t, tt.Result, r)
	}

	tree = NewTree4[string]()
	tree.AddCIDR(Parse("1.1.1.1/0"), "cool")
	ok, r := tree.Contains(iputil.Ip2VpnIp(net.ParseIP("0.0.0.0")))
	assert.True(t, ok)
	assert.Equal(t, "cool", r)

	ok, r = tree.Contains(iputil.Ip2VpnIp(net.ParseIP("255.255.255.255")))
	assert.True(t, ok)
	assert.Equal(t, "cool", r)
}

func TestCIDRTree_MostSpecificContains(t *testing.T) {
	tree := NewTree4[string]()
	tree.AddCIDR(Parse("1.0.0.0/8"), "1")
	tree.AddCIDR(Parse("2.1.0.0/16"), "2")
	tree.AddCIDR(Parse("3.1.1.0/24"), "3")
	tree.AddCIDR(Parse("4.1.1.0/24"), "4a")
	tree.AddCIDR(Parse("4.1.1.0/30"), "4b")
	tree.AddCIDR(Parse("4.1.1.1/32"), "4c")
	tree.AddCIDR(Parse("254.0.0.0/4"), "5")

	tests := []struct {
		Found  bool
		Result interface{}
		IP     string
	}{
		{true, "1", "1.0.0.0"},
		{true, "1", "1.255.255.255"},
		{true, "2", "2.1.0.0"},
		{true, "2", "2.1.255.255"},
		{true, "3", "3.1.1.0"},
		{true, "3", "3.1.1.255"},
		{true, "4a", "4.1.1.255"},
		{true, "4b", "4.1.1.2"},
		{true, "4c", "4.1.1.1"},
		{true, "5", "240.0.0.0"},
		{true, "5", "255.255.255.255"},
		{false, "", "239.0.0.0"},
		{false, "", "4.1.2.2"},
	}

	for _, tt := range tests {
		ok, r := tree.MostSpecificContains(iputil.Ip2VpnIp(net.ParseIP(tt.IP)))
		assert.Equal(t, tt.Found, ok)
		assert.Equal(t, tt.Result, r)
	}

	tree = NewTree4[string]()
	tree.AddCIDR(Parse("1.1.1.1/0"), "cool")
	ok, r := tree.MostSpecificContains(iputil.Ip2VpnIp(net.ParseIP("0.0.0.0")))
	assert.True(t, ok)
	assert.Equal(t, "cool", r)

	ok, r = tree.MostSpecificContains(iputil.Ip2VpnIp(net.ParseIP("255.255.255.255")))
	assert.True(t, ok)
	assert.Equal(t, "cool", r)
}

func TestCIDRTree_Match(t *testing.T) {
	tree := NewTree4[string]()
	tree.AddCIDR(Parse("4.1.1.0/32"), "1a")
	tree.AddCIDR(Parse("4.1.1.1/32"), "1b")

	tests := []struct {
		Found  bool
		Result interface{}
		IP     string
	}{
		{true, "1a", "4.1.1.0"},
		{true, "1b", "4.1.1.1"},
	}

	for _, tt := range tests {
		ok, r := tree.Match(iputil.Ip2VpnIp(net.ParseIP(tt.IP)))
		assert.Equal(t, tt.Found, ok)
		assert.Equal(t, tt.Result, r)
	}

	tree = NewTree4[string]()
	tree.AddCIDR(Parse("1.1.1.1/0"), "cool")
	ok, r := tree.Contains(iputil.Ip2VpnIp(net.ParseIP("0.0.0.0")))
	assert.True(t, ok)
	assert.Equal(t, "cool", r)

	ok, r = tree.Contains(iputil.Ip2VpnIp(net.ParseIP("255.255.255.255")))
	assert.True(t, ok)
	assert.Equal(t, "cool", r)
}

func BenchmarkCIDRTree_Contains(b *testing.B) {
	tree := NewTree4[string]()
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
	tree := NewTree4[string]()
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
