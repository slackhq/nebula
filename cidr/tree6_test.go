package cidr

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDR6Tree_MostSpecificContains(t *testing.T) {
	tree := NewTree6[string]()
	tree.AddCIDR(Parse("1.0.0.0/8"), "1")
	tree.AddCIDR(Parse("2.1.0.0/16"), "2")
	tree.AddCIDR(Parse("3.1.1.0/24"), "3")
	tree.AddCIDR(Parse("4.1.1.1/24"), "4a")
	tree.AddCIDR(Parse("4.1.1.1/30"), "4b")
	tree.AddCIDR(Parse("4.1.1.1/32"), "4c")
	tree.AddCIDR(Parse("254.0.0.0/4"), "5")
	tree.AddCIDR(Parse("1:2:0:4:5:0:0:0/64"), "6a")
	tree.AddCIDR(Parse("1:2:0:4:5:0:0:0/80"), "6b")
	tree.AddCIDR(Parse("1:2:0:4:5:0:0:0/96"), "6c")

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
		{true, "6a", "1:2:0:4:1:1:1:1"},
		{true, "6b", "1:2:0:4:5:1:1:1"},
		{true, "6c", "1:2:0:4:5:0:0:0"},
		{false, "", "239.0.0.0"},
		{false, "", "4.1.2.2"},
	}

	for _, tt := range tests {
		ok, r := tree.MostSpecificContains(net.ParseIP(tt.IP))
		assert.Equal(t, tt.Found, ok)
		assert.Equal(t, tt.Result, r)
	}

	tree = NewTree6[string]()
	tree.AddCIDR(Parse("1.1.1.1/0"), "cool")
	tree.AddCIDR(Parse("::/0"), "cool6")
	ok, r := tree.MostSpecificContains(net.ParseIP("0.0.0.0"))
	assert.True(t, ok)
	assert.Equal(t, "cool", r)

	ok, r = tree.MostSpecificContains(net.ParseIP("255.255.255.255"))
	assert.True(t, ok)
	assert.Equal(t, "cool", r)

	ok, r = tree.MostSpecificContains(net.ParseIP("::"))
	assert.True(t, ok)
	assert.Equal(t, "cool6", r)

	ok, r = tree.MostSpecificContains(net.ParseIP("1:2:3:4:5:6:7:8"))
	assert.True(t, ok)
	assert.Equal(t, "cool6", r)
}

func TestCIDR6Tree_MostSpecificContainsIpV6(t *testing.T) {
	tree := NewTree6[string]()
	tree.AddCIDR(Parse("1:2:0:4:5:0:0:0/64"), "6a")
	tree.AddCIDR(Parse("1:2:0:4:5:0:0:0/80"), "6b")
	tree.AddCIDR(Parse("1:2:0:4:5:0:0:0/96"), "6c")

	tests := []struct {
		Found  bool
		Result interface{}
		IP     string
	}{
		{true, "6a", "1:2:0:4:1:1:1:1"},
		{true, "6b", "1:2:0:4:5:1:1:1"},
		{true, "6c", "1:2:0:4:5:0:0:0"},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.IP)
		hi := binary.BigEndian.Uint64(ip[:8])
		lo := binary.BigEndian.Uint64(ip[8:])

		ok, r := tree.MostSpecificContainsIpV6(hi, lo)
		assert.Equal(t, tt.Found, ok)
		assert.Equal(t, tt.Result, r)
	}
}
