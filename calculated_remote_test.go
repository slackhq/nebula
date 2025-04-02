package nebula

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculatedRemoteApply(t *testing.T) {
	// Test v4 addresses
	ipNet := netip.MustParsePrefix("192.168.1.0/24")
	c, err := newCalculatedRemote(ipNet, ipNet, 4242)
	require.NoError(t, err)

	input, err := netip.ParseAddr("10.0.10.182")
	require.NoError(t, err)

	expected, err := netip.ParseAddr("192.168.1.182")
	require.NoError(t, err)

	assert.Equal(t, netAddrToProtoV4AddrPort(expected, 4242), c.ApplyV4(input))

	// Test v6 addresses
	ipNet = netip.MustParsePrefix("ffff:ffff:ffff:ffff::0/64")
	c, err = newCalculatedRemote(ipNet, ipNet, 4242)
	require.NoError(t, err)

	input, err = netip.ParseAddr("beef:beef:beef:beef:beef:beef:beef:beef")
	require.NoError(t, err)

	expected, err = netip.ParseAddr("ffff:ffff:ffff:ffff:beef:beef:beef:beef")
	require.NoError(t, err)

	assert.Equal(t, netAddrToProtoV6AddrPort(expected, 4242), c.ApplyV6(input))

	// Test v6 addresses part 2
	ipNet = netip.MustParsePrefix("ffff:ffff:ffff:ffff:ffff::0/80")
	c, err = newCalculatedRemote(ipNet, ipNet, 4242)
	require.NoError(t, err)

	input, err = netip.ParseAddr("beef:beef:beef:beef:beef:beef:beef:beef")
	require.NoError(t, err)

	expected, err = netip.ParseAddr("ffff:ffff:ffff:ffff:ffff:beef:beef:beef")
	require.NoError(t, err)

	assert.Equal(t, netAddrToProtoV6AddrPort(expected, 4242), c.ApplyV6(input))

	// Test v6 addresses part 2
	ipNet = netip.MustParsePrefix("ffff:ffff:ffff::0/48")
	c, err = newCalculatedRemote(ipNet, ipNet, 4242)
	require.NoError(t, err)

	input, err = netip.ParseAddr("beef:beef:beef:beef:beef:beef:beef:beef")
	require.NoError(t, err)

	expected, err = netip.ParseAddr("ffff:ffff:ffff:beef:beef:beef:beef:beef")
	require.NoError(t, err)

	assert.Equal(t, netAddrToProtoV6AddrPort(expected, 4242), c.ApplyV6(input))
}

func Test_newCalculatedRemote(t *testing.T) {
	c, err := newCalculatedRemote(netip.MustParsePrefix("1::1/128"), netip.MustParsePrefix("1.0.0.0/32"), 4242)
	require.EqualError(t, err, "invalid mask: 1.0.0.0/32 for cidr: 1::1/128")
	require.Nil(t, c)

	c, err = newCalculatedRemote(netip.MustParsePrefix("1.0.0.0/32"), netip.MustParsePrefix("1::1/128"), 4242)
	require.EqualError(t, err, "invalid mask: 1::1/128 for cidr: 1.0.0.0/32")
	require.Nil(t, c)

	c, err = newCalculatedRemote(netip.MustParsePrefix("1.0.0.0/32"), netip.MustParsePrefix("1.0.0.0/32"), 4242)
	require.NoError(t, err)
	require.NotNil(t, c)

	c, err = newCalculatedRemote(netip.MustParsePrefix("1::1/128"), netip.MustParsePrefix("1::1/128"), 4242)
	require.NoError(t, err)
	require.NotNil(t, c)
}
