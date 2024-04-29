package nebula

import (
	"net"
	"testing"

	"github.com/slackhq/nebula/iputil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculatedRemoteApply(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("192.168.1.0/24")
	require.NoError(t, err)

	c, err := newCalculatedRemote(ipNet, 4242)
	require.NoError(t, err)

	input := iputil.Ip2VpnIp([]byte{10, 0, 10, 182})

	expected := &Ip4AndPort{
		Ip:   uint32(iputil.Ip2VpnIp([]byte{192, 168, 1, 182})),
		Port: 4242,
	}

	assert.Equal(t, expected, c.Apply(input))
}
