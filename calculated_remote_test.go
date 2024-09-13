package nebula

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculatedRemoteApply(t *testing.T) {
	ipNet, err := netip.ParsePrefix("192.168.1.0/24")
	require.NoError(t, err)

	c, err := newCalculatedRemote(ipNet, 4242)
	require.NoError(t, err)

	input, err := netip.ParseAddr("10.0.10.182")
	assert.NoError(t, err)

	expected, err := netip.ParseAddr("192.168.1.182")
	assert.NoError(t, err)

	assert.Equal(t, NewIp4AndPortFromNetIP(expected, 4242), c.Apply(input))
}
