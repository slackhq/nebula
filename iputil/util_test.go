package iputil

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVpnIp_String(t *testing.T) {
	assert.Equal(t, "255.255.255.255", Ip2VpnIp(net.ParseIP("255.255.255.255")).String())
	assert.Equal(t, "1.255.255.255", Ip2VpnIp(net.ParseIP("1.255.255.255")).String())
	assert.Equal(t, "1.1.255.255", Ip2VpnIp(net.ParseIP("1.1.255.255")).String())
	assert.Equal(t, "1.1.1.255", Ip2VpnIp(net.ParseIP("1.1.1.255")).String())
	assert.Equal(t, "1.1.1.1", Ip2VpnIp(net.ParseIP("1.1.1.1")).String())
	assert.Equal(t, "0.0.0.0", Ip2VpnIp(net.ParseIP("0.0.0.0")).String())
}
