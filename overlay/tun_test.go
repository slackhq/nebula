package overlay

import (
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tun.disabled and the disabled tun's settings are only read when the device is made
func TestDisabledTunRestartKeys(t *testing.T) {
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString("tun:\n  disabled: true\n"))
	d, err := NewDeviceFromConfig(c, test.NewLogger(), []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")}, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })

	res := c.ReloadConfigString("tun:\n  disabled: false\n  tx_queue: 100\n")
	require.NoError(t, res.Err)
	assert.ElementsMatch(t, []string{"tun.disabled", "tun.tx_queue"}, res.RestartKeys)
}
