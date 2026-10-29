//go:build linux && !android && !e2e_testing

package udp

import (
	"net/netip"
	"os"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A setting the kernel refuses fails the reload
func TestReloadConfig_RefusedSettingFailsTheReload(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may set listen.so_mark, run as an unprivileged user")
	}
	conn, err := NewListener(testLogger(), Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Batch: 1})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	c := config.NewC(testLogger())
	require.NoError(t, c.LoadString("listen:\n  port: 0\n"))
	c.RegisterReloadCallback(conn.ReloadConfig)

	res := c.ReloadConfigString("listen:\n  port: 0\n  so_mark: 42\n")
	require.NoError(t, res.Err)
	assert.True(t, res.Failed)
}
