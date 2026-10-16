//go:build (openbsd || netbsd) && !e2e_testing

package overlay

import (
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A tun.dev that isn't tunN is ignored like darwin does, and the first free tun is used. Only naming a different tun
// asks for a restart
func TestTunReloadDevRestart(t *testing.T) {
	newWithDev := func(dev string) (*config.C, *tun, error) {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString("tun:\n  dev: "+dev+"\n"))
		tn, err := newTun(c, test.NewLogger(), []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")}, false)
		if err == nil {
			t.Cleanup(func() { _ = tn.Close() })
		}
		return c, tn, err
	}
	if _, _, err := newWithDev(""); err != nil {
		t.Skipf("can't create a tun device here: %v", err)
	}
	c, tn, err := newWithDev("nope")
	require.NoError(t, err, "a bad name should fall back to a free tun")
	require.Regexp(t, `^tun[0-9]+$`, tn.Device)

	for _, dev := range []string{"nope", "", tn.Device, "nope"} {
		res := c.ReloadConfigString("tun:\n  dev: " + dev + "\n")
		require.NoError(t, res.Err)
		assert.False(t, res.Failed, dev)
		assert.False(t, res.RestartRequired, dev)
	}

	other := "tun0"
	if tn.Device == other {
		other = "tun1"
	}
	res := c.ReloadConfigString("tun:\n  dev: " + other + "\n")
	require.NoError(t, res.Err)
	assert.Equal(t, []string{"tun.dev"}, res.RestartKeys)
}

// An empty tun.dev takes the first tun nothing else has open. Reloading it empty, or naming the one we have, needs
// no restart
func TestTunEmptyDevPicksAFreeOne(t *testing.T) {
	newEmpty := func() (*config.C, *tun, error) {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString("tun: {}\n"))
		tn, err := newTun(c, test.NewLogger(), []netip.Prefix{netip.MustParsePrefix("10.1.0.2/24")}, false)
		if err == nil {
			t.Cleanup(func() { _ = tn.Close() })
		}
		return c, tn, err
	}
	c, first, err := newEmpty()
	if err != nil {
		t.Skipf("can't create a tun device here: %v", err)
	}
	_, second, err := newEmpty()
	require.NoError(t, err, "the second tun should skip the one the first has open")
	assert.NotEqual(t, first.Device, second.Device)

	for _, cfg := range []string{
		"tun: {}\npunchy:\n  punch: true\n",
		"tun:\n  dev: " + first.Device + "\n",
		"tun: {}\n",
	} {
		res := c.ReloadConfigString(cfg)
		require.NoError(t, res.Err)
		assert.False(t, res.Failed)
		assert.False(t, res.RestartRequired, cfg)
	}
}
