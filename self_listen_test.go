package nebula

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveSelfListenAddrs_TokenExpansion(t *testing.T) {
	vpnAddrs := []netip.Addr{
		netip.MustParseAddr("100.64.0.5"),
		netip.MustParseAddr("fd00::5"),
	}

	addrs, err := resolveSelfListenAddrs("<nebula>:8080", vpnAddrs)
	require.NoError(t, err)
	assert.Equal(t, []string{"100.64.0.5:8080", "[fd00::5]:8080"}, addrs)
}

func TestResolveSelfListenAddrs_TokenPreservesCertOrder(t *testing.T) {
	vpnAddrs := []netip.Addr{
		netip.MustParseAddr("fd00::5"),
		netip.MustParseAddr("100.64.0.5"),
		netip.MustParseAddr("100.64.0.6"),
	}

	addrs, err := resolveSelfListenAddrs("<nebula>:53", vpnAddrs)
	require.NoError(t, err)
	assert.Equal(t, []string{"[fd00::5]:53", "100.64.0.5:53", "100.64.0.6:53"}, addrs)
}

func TestResolveSelfListenAddrs_TokenUnmapsV4in6(t *testing.T) {
	// A 4-in-6 mapped address must render as plain IPv4, not [::ffff:...].
	vpnAddrs := []netip.Addr{netip.MustParseAddr("::ffff:100.64.0.5")}

	addrs, err := resolveSelfListenAddrs("<nebula>:8080", vpnAddrs)
	require.NoError(t, err)
	assert.Equal(t, []string{"100.64.0.5:8080"}, addrs)
}

func TestResolveSelfListenAddrs_NonTokenPassthrough(t *testing.T) {
	// Non-token values must be returned as the exact original string, so every
	// existing config behaves exactly as before.
	cases := []string{
		"127.0.0.1:8080",
		"0.0.0.0:53",
		"[::]:53",
		"[fd00::5]:2222",
		"example.com:443",
	}
	for _, in := range cases {
		addrs, err := resolveSelfListenAddrs(in, nil)
		require.NoError(t, err, in)
		require.Len(t, addrs, 1, in)
		assert.Equal(t, in, addrs[0], in)
	}
}

func TestResolveSelfListenAddrs_MalformedPassthrough(t *testing.T) {
	// Values that don't parse as host:port and don't contain the token defer to
	// the bind, matching today's behavior (they keep failing at bind time).
	cases := []string{
		"8080",        // bare port
		"::",          // host only, no port
		"not a valid", // garbage
	}
	for _, in := range cases {
		addrs, err := resolveSelfListenAddrs(in, nil)
		require.NoError(t, err, in)
		assert.Equal(t, []string{in}, addrs, in)
	}
}

func TestResolveSelfListenAddrs_TokenWithoutPortErrors(t *testing.T) {
	// The token present but not in host:port form must fail loud.
	_, err := resolveSelfListenAddrs("<nebula>", []netip.Addr{netip.MustParseAddr("100.64.0.5")})
	assert.Error(t, err)
}

func TestResolveSelfListenAddrs_TokenNoVpnAddrsErrors(t *testing.T) {
	_, err := resolveSelfListenAddrs("<nebula>:8080", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no VPN addresses")
}
