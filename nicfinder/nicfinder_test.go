package nicfinder

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type allowAll struct{}

func (allowAll) Allow(netip.Addr) bool { return true }
func (allowAll) AllowName(string) bool { return true }

type testAllowList struct {
	bannedName *regexp.Regexp
}

func (l *testAllowList) Allow(netip.Addr) bool {
	return true
}

func (l *testAllowList) AllowName(n string) bool {
	return !l.bannedName.MatchString(n)
}

func newTestAllowList(bannedName string) *testAllowList {
	return &testAllowList{
		bannedName: regexp.MustCompile(bannedName),
	}
}

func TestCollectLocalAddrs(t *testing.T) {
	ifaces := []localInterface{
		{Name: "lo", Addrs: netipAddrs([]net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		})},
		{Name: "eth0", Addrs: netipAddrs([]net.Addr{
			&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
			&net.IPAddr{IP: net.ParseIP("fd00::5")},
		})},
		{Name: "docker0", Addrs: netipAddrs([]net.Addr{
			&net.IPNet{IP: net.ParseIP("172.17.0.1"), Mask: net.CIDRMask(16, 32)},
		})},
	}
	finder := func() ([]localInterface, error) { return ifaces, nil }

	// Loopback and link local are dropped, everything else on every interface is kept, and IPv4
	// comes through unmapped.
	out, err := collectLocalAddrs(context.Background(), test.NewLogger(), allowAll{}, finder)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("fd00::5"),
		netip.MustParseAddr("172.17.0.1"),
	}, out)

	// An interface the allow list rejects by name contributes nothing.
	out, err = collectLocalAddrs(context.Background(), test.NewLogger(), newTestAllowList("docker.*"), finder)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("fd00::5"),
	}, out)

	// A failure to enumerate interfaces at all is reported rather than silently advertising nothing.
	out, err = collectLocalAddrs(
		context.Background(),
		test.NewLogger(),
		allowAll{},
		func() ([]localInterface, error) {
			return nil, errors.New("failed to enumerate local interfaces: netlinkrib: permission denied")
		},
	)
	assert.Nil(t, out)
	require.EqualError(t, err, "failed to enumerate local interfaces: netlinkrib: permission denied")

	// A finder that could read some interfaces but not others returns both. The ones it read are
	// still collected and the error is passed on.
	out, err = collectLocalAddrs(
		context.Background(),
		test.NewLogger(),
		allowAll{},
		func() ([]localInterface, error) {
			return []localInterface{ifaces[0], ifaces[2]}, errors.New("failed to get addresses for eth0: nope")
		},
	)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("172.17.0.1")}, out)
	require.EqualError(t, err, "failed to get addresses for eth0: nope")
}

// otherAddr is a net.Addr that is neither *net.IPNet nor *net.IPAddr. netlink.Addr is one such
// type: it satisfies net.Addr through an embedded *net.IPNet, and passing it directly once
// silently produced no addresses.
type otherAddr struct{}

func (otherAddr) Network() string { return "other" }
func (otherAddr) String() string  { return "other" }

func TestNetToNetIP(t *testing.T) {
	addr, ok := netToNetIP(&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(24, 32)})
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("::ffff:10.0.0.5"), addr, "net.ParseIP yields a 16 byte slice; Unmap is the caller's job")

	addr, ok = netToNetIP(&net.IPAddr{IP: net.ParseIP("fd00::5")})
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("fd00::5"), addr)

	_, ok = netToNetIP(&net.IPNet{})
	assert.False(t, ok, "an IPNet without an IP carries nothing")

	_, ok = netToNetIP(otherAddr{})
	assert.False(t, ok, "unknown net.Addr implementations must be rejected, not misread")

	_, ok = netToNetIP(nil)
	assert.False(t, ok)
}
