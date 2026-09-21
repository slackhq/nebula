package nicfinder

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

type allowAll struct{}

func (allowAll) Allow(netip.Addr) bool { return true }
func (allowAll) AllowName(string) bool { return true }

type testAllowList struct {
	bannedName *regexp.Regexp
	bannedAddr netip.Addr
}

func (l *testAllowList) Allow(addr netip.Addr) bool {
	return addr != l.bannedAddr
}

func (l *testAllowList) AllowName(n string) bool {
	return !l.bannedName.MatchString(n)
}

func newTestAllowList(bannedName string) *testAllowList {
	return &testAllowList{
		bannedName: regexp.MustCompile(bannedName),
	}
}

func TestAllowedAddr(t *testing.T) {
	ctx, l := context.Background(), test.NewLogger()
	allowed := func(filter Filter, addrs []net.Addr) []netip.Addr {
		var out []netip.Addr
		for _, rawAddr := range addrs {
			if addr, ok := allowedAddr(ctx, l, filter, rawAddr); ok {
				out = append(out, addr)
			}
		}
		return out
	}
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("169.254.10.10"), Mask: net.CIDRMask(16, 32)},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPAddr{IP: net.ParseIP("fd00::5")},
		&net.IPNet{},
		otherAddr{},
		nil,
	}

	// Loopback, link local and anything without an IP are dropped, and IPv4 comes back unmapped
	// even though net.ParseIP hands over a 16 byte slice.
	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("fd00::5"),
	}, allowed(allowAll{}, addrs))

	// The filter sees the unmapped form and can drop a single address.
	al := newTestAllowList("none")
	al.bannedAddr = netip.MustParseAddr("10.0.0.5")
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("fd00::5")}, allowed(al, addrs))
}

// otherAddr is a net.Addr that is neither *net.IPNet nor *net.IPAddr. netlink.Addr is one such
// type: it satisfies net.Addr through an embedded *net.IPNet, and passing it directly once
// silently produced no addresses.
type otherAddr struct{}

func (otherAddr) Network() string { return "other" }
func (otherAddr) String() string  { return "other" }

// hostFilter counts AllowName calls and can reject every name or every address.
type hostFilter struct {
	rejectNames bool
	rejectAddrs bool
	asked       map[string]int
}

func (f *hostFilter) Allow(netip.Addr) bool { return !f.rejectAddrs }
func (f *hostFilter) AllowName(name string) bool {
	f.asked[name]++
	return !f.rejectNames
}

// Runs this platform's localAddrs against the host and checks it honors the whole filter.
func TestLocalAddrsAppliesFilter(t *testing.T) {
	ctx, l := context.Background(), test.NewLogger()

	f := &hostFilter{asked: map[string]int{}}
	all, err := localAddrs(ctx, l, f)
	if len(f.asked) == 0 {
		t.Skipf("no interfaces to enumerate here: %v", err)
	}
	for name, n := range f.asked {
		assert.Equal(t, 1, n, "AllowName asked %d times for %s", n, name)
	}
	// Loopback and link-local never come back, whatever the filter says.
	for _, addr := range all {
		assert.False(t, addr.IsLoopback() || addr.IsLinkLocalUnicast(), "%s", addr)
	}

	none, _ := localAddrs(ctx, l, &hostFilter{rejectNames: true, asked: map[string]int{}})
	assert.Empty(t, none, "addresses got past a filter that rejects every interface name")

	none, _ = localAddrs(ctx, l, &hostFilter{rejectAddrs: true, asked: map[string]int{}})
	assert.Empty(t, none, "addresses got past a filter that rejects every address")
}
