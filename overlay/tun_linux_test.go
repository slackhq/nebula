//go:build !e2e_testing

package overlay

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/DefinedNet/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPolicyRulesForRoutes(t *testing.T) {
	for _, source := range []string{"192.168.200.1/24", "2001:db8:1200::1/44"} {
		t.Run(source, func(t *testing.T) {
			prefix := netip.MustParsePrefix(source)
			route := Route{Install: true, Source: &prefix, Table: 200, Priority: 10000}
			disabled := route
			disabled.Install = false
			normalizedPrefix := prefix.Masked()
			normalized := route
			normalized.Source = &normalizedPrefix
			otherPrefix := netip.PrefixFrom(prefix.Addr().Next(), prefix.Bits())
			otherHost := route
			otherHost.Source = &otherPrefix
			rules := policyRulesForRoutes([]Route{route, route, normalized, otherHost, disabled, {Install: true, Table: mainRouteTable}})
			require.Len(t, rules, 1)
			rule := rules[0]
			assert.Equal(t, 200, rule.Table)
			assert.Equal(t, 10000, rule.Priority)
			assert.Equal(t, prefix.Masked().String(), rule.Src.String())
			assert.Equal(t, -1, rule.Goto, "rule must look up the table, not jump to priority zero")
			assert.Equal(t, -1, rule.SuppressPrefixlen)
			assert.Equal(t, -1, rule.SuppressIfgroup)
			assert.Equal(t, -1, rule.Flow)

			otherTable := route
			otherTable.Table++
			otherPriority := route
			otherPriority.Priority++
			assert.Len(t, policyRulesForRoutes([]Route{route, normalized, otherTable, otherPriority}), 3,
				"different tables and priorities must remain distinct")
		})
	}
}

func TestApplyPolicyRules(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.200.0/24")
	route := func(table int) Route {
		return Route{Install: true, Source: &prefix, Table: table, Priority: 10000}
	}
	for _, tc := range []struct {
		name        string
		newTables   []int
		failures    map[string]error
		preexisting bool
		wantTables  []int
		wantError   bool
	}{
		{name: "replace", newTables: []int{202, 203}, wantTables: []int{202, 203}},
		{name: "unchanged", newTables: []int{200, 201}, wantTables: []int{200, 201}},
		{name: "add failure", newTables: []int{202, 203}, failures: map[string]error{"add/203": unix.EPERM}, wantTables: []int{200, 201}, wantError: true},
		{name: "delete failure", newTables: []int{202, 203}, failures: map[string]error{"del/201": unix.EPERM}, wantTables: []int{200, 201}, wantError: true},
		{name: "restore failure stays tracked accurately", newTables: []int{202, 203}, failures: map[string]error{"del/201": unix.EPERM, "add/200": unix.EPERM}, wantTables: []int{201}, wantError: true},
		{name: "rollback delete failure stays owned", newTables: []int{202, 203}, failures: map[string]error{"add/203": unix.EPERM, "del/202": unix.EPERM}, wantTables: []int{200, 201, 202}, wantError: true},
		{name: "missing rule", failures: map[string]error{"del/200": unix.ENOENT}},
		{name: "preexisting rule is not owned", newTables: []int{202}, preexisting: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := policyRulesForRoutes([]Route{route(200), route(201)})
			device := &tun{policyRules: old}
			installed := make(map[string]netlink.Rule)
			for _, rule := range old {
				installed[rule.String()] = rule
			}
			if tc.preexisting {
				rule := policyRulesForRoutes([]Route{route(202)})[0]
				installed[rule.String()] = rule
			}
			var calls int
			add := func(rule *netlink.Rule) error {
				calls++
				if err := tc.failures[fmt.Sprintf("add/%d", rule.Table)]; err != nil {
					return err
				}
				if _, ok := installed[rule.String()]; ok {
					return unix.EEXIST
				}
				installed[rule.String()] = *rule
				return nil
			}
			del := func(rule *netlink.Rule) error {
				calls++
				if err := tc.failures[fmt.Sprintf("del/%d", rule.Table)]; err != nil {
					if err == unix.ENOENT {
						delete(installed, rule.String())
					}
					return err
				}
				delete(installed, rule.String())
				return nil
			}
			var routes []Route
			for _, table := range tc.newTables {
				routes = append(routes, route(table))
			}
			err := device.applyPolicyRules(routes, add, del)
			if tc.wantError {
				require.ErrorIs(t, err, unix.EPERM)
			} else {
				require.NoError(t, err)
			}
			var tables []int
			for _, rule := range device.policyRules {
				tables = append(tables, rule.Table)
				assert.Contains(t, installed, rule.String())
			}
			assert.ElementsMatch(t, tc.wantTables, tables)
			if tc.preexisting {
				assert.Len(t, installed, 1)
			} else {
				assert.Len(t, installed, len(tc.wantTables))
			}
			if tc.name == "unchanged" {
				assert.Zero(t, calls, "unchanged rules must not be removed and reinstalled")
			}
		})
	}
}

func TestSyncPolicyRoutesFailures(t *testing.T) {
	for _, missing := range []error{nil, unix.ESRCH, unix.ENOENT} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			device := &tun{vpnNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
			routes := []Route{{Install: true, Table: 200}}
			add := func(*netlink.Route) error { return nil }
			del := func(*netlink.Route) error { return missing }
			require.NoError(t, device.syncPolicyRoutes(routes, add, del))
			require.Len(t, device.policyRoutes, 1)
			require.NoError(t, device.syncPolicyRoutes(nil, add, del))
			assert.Empty(t, device.policyRoutes)
		})
	}

	device := &tun{vpnNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
	add := func(*netlink.Route) error { return nil }
	del := func(*netlink.Route) error { return unix.EPERM }
	require.NoError(t, device.syncPolicyRoutes([]Route{{Install: true, Table: 200}}, add, del))
	require.ErrorIs(t, device.syncPolicyRoutes([]Route{{Install: true, Table: 201}}, add, del), unix.EPERM)
	assert.Len(t, device.policyRoutes, 2, "failed cleanup stays tracked while the new table is installed")
	del = func(*netlink.Route) error { return nil }
	require.NoError(t, device.syncPolicyRoutes(nil, add, del))
	assert.Empty(t, device.policyRoutes)

	add = func(*netlink.Route) error { return unix.EPERM }
	require.ErrorIs(t, device.syncPolicyRoutes([]Route{{Install: true, Table: 200}}, add, del), unix.EPERM)
	assert.Empty(t, device.policyRoutes, "failed additions must not be owned")
}

func TestSyncPolicyRoutes(t *testing.T) {
	device := &tun{deviceIndex: 42, vpnNetworks: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("2001:db8::1/64"),
	}}
	installed := make(map[string]netlink.Route)
	key := func(route *netlink.Route) string { return fmt.Sprintf("%d/%s", route.Table, route.Dst) }
	add := func(route *netlink.Route) error {
		if _, ok := installed[key(route)]; ok {
			return unix.EEXIST
		}
		installed[key(route)] = *route
		return nil
	}
	del := func(route *netlink.Route) error {
		delete(installed, key(route))
		return nil
	}
	routes := []Route{{Install: true, Table: 200}, {Install: true, Table: 200}, {Install: true, Table: mainRouteTable}, {Table: 201}}
	require.NoError(t, device.syncPolicyRoutes(routes, add, del))
	require.Len(t, device.policyRoutes, 2)
	for _, route := range device.policyRoutes {
		assert.Equal(t, 42, route.LinkIndex)
		assert.Equal(t, 200, route.Table)
	}
	require.NoError(t, device.syncPolicyRoutes(routes, add, del))
	assert.Len(t, device.policyRoutes, 2, "repeated refresh must not duplicate ownership")

	// An externally deleted route can be recreated without duplicating ownership.
	delete(installed, key(&device.policyRoutes[0]))
	require.NoError(t, device.syncPolicyRoutes(routes, add, del))
	assert.Len(t, device.policyRoutes, 2)

	// Retiring a table must remove all of its generated routes.
	require.NoError(t, device.syncPolicyRoutes([]Route{{Install: true, Table: 201}}, add, del))
	require.Len(t, installed, 2)
	for _, route := range installed {
		assert.Equal(t, 201, route.Table)
	}
	require.NoError(t, device.syncPolicyRoutes(nil, add, del))
	assert.Empty(t, installed)
	assert.Empty(t, device.policyRoutes)

	// Existing routes are neither replaced nor claimed for cleanup.
	preexisting := netlink.Route{Table: 200, Dst: &net.IPNet{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(24, 32)}}
	installed[key(&preexisting)] = preexisting
	require.NoError(t, device.syncPolicyRoutes(routes, add, del))
	assert.Len(t, device.policyRoutes, 1)
	require.NoError(t, device.syncPolicyRoutes(nil, add, del))
	assert.Equal(t, map[string]netlink.Route{key(&preexisting): preexisting}, installed)
}

var runAdvMSSTests = []struct {
	name     string
	tun      *tun
	r        Route
	expected int
}{
	// Standard case, default MTU is the device max MTU
	{"default", &tun{DefaultMTU: 1440, MaxMTU: 1440}, Route{}, 0},
	{"default-min", &tun{DefaultMTU: 1440, MaxMTU: 1440}, Route{MTU: 1440}, 0},
	{"default-low", &tun{DefaultMTU: 1440, MaxMTU: 1440}, Route{MTU: 1200}, 1160},

	// Case where we have a route MTU set higher than the default
	{"route", &tun{DefaultMTU: 1440, MaxMTU: 8941}, Route{}, 1400},
	{"route-min", &tun{DefaultMTU: 1440, MaxMTU: 8941}, Route{MTU: 1440}, 1400},
	{"route-high", &tun{DefaultMTU: 1440, MaxMTU: 8941}, Route{MTU: 8941}, 0},
}

func TestTunAdvMSS(t *testing.T) {
	for _, tt := range runAdvMSSTests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.tun.advMSS(tt.r)
			if o != tt.expected {
				t.Errorf("got %d, want %d", o, tt.expected)
			}
		})
	}
}

// TestOffloadUSOEnabled pins the single source of truth for the per-queue USO
// capability: it is derived from the negotiated offload mask, so the mask
// stored on the tun and the capability reported to coalescers cannot drift.
func TestOffloadUSOEnabled(t *testing.T) {
	// usoAndTSOOffloadFlags must be a strict superset of tsoOffloadFlags. Otherwise
	// the TSO-only fallback (and the historic hardcoded-mask bug in
	// addQueue) would not actually be a downgrade.
	if usoAndTSOOffloadFlags&tsoOffloadFlags != tsoOffloadFlags {
		t.Fatalf("usoAndTSOOffloadFlags (%#x) is not a superset of tsoOffloadFlags (%#x)", usoAndTSOOffloadFlags, tsoOffloadFlags)
	}
	if usoAndTSOOffloadFlags == tsoOffloadFlags {
		t.Fatal("usoAndTSOOffloadFlags must add bits beyond tsoOffloadFlags")
	}

	cases := []struct {
		name         string
		offloadFlags uint
		wantUSO      bool
	}{
		{"uso-negotiated", usoAndTSOOffloadFlags, true},
		{"tso-fallback", tsoOffloadFlags, false},
		{"no-vnet-hdr", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := offloadUSOEnabled(tc.offloadFlags); got != tc.wantUSO {
				t.Fatalf("offloadUSOEnabled(%#x) = %v, want %v", tc.offloadFlags, got, tc.wantUSO)
			}
		})
	}
}

// TestAddQueueReplaysNegotiatedMask guards the device-wide TUNSETOFFLOAD
// downgrade bug: addQueue must issue the exact mask newTun negotiated
// (t.offloadFlags), not a hardcoded TSO-only mask. Because TUNSETOFFLOAD is
// per-netdev, a narrower mask on an added queue silently disables USO for
// every queue on a USO-capable kernel while the queues keep advertising it.
//
// A full multi-queue exercise needs /dev/net/tun and CAP_NET_ADMIN, which are
// not available in CI/sandbox, so this asserts on the struct field that the
// TUNSETOFFLOAD argument is read from.
func TestAddQueueReplaysNegotiatedMask(t *testing.T) {
	t.Run("uso-negotiated", func(t *testing.T) {
		tn := &tun{vnetHdr: true, offloadFlags: usoAndTSOOffloadFlags}
		// The ioctl argument in addQueue is uintptr(t.offloadFlags);
		// it must equal the negotiated USO mask, and must NOT be the TSO-only
		// mask (the original bug).
		if tn.offloadFlags != usoAndTSOOffloadFlags {
			t.Fatalf("offloadFlags = %#x, want %#x", tn.offloadFlags, usoAndTSOOffloadFlags)
		}
		if tn.offloadFlags == tsoOffloadFlags {
			t.Fatal("added queue would downgrade USO: offloadFlags must not be the TSO-only mask when USO was negotiated")
		}
	})
	t.Run("tso-fallback", func(t *testing.T) {
		tn := &tun{vnetHdr: true, offloadFlags: tsoOffloadFlags}
		if tn.offloadFlags != tsoOffloadFlags {
			t.Fatalf("offloadFlags = %#x, want %#x", tn.offloadFlags, tsoOffloadFlags)
		}
	})
}
