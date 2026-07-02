//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

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

func TestGetGatewayAddr(t *testing.T) {
	v4 := net.ParseIP("10.0.0.1")
	v6 := net.ParseIP("2001:db8::1")
	v4mapped := net.ParseIP("::ffff:10.0.0.1")
	bad5 := net.IP{1, 2, 3, 4, 5} // length 5: AddrFromSlice rejects

	tests := []struct {
		name     string
		gw       net.IP
		via      netlink.Destination
		wantOK   bool
		wantAddr string // assertion only when wantOK is true
	}{
		// Path A: RTA_GATEWAY happy
		{"valid IPv4 RTA_GATEWAY", v4, nil, true, "10.0.0.1"},
		{"valid IPv6 RTA_GATEWAY", v6, nil, true, "2001:db8::1"},
		{"IPv4-mapped-IPv6 RTA_GATEWAY is unmapped on return", v4mapped, nil, true, "10.0.0.1"},

		// Path B: RTA_GATEWAY rejected, via type-assertion fails
		{"nil gw, nil via", nil, nil, false, ""},
		{"nil gw, wrong-type via (MPLSDestination)", nil, &netlink.MPLSDestination{}, false, ""},

		// Path D: RTA_GATEWAY rejected, RTA_VIA happy
		{"nil gw, valid RTA_VIA IPv4 -> fallback succeeds", nil, &netlink.Via{Addr: v4}, true, "10.0.0.1"},
		{"nil gw, valid RTA_VIA IPv6 -> fallback succeeds", nil, &netlink.Via{Addr: v6}, true, "2001:db8::1"},

		// Path C: RTA_GATEWAY rejected, RTA_VIA Addr rejected
		{"nil gw, RTA_VIA with nil Addr", nil, &netlink.Via{Addr: nil}, false, ""},
		{"nil gw, RTA_VIA with empty []byte Addr", nil, &netlink.Via{Addr: []byte{}}, false, ""},
		{"nil gw, RTA_VIA with malformed Addr (5 bytes)", nil, &netlink.Via{Addr: bad5}, false, ""},

		// Boundary: invalid gw falls through to valid RTA_VIA
		{"malformed gw (5 bytes), valid RTA_VIA falls through to D", bad5, &netlink.Via{Addr: v4}, true, "10.0.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := getGatewayAddr(tc.gw, tc.via)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantAddr, got.String())
			} else {
				assert.Equal(t, netip.Addr{}, got)
			}
		})
	}
}
