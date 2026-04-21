//go:build !e2e_testing
// +build !e2e_testing

package tio

import (
	"testing"

	"github.com/slackhq/nebula/overlay"
)

var runAdvMSSTests = []struct {
	name     string
	tun      *overlay.tun
	r        overlay.Route
	expected int
}{
	// Standard case, default MTU is the device max MTU
	{"default", &overlay.tun{DefaultMTU: 1440, MaxMTU: 1440}, overlay.Route{}, 0},
	{"default-min", &overlay.tun{DefaultMTU: 1440, MaxMTU: 1440}, overlay.Route{MTU: 1440}, 0},
	{"default-low", &overlay.tun{DefaultMTU: 1440, MaxMTU: 1440}, overlay.Route{MTU: 1200}, 1160},

	// Case where we have a route MTU set higher than the default
	{"route", &overlay.tun{DefaultMTU: 1440, MaxMTU: 8941}, overlay.Route{}, 1400},
	{"route-min", &overlay.tun{DefaultMTU: 1440, MaxMTU: 8941}, overlay.Route{MTU: 1440}, 1400},
	{"route-high", &overlay.tun{DefaultMTU: 1440, MaxMTU: 8941}, overlay.Route{MTU: 8941}, 0},
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
