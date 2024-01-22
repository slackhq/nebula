//go:build !e2e_testing
// +build !e2e_testing

package overlay

import "testing"

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
