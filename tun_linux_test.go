// +build !e2e_testing

package nebula

import "testing"

var runAdvMSSTests = []struct {
	name     string
	tun      Tun
	r        route
	expected int
}{
	// Standard case, default MTU is the device max MTU
	{"default", Tun{DefaultMTU: 1440, MaxMTU: 1440}, route{}, 0},
	{"default-min", Tun{DefaultMTU: 1440, MaxMTU: 1440}, route{mtu: 1440}, 0},
	{"default-low", Tun{DefaultMTU: 1440, MaxMTU: 1440}, route{mtu: 1200}, 1160},

	// Case where we have a route MTU set higher than the default
	{"route", Tun{DefaultMTU: 1440, MaxMTU: 8941}, route{}, 1400},
	{"route-min", Tun{DefaultMTU: 1440, MaxMTU: 8941}, route{mtu: 1440}, 1400},
	{"route-high", Tun{DefaultMTU: 1440, MaxMTU: 8941}, route{mtu: 8941}, 0},
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
