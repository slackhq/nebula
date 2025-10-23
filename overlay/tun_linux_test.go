//go:build !e2e_testing
// +build !e2e_testing

package overlay

import "testing"

var runAdvMSSTests = []struct {
	name       string
	defaultMTU int
	maxMTU     int
	r          Route
	expected   int
}{
	// Standard case, default MTU is the device max MTU
	{"default", 1440, 1440, Route{}, 0},
	{"default-min", 1440, 1440, Route{MTU: 1440}, 0},
	{"default-low", 1440, 1440, Route{MTU: 1200}, 1160},

	// Case where we have a route MTU set higher than the default
	{"route", 1440, 8941, Route{}, 1400},
	{"route-min", 1440, 8941, Route{MTU: 1440}, 1400},
	{"route-high", 1440, 8941, Route{MTU: 8941}, 0},
}

func TestTunAdvMSS(t *testing.T) {
	for _, tt := range runAdvMSSTests {
		t.Run(tt.name, func(t *testing.T) {
			o := advMSS(tt.r, tt.defaultMTU, tt.maxMTU)
			if o != tt.expected {
				t.Errorf("got %d, want %d", o, tt.expected)
			}
		})
	}
}
