//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

func TestValidateTunName(t *testing.T) {
	// A device name must be shorter than IFNAMSIZ (i.e. IFNAMSIZ-1 chars max).
	maxLenName := strings.Repeat("a", unix.IFNAMSIZ-1)

	tests := []struct {
		name    string
		tmpl    string
		wantErr bool
	}{
		{"short literal name is fine", "nebula1", false},
		{"literal name at the max length is fine", maxLenName, false},
		{"literal name at IFNAMSIZ is rejected", strings.Repeat("a", unix.IFNAMSIZ), true},
		{"trailing template is fine", "nebula%d", false},
		{"mid-string template is fine", "neb%dprod", false},
		{"leading template is fine", "%dnebula", false},
		{"template at the max length is fine", strings.Repeat("a", unix.IFNAMSIZ-3) + "%d", false},
		{"template at IFNAMSIZ is rejected", strings.Repeat("a", unix.IFNAMSIZ-2) + "%d", true},
		{"bare %d is rejected", "%d", true},
		{"multiple %d is rejected", "neb%d%dprod", true},
		{"over-long template is rejected", strings.Repeat("a", unix.IFNAMSIZ-1) + "%d", true},
		{"over-long mid-string template is rejected", "neb%d" + strings.Repeat("a", unix.IFNAMSIZ-3), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTunName(tt.tmpl)
			if tt.wantErr && err == nil {
				t.Fatalf("expected an error for %q, got none", tt.tmpl)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.tmpl, err)
			}
		})
	}
}
