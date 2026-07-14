//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"testing"
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

// TestOffloadUSOEnabled pins the single source of truth for the per-queue USO
// capability: it is derived from the negotiated offload mask, so the mask
// stored on the tun and the capability reported to coalescers cannot drift.
func TestOffloadUSOEnabled(t *testing.T) {
	// usoOffloadFlags must be a strict superset of tsoOffloadFlags. Otherwise
	// the TSO-only fallback (and the historic hardcoded-mask bug in
	// addQueue) would not actually be a downgrade.
	if usoOffloadFlags&tsoOffloadFlags != tsoOffloadFlags {
		t.Fatalf("usoOffloadFlags (%#x) is not a superset of tsoOffloadFlags (%#x)", usoOffloadFlags, tsoOffloadFlags)
	}
	if usoOffloadFlags == tsoOffloadFlags {
		t.Fatal("usoOffloadFlags must add bits beyond tsoOffloadFlags")
	}

	cases := []struct {
		name         string
		offloadFlags uint
		wantUSO      bool
	}{
		{"uso-negotiated", usoOffloadFlags, true},
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
		tn := &tun{vnetHdr: true, offloadFlags: usoOffloadFlags}
		// The ioctl argument in addQueue is uintptr(t.offloadFlags);
		// it must equal the negotiated USO mask, and must NOT be the TSO-only
		// mask (the original bug).
		if tn.offloadFlags != usoOffloadFlags {
			t.Fatalf("offloadFlags = %#x, want %#x", tn.offloadFlags, usoOffloadFlags)
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
