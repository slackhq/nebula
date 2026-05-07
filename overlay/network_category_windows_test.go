//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"testing"
)

func Test_parseNetworkCategory(t *testing.T) {
	cases := []struct {
		in        string
		wantCat   networkCategory
		wantApply bool
		wantErr   bool
	}{
		{"", 0, false, false},
		{"unset", 0, false, false},
		{"  UNSET  ", 0, false, false},
		{"private", networkCategoryPrivate, true, false},
		{"Private", networkCategoryPrivate, true, false},
		{"  PRIVATE  ", networkCategoryPrivate, true, false},
		{"public", networkCategoryPublic, true, false},
		{"PUBLIC", networkCategoryPublic, true, false},
		{"domain", networkCategoryDomainAuthenticated, true, false},
		{"DomainAuthenticated", networkCategoryDomainAuthenticated, true, false},
		{"garbage", 0, false, true},
		{"privates", 0, false, true},
	}
	for _, tc := range cases {
		cat, apply, err := parseNetworkCategory(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseNetworkCategory(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if cat != tc.wantCat || apply != tc.wantApply {
			t.Errorf("parseNetworkCategory(%q) = (%v, %v), want (%v, %v)", tc.in, cat, apply, tc.wantCat, tc.wantApply)
		}
	}
}

// Test_NLM_round_trip exercises every COM call path used by setNetworkCategory
// without mutating the host's network state. It validates the CLSID/IID
// constants and every vtable index by enumerating connections, fetching the
// adapter id and parent network, reading the current category, and writing it
// back unchanged.
//
// Requires Windows but does not require admin or the wintun driver. Skips if
// no network connections are available (unlikely outside of an isolated
// container).
func Test_NLM_round_trip(t *testing.T) {
	deinit, err := coInit()
	if err != nil {
		t.Fatalf("coInit: %v", err)
	}
	defer deinit()

	nlm, err := createNetworkListManager()
	if err != nil {
		t.Fatalf("createNetworkListManager: %v", err)
	}
	defer nlm.Release()

	enum, err := nlm.GetNetworkConnections()
	if err != nil {
		t.Fatalf("GetNetworkConnections: %v", err)
	}
	defer enum.Release()

	saw := 0
	for {
		conn, err := enum.Next()
		if err != nil {
			t.Fatalf("EnumNetworkConnections.Next: %v", err)
		}
		if conn == nil {
			break
		}
		saw++

		if _, err := conn.GetAdapterId(); err != nil {
			conn.Release()
			t.Fatalf("INetworkConnection.GetAdapterId: %v", err)
		}

		net, err := conn.GetNetwork()
		conn.Release()
		if err != nil {
			t.Fatalf("INetworkConnection.GetNetwork: %v", err)
		}

		cat, err := net.GetCategory()
		if err != nil {
			net.Release()
			t.Fatalf("INetwork.GetCategory: %v", err)
		}
		// Set to the current value so the host's NLM state is unchanged but
		// SetCategory's vtable slot is still validated end-to-end.
		if err := net.SetCategory(cat); err != nil {
			net.Release()
			t.Fatalf("INetwork.SetCategory(%v): %v", cat, err)
		}
		net.Release()
	}

	if saw == 0 {
		t.Skip("no NLM network connections available; skipping round-trip")
	}
}
