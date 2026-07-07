package nebula

import (
	"bytes"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControl_GetHostInfoByVpnIp(t *testing.T) {
	//TODO: CERT-V2 with multiple certificate versions we have a problem with this test
	// Some certs versions have different characteristics and each version implements their own Copy() func
	// which means this is not a good place to test for exposing memory
	l := test.NewLogger()
	// Special care must be taken to re-use all objects provided to the hostmap and certificate in the expectedInfo object
	// To properly ensure we are not exposing core memory to the caller
	hm := newHostMap(l)
	hm.preferredRanges.Store(&[]netip.Prefix{})

	remote1 := netip.MustParseAddrPort("0.0.0.100:4444")
	remote2 := netip.MustParseAddrPort("[1:2:3:4:5:6:7:8]:4444")

	ipNet := net.IPNet{
		IP:   remote1.Addr().AsSlice(),
		Mask: net.IPMask{255, 255, 255, 0},
	}

	ipNet2 := net.IPNet{
		IP:   remote2.Addr().AsSlice(),
		Mask: net.IPMask{255, 255, 255, 0},
	}

	remotes := NewRemoteList([]netip.Addr{netip.IPv4Unspecified()}, nil)
	remotes.unlockedPrependV4(netip.IPv4Unspecified(), netAddrToProtoV4AddrPort(remote1.Addr(), remote1.Port()))
	remotes.unlockedPrependV6(netip.IPv4Unspecified(), netAddrToProtoV6AddrPort(remote2.Addr(), remote2.Port()))

	vpnIp, ok := netip.AddrFromSlice(ipNet.IP)
	assert.True(t, ok)

	crt := &dummyCert{}
	hm.unlockedAddHostInfo(&HostInfo{
		remote:  remote1,
		remotes: remotes,
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{Certificate: crt},
		},
		remoteIndexId: 200,
		localIndexId:  201,
		vpnAddrs:      []netip.Addr{vpnIp},
		relayState: RelayState{
			relays:         nil,
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}, &Interface{})

	vpnIp2, ok := netip.AddrFromSlice(ipNet2.IP)
	assert.True(t, ok)

	hm.unlockedAddHostInfo(&HostInfo{
		remote:  remote1,
		remotes: remotes,
		ConnectionState: &ConnectionState{
			peerCert: nil,
		},
		remoteIndexId: 200,
		localIndexId:  201,
		vpnAddrs:      []netip.Addr{vpnIp2},
		relayState: RelayState{
			relays:         nil,
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}, &Interface{})

	c := Control{
		state: StateReady,
		f: &Interface{
			hostMap: hm,
		},
		l: test.NewLogger(),
	}

	thi := c.GetHostInfoByVpnAddr(vpnIp, false)

	expectedInfo := ControlHostInfo{
		VpnAddrs:               []netip.Addr{vpnIp},
		LocalIndex:             201,
		RemoteIndex:            200,
		RemoteAddrs:            []netip.AddrPort{remote2, remote1},
		Cert:                   crt.Copy(),
		MessageCounter:         0,
		CurrentRemote:          remote1,
		CurrentRelaysToMe:      []netip.Addr{},
		CurrentRelaysThroughMe: []netip.Addr{},
	}

	// Make sure we don't have any unexpected fields
	assertFields(t, []string{"VpnAddrs", "LocalIndex", "RemoteIndex", "RemoteAddrs", "Cert", "MessageCounter", "CurrentRemote", "CurrentRelaysToMe", "CurrentRelaysThroughMe"}, thi)
	assert.Equal(t, &expectedInfo, thi)
	test.AssertDeepCopyEqual(t, &expectedInfo, thi)

	// Make sure we don't panic if the host info doesn't have a cert yet
	assert.NotPanics(t, func() {
		thi = c.GetHostInfoByVpnAddr(vpnIp2, false)
	})
}

func assertFields(t *testing.T, expected []string, actualStruct any) {
	val := reflect.ValueOf(actualStruct).Elem()
	fields := make([]string, val.NumField())
	for i := 0; i < val.NumField(); i++ {
		fields[i] = val.Type().Field(i).Name
	}

	assert.Equal(t, expected, fields)
}

// alwaysAllowV4/V6 are check funcs that accept every entry (including nil pointers),
// letting us inject a nil *V4AddrPort/*V6AddrPort into a RemoteList's reported cache
// the same way a malformed proto message off the wire could.
func alwaysAllowV4(netip.Addr, *V4AddrPort) bool { return true }
func alwaysAllowV6(netip.Addr, *V6AddrPort) bool { return true }

// TestGetRelays_SkipsNilRelayAddrs proves GetRelays tolerates nil entries in the
// RelayVpnAddrs proto slice (which protoAddrToNetAddr would nil-deref on) and still
// returns the valid relays, including the legacy OldRelayVpnAddrs.
func TestGetRelays_SkipsNilRelayAddrs(t *testing.T) {
	good := netip.MustParseAddr("10.0.0.9")

	d := &NebulaMetaDetails{
		OldRelayVpnAddrs: []uint32{0x0a000001}, // 10.0.0.1
		RelayVpnAddrs: []*Addr{
			nil,
			netAddrToProtoAddr(good),
			nil,
		},
	}

	var relays []netip.Addr
	require.NotPanics(t, func() { relays = d.GetRelays() })

	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		good,
	}, relays)
}

// TestGetRelays_AllNil ensures an all-nil RelayVpnAddrs slice yields no relays and no panic.
func TestGetRelays_AllNil(t *testing.T) {
	d := &NebulaMetaDetails{RelayVpnAddrs: []*Addr{nil, nil}}
	var relays []netip.Addr
	require.NotPanics(t, func() { relays = d.GetRelays() })
	assert.Empty(t, relays)
}

// TestRemoteList_CopyCache_SkipsNilReported proves CopyCache skips nil reported
// pointers (v4 and v6) instead of nil-dereferencing them in protoV*AddrPortToNetAddrPort.
func TestRemoteList_CopyCache_SkipsNilReported(t *testing.T) {
	owner := netip.MustParseAddr("10.0.0.1")
	rl := NewRemoteList([]netip.Addr{owner}, nil)

	rl.unlockedSetV4(owner, owner, []*V4AddrPort{
		nil,
		newIp4AndPortFromString("1.2.3.4:5"),
		nil,
	}, alwaysAllowV4)

	rl.unlockedSetV6(owner, owner, []*V6AddrPort{
		nil,
		newIp6AndPortFromString("[1::1]:6"),
		nil,
	}, alwaysAllowV6)

	var cm *CacheMap
	require.NotPanics(t, func() { cm = rl.CopyCache() })

	c := (*cm)[owner.String()]
	require.NotNil(t, c)
	assert.ElementsMatch(t, []netip.AddrPort{
		netip.MustParseAddrPort("1.2.3.4:5"),
		netip.MustParseAddrPort("[1::1]:6"),
	}, c.Reported)
}

// TestRemoteList_Rebuild_SkipsNilReported drives unlockedCollect (via Rebuild) with
// nil reported entries and confirms only the valid addresses survive, with no panic.
func TestRemoteList_Rebuild_SkipsNilReported(t *testing.T) {
	owner := netip.MustParseAddr("10.0.0.1")
	rl := NewRemoteList([]netip.Addr{owner}, nil)

	rl.unlockedSetV4(owner, owner, []*V4AddrPort{
		nil,
		newIp4AndPortFromString("1.2.3.4:5"),
	}, alwaysAllowV4)
	rl.unlockedSetV6(owner, owner, []*V6AddrPort{
		newIp6AndPortFromString("[1::1]:6"),
		nil,
	}, alwaysAllowV6)

	require.NotPanics(t, func() { rl.Rebuild([]netip.Prefix{}) })

	assert.ElementsMatch(t, []netip.AddrPort{
		netip.MustParseAddrPort("1.2.3.4:5"),
		netip.MustParseAddrPort("[1::1]:6"),
	}, rl.addrs)
}

// newRelayControl marshals a NebulaControl the way it arrives on the wire so we can feed
// it through HandleControlMsg's unmarshal + validate path.
func newRelayControl(t *testing.T, typ NebulaControl_MessageType, from, to *Addr) []byte {
	t.Helper()
	msg := &NebulaControl{
		Type:          typ,
		RelayFromAddr: from,
		RelayToAddr:   to,
	}
	b, err := msg.Marshal()
	require.NoError(t, err)
	return b
}

// TestRelayManager_HandleControlMsg_NilRelayAddrs verifies the validation block added to
// HandleControlMsg: CreateRelay{Request,Response} carrying a nil RelayFromAddr or
// RelayToAddr are dropped with a debug log rather than nil-dereferencing downstream.
func TestRelayManager_HandleControlMsg_NilRelayAddrs(t *testing.T) {
	good := netAddrToProtoAddr(netip.MustParseAddr("10.0.0.9"))

	cases := []struct {
		name    string
		typ     NebulaControl_MessageType
		from    *Addr
		to      *Addr
		wantLog string // debug substring expected, "" == expect no drop log
	}{
		{"request nil from", NebulaControl_CreateRelayRequest, nil, good, "nil RelayFromAddr"},
		{"request nil to", NebulaControl_CreateRelayRequest, good, nil, "nil RelayToAddr"},
		{"request both nil", NebulaControl_CreateRelayRequest, nil, nil, "nil RelayFromAddr"},
		{"response nil from", NebulaControl_CreateRelayResponse, nil, good, "nil RelayFromAddr"},
		{"response nil to", NebulaControl_CreateRelayResponse, good, nil, "nil RelayToAddr"},
		// A non-relay control type is not subject to the relay-addr validation and must
		// pass through it untouched (the final switch simply no-ops on it).
		{"unrelated type nil addrs", NebulaControl_None, nil, nil, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := test.NewLoggerWithOutputAndLevel(&buf, slog.LevelDebug)
			rm := &relayManager{l: l, hostmap: newHostMap(l)}
			rm.useRelays.Store(true)

			f := &Interface{l: l}
			h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}, localIndexId: 1}

			d := newRelayControl(t, tc.typ, tc.from, tc.to)

			require.NotPanics(t, func() { rm.HandleControlMsg(h, d, f) })

			if tc.wantLog == "" {
				assert.NotContains(t, buf.String(), "nil Relay")
			} else {
				assert.Contains(t, buf.String(), tc.wantLog)
			}
		})
	}
}
