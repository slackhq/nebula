package nebula

import (
	"bytes"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartRelaysLogDedupe verifies that repeated attempts with the same relay set drop the log
// chatter to Debug, mirroring how the normal handshake retry loop quiets down once it's already
// announced its targets.
func TestStartRelaysLogDedupe(t *testing.T) {
	vpnIp := netip.MustParseAddr("100.64.99.4")
	otherRelay := netip.MustParseAddr("100.64.99.5")

	newHH := func() *HandshakeHostInfo {
		// Use the target's own vpnIp as the "relay" so the loop body skips it without
		// touching any sender-side state. That isolates the test to the level-selection
		// behavior of the top-level "Attempt to relay through hosts" log.
		hostinfo := &HostInfo{
			vpnAddrs:     []netip.Addr{vpnIp},
			localIndexId: 1,
			remotes:      NewRemoteList([]netip.Addr{vpnIp}, nil),
		}
		hostinfo.remotes.relays = []netip.Addr{vpnIp}
		return &HandshakeHostInfo{hostinfo: hostinfo}
	}

	// Park any extra relay addresses we'll introduce mid-test in myVpnAddrsTable so the loop
	// body always skips before touching f.Handshake (which would need a real handshakeManager).
	addrTable := new(bart.Lite)
	addrTable.Insert(netip.PrefixFrom(otherRelay, otherRelay.BitLen()))
	f := &Interface{myVpnAddrsTable: addrTable}

	newRM := func(buf *bytes.Buffer) *relayManager {
		l := test.NewLoggerWithOutputAndLevel(buf, slog.LevelDebug)
		rm := &relayManager{l: l, hostmap: newHostMap(l)}
		rm.useRelays.Store(true)
		return rm
	}

	const msg = `msg="Attempt to relay through hosts"`

	t.Run("first attempt logs at Info", func(t *testing.T) {
		var buf bytes.Buffer
		rm := newRM(&buf)
		hh := newHH()
		rm.StartRelays(f, vpnIp, hh, nil)
		assert.Equal(t, []netip.Addr{vpnIp}, hh.lastRelays, "lastRelays should record the relay set we just attempted")
		assert.Contains(t, buf.String(), "level=INFO "+msg, "expected Info level on first attempt")
	})

	t.Run("repeat attempt with same relays drops to Debug", func(t *testing.T) {
		var buf bytes.Buffer
		rm := newRM(&buf)
		hh := newHH()
		rm.StartRelays(f, vpnIp, hh, nil)
		first := append([]netip.Addr(nil), hh.lastRelays...)
		buf.Reset()
		rm.StartRelays(f, vpnIp, hh, nil)
		assert.Equal(t, first, hh.lastRelays)
		assert.Contains(t, buf.String(), "level=DEBUG "+msg, "expected Debug level on identical retry")
		assert.NotContains(t, buf.String(), "level=INFO "+msg, "Info should not fire on identical retry")
	})

	t.Run("changed relay list bumps back to Info", func(t *testing.T) {
		var buf bytes.Buffer
		rm := newRM(&buf)
		hh := newHH()
		rm.StartRelays(f, vpnIp, hh, nil)
		buf.Reset()

		// The lighthouse handed us a new set this round.
		hh.hostinfo.remotes.relays = []netip.Addr{vpnIp, otherRelay}

		rm.StartRelays(f, vpnIp, hh, nil)
		assert.Equal(t, []netip.Addr{vpnIp, otherRelay}, hh.lastRelays)
		assert.Contains(t, buf.String(), "level=INFO "+msg, "expected Info when the relay list changes")
	})

	t.Run("disabled relays clears lastRelays and emits no Attempt log", func(t *testing.T) {
		var buf bytes.Buffer
		rm := newRM(&buf)
		rm.useRelays.Store(false)
		hh := newHH()
		hh.lastRelays = []netip.Addr{vpnIp}

		rm.StartRelays(f, vpnIp, hh, nil)
		assert.Nil(t, hh.lastRelays, "with relays disabled lastRelays should be cleared")
		assert.NotContains(t, buf.String(), msg, "should not log when we shortcut out")
	})
}

// TestHandleCreateRelayRequestRejectsSpoofedFrom verifies that a relay only forwards a CreateRelayRequest
// when relayFrom is the peer that sent it. Otherwise any peer could reset another host's established
// relay back to Requested, or allocate unbounded relay entries on the target's hostinfo.
func TestHandleCreateRelayRequestRejectsSpoofedFrom(t *testing.T) {
	l := test.NewLogger()
	relayAddr := netip.MustParseAddr("10.128.0.128")
	malloryAddr := netip.MustParseAddr("10.128.0.3")
	victimAddr := netip.MustParseAddr("10.128.0.1")
	targetAddr := netip.MustParseAddr("10.128.0.2")

	addrTable := new(bart.Lite)
	addrTable.Insert(netip.PrefixFrom(relayAddr, relayAddr.BitLen()))
	hm := newHostMap(l)
	f := &Interface{myVpnAddrsTable: addrTable, hostMap: hm}
	rm := &relayManager{l: l, hostmap: hm}
	rm.amRelay.Store(true)

	newRelayState := func() RelayState {
		return RelayState{relayForByAddr: map[netip.Addr]*Relay{}, relayForByIdx: map[uint32]*Relay{}}
	}
	mallory := &HostInfo{vpnAddrs: []netip.Addr{malloryAddr}, localIndexId: 1, relayState: newRelayState()}
	target := &HostInfo{
		vpnAddrs:     []netip.Addr{targetAddr},
		localIndexId: 2,
		remotes:      NewRemoteList([]netip.Addr{targetAddr}, nil),
		relayState:   newRelayState(),
	}
	target.SetRemote(netip.MustParseAddrPort("192.0.2.2:4242"))
	hm.unlockedAddHostInfo(mallory, f)
	hm.unlockedAddHostInfo(target, f)

	// The victim already has a working relay to the target through us.
	_, err := AddRelay(l, target, hm, victimAddr, nil, ForwardingType, Established)
	require.NoError(t, err)
	relaysBefore := len(hm.Relays)

	for i := range 10 {
		spoofed := netip.AddrFrom4([4]byte{10, 128, 1, byte(i)})
		for _, from := range []netip.Addr{victimAddr, spoofed} {
			rm.handleCreateRelayRequest(cert.Version2, mallory, f, &NebulaControl{
				Type:                NebulaControl_CreateRelayRequest,
				InitiatorRelayIndex: uint32(100 + i),
				RelayFromAddr:       netAddrToProtoAddr(from),
				RelayToAddr:         netAddrToProtoAddr(targetAddr),
			})
		}
	}

	r, ok := target.relayState.QueryRelayForByIp(victimAddr)
	require.True(t, ok)
	assert.Equal(t, Established, r.State, "victim's relay must not be reset by a request from another peer")
	assert.Len(t, hm.Relays, relaysBefore, "spoofed requests must not allocate relay entries")
	assert.Empty(t, mallory.relayState.CopyAllRelayFor(), "spoofed requests must not create state on the sender")
}
