package nebula

import (
	"bytes"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
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
