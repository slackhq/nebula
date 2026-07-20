package nebula

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chainIds returns the localIndexIds of the hostinfos holding addr, primary (index 0) first. It
// also validates the Hosts/moreHosts sync contract on every call so a mutation that broke it
// fails fast.
func chainIds(t *testing.T, hm *HostMap, addr netip.Addr) []uint32 {
	t.Helper()
	assertHostMapInvariants(t, hm)
	list := hm.unlockedGetHostList(addr)
	ids := make([]uint32, len(list))
	for i, h := range list {
		ids[i] = h.localIndexId
	}
	return ids
}

// assertHostMapInvariants checks the Hosts/moreHosts contract: moreHosts only holds addresses
// with 2 or more hostinfos, its first entry is always the primary in Hosts, lists never hold
// duplicates, every hostinfo in a list owns the address and is registered in Indexes, and every
// indexed hostinfo is reachable through each of its addresses.
func assertHostMapInvariants(t *testing.T, hm *HostMap) {
	t.Helper()
	for addr, list := range hm.moreHosts {
		require.GreaterOrEqualf(t, len(list), 2, "moreHosts[%s] must hold at least 2 hostinfos", addr)
		require.Samef(t, hm.Hosts[addr], list[0], "moreHosts[%s][0] must match the primary in Hosts", addr)
		seen := map[*HostInfo]bool{}
		for _, h := range list {
			require.NotNilf(t, h, "moreHosts[%s] must never hold a nil hostinfo", addr)
			require.Falsef(t, seen[h], "moreHosts[%s] holds hostinfo %d twice", addr, h.localIndexId)
			seen[h] = true
			require.Samef(t, hm.Indexes[h.localIndexId], h, "moreHosts[%s] member %d is not registered in Indexes", addr, h.localIndexId)
			require.Truef(t, slices.Contains(h.vpnAddrs, addr), "moreHosts[%s] member %d does not own the address", addr, h.localIndexId)
		}
	}
	for addr, h := range hm.Hosts {
		require.NotNilf(t, h, "Hosts[%s] must never be nil", addr)
		require.Samef(t, hm.Indexes[h.localIndexId], h, "Hosts[%s] primary %d is not registered in Indexes", addr, h.localIndexId)
		require.Truef(t, slices.Contains(h.vpnAddrs, addr), "Hosts[%s] primary (index %d) does not own the address", addr, h.localIndexId)
	}
	for idx, h := range hm.Indexes {
		require.Equalf(t, idx, h.localIndexId, "Indexes[%d] holds hostinfo with localIndexId %d", idx, h.localIndexId)
		for _, va := range h.vpnAddrs {
			require.Truef(t, slices.Contains(hm.unlockedGetHostList(va), h), "indexed hostinfo %d is missing from the list for %s", idx, va)
		}
	}
}

func TestHostMap_MakePrimary(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)

	f := &Interface{}
	a := netip.MustParseAddr("0.0.0.1")

	h1 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 1}
	h2 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 2}
	h3 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 3}
	h4 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 4}

	hm.unlockedAddHostInfo(h4, f)
	hm.unlockedAddHostInfo(h3, f)
	hm.unlockedAddHostInfo(h2, f)
	hm.unlockedAddHostInfo(h1, f)

	// Most-recently-added is primary: h1, h2, h3, h4
	assert.Equal(t, []uint32{1, 2, 3, 4}, chainIds(t, hm, a))
	assert.Equal(t, h1, hm.QueryVpnAddr(a))

	// Swap the middle to primary: h3, h1, h2, h4
	hm.MakePrimary(h3)
	assert.Equal(t, []uint32{3, 1, 2, 4}, chainIds(t, hm, a))
	assert.Equal(t, h3, hm.QueryVpnAddr(a))

	// Swap the tail to primary: h4, h3, h1, h2
	hm.MakePrimary(h4)
	assert.Equal(t, []uint32{4, 3, 1, 2}, chainIds(t, hm, a))

	// Swapping the current primary again is a no-op
	hm.MakePrimary(h4)
	assert.Equal(t, []uint32{4, 3, 1, 2}, chainIds(t, hm, a))
}

func TestHostMap_DeleteHostInfo(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)

	f := &Interface{}
	a := netip.MustParseAddr("0.0.0.1")

	h1 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 1}
	h2 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 2}
	h3 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 3}
	h4 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 4}
	h5 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 5}
	h6 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 6}

	hm.unlockedAddHostInfo(h6, f)
	hm.unlockedAddHostInfo(h5, f)
	hm.unlockedAddHostInfo(h4, f)
	hm.unlockedAddHostInfo(h3, f)
	hm.unlockedAddHostInfo(h2, f)
	hm.unlockedAddHostInfo(h1, f)

	// h6 is evicted by the MaxHostInfosPerVpnIp cap; the rest are newest-first.
	assert.Nil(t, hm.QueryIndex(h6.localIndexId))
	assert.Equal(t, []uint32{1, 2, 3, 4, 5}, chainIds(t, hm, a))

	// Delete primary; not final since siblings remain.
	assert.False(t, hm.DeleteHostInfo(h1))
	assert.Equal(t, []uint32{2, 3, 4, 5}, chainIds(t, hm, a))

	// Deleting the same hostinfo again must not report final while siblings remain and must not
	// disturb the list. The old chain code got this wrong: the first delete nil'd next/prev, so a
	// second delete looked final and wiped lighthouse state out from under the live sibling.
	assert.False(t, hm.DeleteHostInfo(h1))
	assert.Equal(t, []uint32{2, 3, 4, 5}, chainIds(t, hm, a))

	// Delete a middle node.
	assert.False(t, hm.DeleteHostInfo(h3))
	assert.Equal(t, []uint32{2, 4, 5}, chainIds(t, hm, a))

	// Delete the tail.
	assert.False(t, hm.DeleteHostInfo(h5))
	assert.Equal(t, []uint32{2, 4}, chainIds(t, hm, a))

	// Delete the head; h4 remains and becomes primary.
	assert.False(t, hm.DeleteHostInfo(h2))
	assert.Equal(t, []uint32{4}, chainIds(t, hm, a))
	assert.Equal(t, h4, hm.QueryVpnAddr(a))

	// Delete the only remaining item; final is true and the address is gone.
	assert.True(t, hm.DeleteHostInfo(h4))
	assert.Empty(t, chainIds(t, hm, a))
	assert.Nil(t, hm.QueryVpnAddr(a))

	// Deleting an already-gone hostinfo is still final; nothing holds the address anymore.
	assert.True(t, hm.DeleteHostInfo(h4))
	assert.Empty(t, chainIds(t, hm, a))
}

// TestHostMap_MakePrimary_DeletedHostInfo covers promoting a hostinfo that lost a race with
// tunnel teardown: swapPrimary and AddRelay decide to promote while holding a stale pointer and
// only take the write lock after a delete fully unlinked the hostinfo. MakePrimary must be a
// no-op, not a resurrection that installs an unmanaged primary.
func TestHostMap_MakePrimary_DeletedHostInfo(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	f := &Interface{}
	a := netip.MustParseAddr("0.0.0.1")

	h1 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 1}
	h2 := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 2}
	hm.unlockedAddHostInfo(h1, f)
	hm.unlockedAddHostInfo(h2, f)

	// h1 is fully deleted while another goroutine still holds a pointer to it.
	assert.False(t, hm.DeleteHostInfo(h1))
	assert.Equal(t, []uint32{2}, chainIds(t, hm, a))

	// The stale promote must not bring it back.
	hm.MakePrimary(h1)
	assert.Equal(t, []uint32{2}, chainIds(t, hm, a))
	assert.Equal(t, h2, hm.QueryVpnAddr(a))
	assert.Nil(t, hm.QueryIndex(h1.localIndexId))
}

// TestHostMap_QueryVpnAddrsRelayFor_NonPrimary makes sure a relay established on an older
// hostinfo is still found after a newer tunnel without relay state takes primary for the same
// address. The lookup checks the primary first and falls back to the rest of the list.
func TestHostMap_QueryVpnAddrsRelayFor_NonPrimary(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	f := &Interface{}
	relayAddr := netip.MustParseAddr("0.0.0.9")
	target := netip.MustParseAddr("0.0.0.1")

	older := &HostInfo{
		vpnAddrs:     []netip.Addr{relayAddr},
		localIndexId: 1,
		relayState: RelayState{
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}
	older.relayState.InsertRelay(target, 100, &Relay{Type: ForwardingType, State: Established, LocalIndex: 100, PeerAddr: target})
	hm.unlockedAddHostInfo(older, f)

	// The relay is found on the primary.
	h, r, err := hm.QueryVpnAddrsRelayFor([]netip.Addr{target}, relayAddr)
	require.NoError(t, err)
	assert.Equal(t, older, h)
	assert.Equal(t, uint32(100), r.LocalIndex)

	// A re-handshake with no relay state takes primary; the established relay on the older
	// hostinfo must still be found through the fallback.
	newer := &HostInfo{vpnAddrs: []netip.Addr{relayAddr}, localIndexId: 2}
	hm.unlockedAddHostInfo(newer, f)
	assert.Equal(t, []uint32{2, 1}, chainIds(t, hm, relayAddr))

	h, r, err = hm.QueryVpnAddrsRelayFor([]netip.Addr{target}, relayAddr)
	require.NoError(t, err)
	assert.Equal(t, older, h)
	assert.Equal(t, uint32(100), r.LocalIndex)

	// No hostinfo at all is a plain miss.
	_, _, err = hm.QueryVpnAddrsRelayFor([]netip.Addr{target}, netip.MustParseAddr("0.0.0.42"))
	require.Error(t, err)
}

// TestHostMap_DeleteHostInfo_MultipleVpnAddrs exercises the case where a hostinfo carries more than one
// vpnAddr and shares its next/prev chain with a live sibling. Deleting the head must not corrupt the
// sibling: every address the sibling owns has to keep pointing at it. The pre-fix code unlinked the shared
// chain once per vpnAddr, so on the first address it nil'd next/prev, and on the second address the node
// looked already-detached: it dropped the map entry instead of promoting the sibling (and tripped the
// isLastHostinfo relay teardown). See unlockedDeleteHostInfo.
func TestHostMap_DeleteHostInfo_MultipleVpnAddrs(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)

	f := &Interface{}

	a := netip.MustParseAddr("0.0.0.1")
	b := netip.MustParseAddr("0.0.0.2")

	// Two tunnels for the same peer, each reachable at both a and b.
	other := &HostInfo{vpnAddrs: []netip.Addr{a, b}, localIndexId: 1}
	head := &HostInfo{vpnAddrs: []netip.Addr{a, b}, localIndexId: 2}

	hm.unlockedAddHostInfo(other, f)
	hm.unlockedAddHostInfo(head, f)

	// head is primary for both addresses, other is next in each address's list.
	assert.Equal(t, head, hm.QueryVpnAddr(a))
	assert.Equal(t, head, hm.QueryVpnAddr(b))
	assert.Equal(t, []uint32{2, 1}, chainIds(t, hm, a))
	assert.Equal(t, []uint32{2, 1}, chainIds(t, hm, b))

	// Delete the head. other is still live, so it must become primary for BOTH addresses.
	assert.False(t, hm.DeleteHostInfo(head))
	assert.Equal(t, other, hm.QueryVpnAddr(a))
	assert.Equal(t, other, hm.QueryVpnAddr(b))
	assert.Equal(t, []uint32{1}, chainIds(t, hm, a))
	assert.Equal(t, []uint32{1}, chainIds(t, hm, b))

	// head is fully removed from the index map.
	assert.Nil(t, hm.QueryIndex(head.localIndexId))
}

// TestHostMap_DeleteHostInfo_DivergentVpnAddrs covers chained hostinfos for the same peer whose
// vpnAddrs sets differ (a re-handshake cert added a second address). Deleting the superset node
// must not promote a sibling to an address it does not own.
func TestHostMap_DeleteHostInfo_DivergentVpnAddrs(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	f := &Interface{}
	a := netip.MustParseAddr("0.0.0.1")
	b := netip.MustParseAddr("0.0.0.2")

	// sub owns only a; super (a newer handshake) owns a and b.
	sub := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 1}
	super := &HostInfo{vpnAddrs: []netip.Addr{a, b}, localIndexId: 2}
	hm.unlockedAddHostInfo(sub, f)
	hm.unlockedAddHostInfo(super, f)

	assert.Equal(t, []uint32{2, 1}, chainIds(t, hm, a))
	assert.Equal(t, []uint32{2}, chainIds(t, hm, b))

	// Delete super: a promotes to sub (which owns it); b has no remaining owner and must be
	// removed, not dangled at sub (which does not own b).
	assert.False(t, hm.DeleteHostInfo(super))
	assert.Equal(t, []uint32{1}, chainIds(t, hm, a))
	assert.Empty(t, chainIds(t, hm, b))
	assert.Equal(t, sub, hm.QueryVpnAddr(a))
	assert.Nil(t, hm.QueryVpnAddr(b))
	assert.Nil(t, hm.QueryIndex(super.localIndexId))

	// Deleting sub cleans up fully.
	assert.True(t, hm.DeleteHostInfo(sub))
	assert.Nil(t, hm.QueryVpnAddr(a))
	assertHostMapInvariants(t, hm)
}

// TestHostMap_AddDivergentOverlap covers a new hostinfo claiming addresses currently owned by two
// DIFFERENT hostinfos. The old single shared next/prev chain overwrote a pointer and orphaned one
// of them (in Indexes but unreachable via its address); independent per-address lists cannot.
func TestHostMap_AddDivergentOverlap(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	f := &Interface{}
	a := netip.MustParseAddr("0.0.0.1")
	b := netip.MustParseAddr("0.0.0.2")

	hiA := &HostInfo{vpnAddrs: []netip.Addr{a}, localIndexId: 1}
	hiP := &HostInfo{vpnAddrs: []netip.Addr{b}, localIndexId: 2}
	hm.unlockedAddHostInfo(hiA, f)
	hm.unlockedAddHostInfo(hiP, f)

	hiB := &HostInfo{vpnAddrs: []netip.Addr{a, b}, localIndexId: 3}
	hm.unlockedAddHostInfo(hiB, f)

	assert.Equal(t, []uint32{3, 1}, chainIds(t, hm, a))
	assert.Equal(t, []uint32{3, 2}, chainIds(t, hm, b))
	// hiA is still reachable via its address (not orphaned) and still indexed.
	assert.Contains(t, chainIds(t, hm, a), hiA.localIndexId)
	assert.NotNil(t, hm.QueryIndex(hiA.localIndexId))
}

// TestHostMap_MaxHostInfosPerVpnIp_MultipleVpnAddrs verifies the MaxHostInfosPerVpnIp overflow prune
// (unlockedInnerAddHostInfo calls unlockedDeleteHostInfo on the oldest node once the chain is too long)
// still behaves when hostinfos carry more than one vpnAddr. The pruned node is always the tail, so it is
// primary for none of the addresses, and both address chains must stay consistent afterwards.
func TestHostMap_MaxHostInfosPerVpnIp_MultipleVpnAddrs(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)

	f := &Interface{}

	a := netip.MustParseAddr("0.0.0.1")
	b := netip.MustParseAddr("0.0.0.2")

	// Add one more than the cap, newest last so it becomes head. Every hostinfo owns both a and b.
	hostinfos := make([]*HostInfo, 0, MaxHostInfosPerVpnIp+1)
	for i := 0; i <= MaxHostInfosPerVpnIp; i++ {
		hostinfos = append(hostinfos, &HostInfo{vpnAddrs: []netip.Addr{a, b}, localIndexId: uint32(i + 1)})
	}
	// Add oldest first (highest index in our slice) so the very first one added is the overflow victim.
	for i := len(hostinfos) - 1; i >= 0; i-- {
		hm.unlockedAddHostInfo(hostinfos[i], f)
	}

	oldest := hostinfos[len(hostinfos)-1]

	// The oldest hostinfo was pruned from both lists and the index map.
	assert.Nil(t, hm.QueryIndex(oldest.localIndexId))

	// Both addresses hold exactly MaxHostInfosPerVpnIp survivors in the same order; oldest is absent.
	require.Len(t, chainIds(t, hm, a), MaxHostInfosPerVpnIp)
	assert.Equal(t, chainIds(t, hm, a), chainIds(t, hm, b), "both addresses must list the same survivors in the same order")
	assert.NotContains(t, chainIds(t, hm, a), oldest.localIndexId)
	assert.Equal(t, hm.QueryVpnAddr(a), hm.QueryVpnAddr(b))
}

func TestHostMap_reload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(test.NewLogger())

	hm := NewHostMapFromConfig(l, c)

	toS := func(ipn []netip.Prefix) []string {
		var s []string
		for _, n := range ipn {
			s = append(s, n.String())
		}
		return s
	}

	assert.Empty(t, hm.GetPreferredRanges())

	c.ReloadConfigString("preferred_ranges: [1.1.1.0/24, 10.1.1.0/24]")
	assert.Equal(t, []string{"1.1.1.0/24", "10.1.1.0/24"}, toS(hm.GetPreferredRanges()))

	c.ReloadConfigString("preferred_ranges: [1.1.1.1/32]")
	assert.Equal(t, []string{"1.1.1.1/32"}, toS(hm.GetPreferredRanges()))
}

func TestHostMap_RelayState(t *testing.T) {
	h1 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 1}
	a1 := netip.MustParseAddr("::1")
	a2 := netip.MustParseAddr("2001::1")

	h1.relayState.InsertRelayTo(a1)
	assert.Equal(t, []netip.Addr{a1}, h1.relayState.relays)
	h1.relayState.InsertRelayTo(a2)
	assert.Equal(t, []netip.Addr{a1, a2}, h1.relayState.relays)
	// Ensure that the first relay added is the first one returned in the copy
	currentRelays := h1.relayState.CopyRelayIps()
	require.Len(t, currentRelays, 2)
	assert.Equal(t, a1, currentRelays[0])

	// Deleting the last one in the list works ok
	h1.relayState.DeleteRelay(a2)
	assert.Equal(t, []netip.Addr{a1}, h1.relayState.relays)

	// Deleting an element not in the list works ok
	h1.relayState.DeleteRelay(a2)
	assert.Equal(t, []netip.Addr{a1}, h1.relayState.relays)

	// Deleting the only element in the list works ok
	h1.relayState.DeleteRelay(a1)
	assert.Equal(t, []netip.Addr{}, h1.relayState.relays)

}
