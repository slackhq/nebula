package nebula

import (
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostMap_MakePrimary(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)

	f := &Interface{}

	h1 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 1}
	h2 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 2}
	h3 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 3}
	h4 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 4}

	hm.unlockedAddHostInfo(h4, f)
	hm.unlockedAddHostInfo(h3, f)
	hm.unlockedAddHostInfo(h2, f)
	hm.unlockedAddHostInfo(h1, f)

	// Make sure we go h1 -> h2 -> h3 -> h4
	prim := hm.QueryVpnAddr(netip.MustParseAddr("0.0.0.1"))
	assert.Equal(t, h1.localIndexId, prim.localIndexId)
	assert.Equal(t, h2.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h1.localIndexId, h2.prev.localIndexId)
	assert.Equal(t, h3.localIndexId, h2.next.localIndexId)
	assert.Equal(t, h2.localIndexId, h3.prev.localIndexId)
	assert.Equal(t, h4.localIndexId, h3.next.localIndexId)
	assert.Equal(t, h3.localIndexId, h4.prev.localIndexId)
	assert.Nil(t, h4.next)

	// Swap h3/middle to primary
	hm.MakePrimary(h3)

	// Make sure we go h3 -> h1 -> h2 -> h4
	prim = hm.QueryVpnAddr(netip.MustParseAddr("0.0.0.1"))
	assert.Equal(t, h3.localIndexId, prim.localIndexId)
	assert.Equal(t, h1.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h2.localIndexId, h1.next.localIndexId)
	assert.Equal(t, h3.localIndexId, h1.prev.localIndexId)
	assert.Equal(t, h4.localIndexId, h2.next.localIndexId)
	assert.Equal(t, h1.localIndexId, h2.prev.localIndexId)
	assert.Equal(t, h2.localIndexId, h4.prev.localIndexId)
	assert.Nil(t, h4.next)

	// Swap h4/tail to primary
	hm.MakePrimary(h4)

	// Make sure we go h4 -> h3 -> h1 -> h2
	prim = hm.QueryVpnAddr(netip.MustParseAddr("0.0.0.1"))
	assert.Equal(t, h4.localIndexId, prim.localIndexId)
	assert.Equal(t, h3.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h1.localIndexId, h3.next.localIndexId)
	assert.Equal(t, h4.localIndexId, h3.prev.localIndexId)
	assert.Equal(t, h2.localIndexId, h1.next.localIndexId)
	assert.Equal(t, h3.localIndexId, h1.prev.localIndexId)
	assert.Equal(t, h1.localIndexId, h2.prev.localIndexId)
	assert.Nil(t, h2.next)

	// Swap h4 again should be no-op
	hm.MakePrimary(h4)

	// Make sure we go h4 -> h3 -> h1 -> h2
	prim = hm.QueryVpnAddr(netip.MustParseAddr("0.0.0.1"))
	assert.Equal(t, h4.localIndexId, prim.localIndexId)
	assert.Equal(t, h3.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h1.localIndexId, h3.next.localIndexId)
	assert.Equal(t, h4.localIndexId, h3.prev.localIndexId)
	assert.Equal(t, h2.localIndexId, h1.next.localIndexId)
	assert.Equal(t, h3.localIndexId, h1.prev.localIndexId)
	assert.Equal(t, h1.localIndexId, h2.prev.localIndexId)
	assert.Nil(t, h2.next)
}

func TestHostMap_DeleteHostInfo(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)

	f := &Interface{}

	h1 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 1}
	h2 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 2}
	h3 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 3}
	h4 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 4}
	h5 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 5}
	h6 := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("0.0.0.1")}, localIndexId: 6}

	hm.unlockedAddHostInfo(h6, f)
	hm.unlockedAddHostInfo(h5, f)
	hm.unlockedAddHostInfo(h4, f)
	hm.unlockedAddHostInfo(h3, f)
	hm.unlockedAddHostInfo(h2, f)
	hm.unlockedAddHostInfo(h1, f)

	// h6 should be deleted
	assert.Nil(t, h6.next)
	assert.Nil(t, h6.prev)
	h := hm.QueryIndex(h6.localIndexId)
	assert.Nil(t, h)

	// Make sure we go h1 -> h2 -> h3 -> h4 -> h5
	prim := hm.QueryVpnAddr(netip.MustParseAddr("0.0.0.1"))
	assert.Equal(t, h1.localIndexId, prim.localIndexId)
	assert.Equal(t, h2.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h1.localIndexId, h2.prev.localIndexId)
	assert.Equal(t, h3.localIndexId, h2.next.localIndexId)
	assert.Equal(t, h2.localIndexId, h3.prev.localIndexId)
	assert.Equal(t, h4.localIndexId, h3.next.localIndexId)
	assert.Equal(t, h3.localIndexId, h4.prev.localIndexId)
	assert.Equal(t, h5.localIndexId, h4.next.localIndexId)
	assert.Equal(t, h4.localIndexId, h5.prev.localIndexId)
	assert.Nil(t, h5.next)

	// Delete primary
	hm.DeleteHostInfo(h1)
	assert.Nil(t, h1.prev)
	assert.Nil(t, h1.next)

	// Make sure we go h2 -> h3 -> h4 -> h5
	prim = hm.QueryVpnAddr(netip.MustParseAddr("0.0.0.1"))
	assert.Equal(t, h2.localIndexId, prim.localIndexId)
	assert.Equal(t, h3.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h3.localIndexId, h2.next.localIndexId)
	assert.Equal(t, h2.localIndexId, h3.prev.localIndexId)
	assert.Equal(t, h4.localIndexId, h3.next.localIndexId)
	assert.Equal(t, h3.localIndexId, h4.prev.localIndexId)
	assert.Equal(t, h5.localIndexId, h4.next.localIndexId)
	assert.Equal(t, h4.localIndexId, h5.prev.localIndexId)
	assert.Nil(t, h5.next)

	// Delete in the middle
	hm.DeleteHostInfo(h3)
	assert.Nil(t, h3.prev)
	assert.Nil(t, h3.next)

	// Make sure we go h2 -> h4 -> h5
	prim = hm.QueryVpnAddr(netip.MustParseAddr("0.0.0.1"))
	assert.Equal(t, h2.localIndexId, prim.localIndexId)
	assert.Equal(t, h4.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h4.localIndexId, h2.next.localIndexId)
	assert.Equal(t, h2.localIndexId, h4.prev.localIndexId)
	assert.Equal(t, h5.localIndexId, h4.next.localIndexId)
	assert.Equal(t, h4.localIndexId, h5.prev.localIndexId)
	assert.Nil(t, h5.next)

	// Delete the tail
	hm.DeleteHostInfo(h5)
	assert.Nil(t, h5.prev)
	assert.Nil(t, h5.next)

	// Make sure we go h2 -> h4
	prim = hm.QueryVpnAddr(netip.MustParseAddr("0.0.0.1"))
	assert.Equal(t, h2.localIndexId, prim.localIndexId)
	assert.Equal(t, h4.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h4.localIndexId, h2.next.localIndexId)
	assert.Equal(t, h2.localIndexId, h4.prev.localIndexId)
	assert.Nil(t, h4.next)

	// Delete the head
	hm.DeleteHostInfo(h2)
	assert.Nil(t, h2.prev)
	assert.Nil(t, h2.next)

	// Make sure we only have h4
	prim = hm.QueryVpnAddr(netip.MustParseAddr("0.0.0.1"))
	assert.Equal(t, h4.localIndexId, prim.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Nil(t, prim.next)
	assert.Nil(t, h4.next)

	// Delete the only item
	hm.DeleteHostInfo(h4)
	assert.Nil(t, h4.prev)
	assert.Nil(t, h4.next)

	// Make sure we have nil
	prim = hm.QueryVpnAddr(netip.MustParseAddr("0.0.0.1"))
	assert.Nil(t, prim)
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

	// head is primary for both addresses, other is next in the shared chain
	assert.Equal(t, head.localIndexId, hm.QueryVpnAddr(a).localIndexId)
	assert.Equal(t, head.localIndexId, hm.QueryVpnAddr(b).localIndexId)
	assert.Equal(t, other.localIndexId, head.next.localIndexId)
	assert.Equal(t, head.localIndexId, other.prev.localIndexId)

	// Delete the head. other is still live, so it must become primary for BOTH addresses.
	hm.DeleteHostInfo(head)

	// Pre-fix: QueryVpnAddr(b) came back nil here because the second address was deleted rather than
	// promoted, leaving other unreachable at b.
	require.NotNil(t, hm.QueryVpnAddr(a))
	require.NotNil(t, hm.QueryVpnAddr(b))
	assert.Equal(t, other.localIndexId, hm.QueryVpnAddr(a).localIndexId)
	assert.Equal(t, other.localIndexId, hm.QueryVpnAddr(b).localIndexId)

	// other is now the only hostinfo in the chain
	assert.Nil(t, other.prev)
	assert.Nil(t, other.next)

	// head is fully detached
	assert.Nil(t, head.prev)
	assert.Nil(t, head.next)
	assert.Nil(t, hm.QueryIndex(head.localIndexId))
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

	// The oldest hostinfo should have been pruned and fully detached
	assert.Nil(t, oldest.next)
	assert.Nil(t, oldest.prev)
	assert.Nil(t, hm.QueryIndex(oldest.localIndexId))

	// Both addresses resolve to the same head, and that head is one of the survivors (not the pruned one)
	primA := hm.QueryVpnAddr(a)
	primB := hm.QueryVpnAddr(b)
	require.NotNil(t, primA)
	require.NotNil(t, primB)
	assert.Equal(t, primA.localIndexId, primB.localIndexId)
	assert.NotEqual(t, oldest.localIndexId, primA.localIndexId)

	// Walk the shared chain: exactly MaxHostInfosPerVpnIp survivors, no cycles, oldest absent
	seen := map[uint32]struct{}{}
	for h := primA; h != nil; h = h.next {
		_, dup := seen[h.localIndexId]
		require.False(t, dup, "cycle detected in hostinfo chain")
		seen[h.localIndexId] = struct{}{}
		if h.next != nil {
			assert.Equal(t, h.localIndexId, h.next.prev.localIndexId, "prev pointer must mirror next")
		}
	}
	assert.Len(t, seen, MaxHostInfosPerVpnIp)
	_, prunedStillPresent := seen[oldest.localIndexId]
	assert.False(t, prunedStillPresent)
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
