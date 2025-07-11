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

func TestHostMap_reload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)

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
