package nebula

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// establishedPeerConn records which destinations the hostmap has told it are established peers, and fails the test
// on a call that doesn't change anything, which would mean a reference count went wrong.
type establishedPeerConn struct {
	udp.NoopConn
	t     *testing.T
	mu    sync.Mutex
	peers map[netip.AddrPort]bool
}

func (c *establishedPeerConn) SetEstablishedPeer(dst netip.AddrPort, established bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	assert.NotEqual(c.t, established, c.peers[dst], "SetEstablishedPeer(%v, %v) repeated", dst, established)
	if established {
		c.peers[dst] = true
	} else {
		delete(c.peers, dst)
	}
}

func (c *establishedPeerConn) established() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []netip.AddrPort
	for dst := range c.peers {
		out = append(out, dst)
	}
	return out
}

// newEstablishedTestHostMap returns a hostmap whose conns are a recording conn and one that doesn't track peers.
func newEstablishedTestHostMap(t *testing.T) (*HostMap, *establishedPeerConn) {
	hm := newHostMap(test.NewLogger())
	hm.preferredRanges.Store(&[]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
	c := &establishedPeerConn{t: t, peers: map[netip.AddrPort]bool{}}
	hm.established = newEstablishedRemotes([]udp.Conn{c, udp.NoopConn{}})
	require.NotNil(t, hm.established)
	return hm, c
}

func newEstablishedTestHostInfo(vpnAddr netip.Addr, index uint32) *HostInfo {
	return &HostInfo{
		vpnAddrs:     []netip.Addr{vpnAddr},
		localIndexId: index,
		remotes:      NewRemoteList([]netip.Addr{vpnAddr}, nil),
	}
}

func TestNewEstablishedRemotesWithoutTrackingConns(t *testing.T) {
	assert.Nil(t, newEstablishedRemotes([]udp.Conn{udp.NoopConn{}}))
}

// A conn hears about a remote while at least one hostinfo in the main hostmap has it as its direct remote: from
// the add, through roaming and SetRemoteIfPreferred, until the last such hostinfo is deleted or retired by
// MaxHostInfosPerVpnIp. Pending and relayed hostinfos never count.
func TestHostMap_EstablishedRemotes(t *testing.T) {
	hm, c := newEstablishedTestHostMap(t)
	f := &Interface{}
	a := netip.MustParseAddr("10.0.0.1")
	r1 := netip.MustParseAddrPort("203.0.113.1:4242")
	r2 := netip.MustParseAddrPort("203.0.113.2:4242")
	r3 := netip.MustParseAddrPort("192.168.1.3:4242")

	// A pending hostinfo, as a handshake sets its remote, isn't established.
	h1 := newEstablishedTestHostInfo(a, 1)
	h1.SetRemote(r1)
	assert.Empty(t, c.established())

	// Handshake completion adds it to the main hostmap.
	hm.unlockedAddHostInfo(h1, f)
	assert.ElementsMatch(t, []netip.AddrPort{r1}, c.established())

	// A relayed tunnel has no direct remote.
	relayed := newEstablishedTestHostInfo(netip.MustParseAddr("10.0.0.2"), 2)
	hm.unlockedAddHostInfo(relayed, f)
	assert.ElementsMatch(t, []netip.AddrPort{r1}, c.established())

	// A rehandshake's new hostinfo shares the remote, which stays established until both are gone.
	h3 := newEstablishedTestHostInfo(a, 3)
	h3.SetRemote(r1)
	hm.unlockedAddHostInfo(h3, f)
	hm.DeleteHostInfo(h1)
	assert.ElementsMatch(t, []netip.AddrPort{r1}, c.established())

	// Roaming moves the reference.
	h3.SetRemote(r2)
	assert.ElementsMatch(t, []netip.AddrPort{r2}, c.established())
	require.True(t, h3.SetRemoteIfPreferred(hm, ViaSender{UdpAddr: r3}))
	assert.ElementsMatch(t, []netip.AddrPort{r3}, c.established())

	// A relayed tunnel that hears from its peer directly roams onto a direct remote.
	relayed.SetRemote(r1)
	assert.ElementsMatch(t, []netip.AddrPort{r1, r3}, c.established())
	hm.DeleteHostInfo(relayed)

	// A deleted hostinfo lets go, and a SetRemote after that changes nothing.
	hm.DeleteHostInfo(h3)
	assert.Empty(t, c.established())
	h3.SetRemote(r2)
	assert.Empty(t, c.established())
	hm.DeleteHostInfo(h3)

	// Adding past MaxHostInfosPerVpnIp retires the oldest hostinfo and its remote.
	var hs []*HostInfo
	for i := range MaxHostInfosPerVpnIp + 1 {
		h := newEstablishedTestHostInfo(a, uint32(10+i))
		h.SetRemote(netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(1000+i)))
		hm.unlockedAddHostInfo(h, f)
		hs = append(hs, h)
	}
	assert.Len(t, c.established(), MaxHostInfosPerVpnIp)
	assert.NotContains(t, c.established(), hs[0].GetRemote())
}

// Roaming on the receive path races tunnel teardown on the connection manager; whatever the order, a deleted
// hostinfo holds no reference.
func TestHostMap_EstablishedRemotesRoamRacesDelete(t *testing.T) {
	hm, c := newEstablishedTestHostMap(t)
	f := &Interface{}
	a := netip.MustParseAddr("10.0.0.1")
	for i := range 200 {
		h := newEstablishedTestHostInfo(a, uint32(i+1))
		h.SetRemote(netip.MustParseAddrPort("203.0.113.1:4242"))
		hm.Lock()
		hm.unlockedAddHostInfo(h, f)
		hm.Unlock()
		var wg sync.WaitGroup
		wg.Go(func() { h.SetRemote(netip.AddrPortFrom(netip.MustParseAddr("203.0.113.2"), uint16(i+1))) })
		wg.Go(func() { hm.DeleteHostInfo(h) })
		wg.Wait()
		require.Empty(t, c.established(), "round %d", i)
	}
}

// A hostinfo holds its reference in the first tracking hostmap it joins; another's add and delete of it change
// nothing, so neither hostmap's counts go wrong.
func TestHostMap_EstablishedRemotesSingleOwner(t *testing.T) {
	hm1, c1 := newEstablishedTestHostMap(t)
	hm2, c2 := newEstablishedTestHostMap(t)
	f := &Interface{}
	r := netip.MustParseAddrPort("203.0.113.1:4242")
	h := newEstablishedTestHostInfo(netip.MustParseAddr("10.0.0.1"), 1)
	h.SetRemote(r)

	hm1.unlockedAddHostInfo(h, f)
	hm2.unlockedAddHostInfo(h, f)
	assert.ElementsMatch(t, []netip.AddrPort{r}, c1.established())
	assert.Empty(t, c2.established())

	hm2.DeleteHostInfo(h)
	assert.Equal(t, map[netip.AddrPort]int{r: 1}, hm1.established.refs)
	assert.Empty(t, hm2.established.refs)
	assert.ElementsMatch(t, []netip.AddrPort{r}, c1.established())

	hm1.DeleteHostInfo(h)
	assert.Empty(t, hm1.established.refs)
	assert.Empty(t, hm2.established.refs)
	assert.Empty(t, c1.established())
	assert.Empty(t, c2.established())
}
