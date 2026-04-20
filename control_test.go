package nebula

import (
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
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
		f: &Interface{
			hostMap: hm,
		},
		l: logrus.New(),
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

func TestControl_ListHostmapHostsIter(t *testing.T) {
	c := testControlWithHostMap(t)

	expected := c.ListHostmapHosts(false)

	actual := make([]ControlHostInfo, 0)
	for host := range c.ListHostmapHostsIter(false) {
		actual = append(actual, host)
	}

	sortControlHostInfosByVpnAddrs(expected)
	sortControlHostInfosByVpnAddrs(actual)

	assert.Equal(t, expected, actual)
	test.AssertDeepCopyEqual(t, expected, actual)
}

func TestControl_ListHostmapIndexesIter(t *testing.T) {
	c := testControlWithHostMap(t)

	expected := c.ListHostmapIndexes(false)

	actual := make([]ControlHostInfo, 0)
	for host := range c.ListHostmapIndexesIter(false) {
		actual = append(actual, host)
	}

	sortControlHostInfosByLocalIndex(expected)
	sortControlHostInfosByLocalIndex(actual)

	assert.Equal(t, expected, actual)
	test.AssertDeepCopyEqual(t, expected, actual)
}

func Test_listHostMapHostsIter_YieldStopsAfterFalse(t *testing.T) {
	hl := newFakeControlHostLister(t)

	seq := listHostMapHostsIter(hl)

	yieldCalls := 0
	seq(func(host ControlHostInfo) bool {
		yieldCalls++
		return false
	})

	assert.Equal(t, 1, yieldCalls)
}

func Test_listHostMapIndexesIter_YieldStopsAfterFalse(t *testing.T) {
	hl := newFakeControlHostLister(t)

	seq := listHostMapIndexesIter(hl)

	yieldCalls := 0
	seq(func(host ControlHostInfo) bool {
		yieldCalls++
		return false
	})

	assert.Equal(t, 1, yieldCalls)
}

func TestControl_ListHostmapHostsIter_Empty(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	hm.preferredRanges.Store(&[]netip.Prefix{})

	c := Control{
		f: &Interface{hostMap: hm},
		l: logrus.New(),
	}

	var actual []ControlHostInfo
	for host := range c.ListHostmapHostsIter(false) {
		actual = append(actual, host)
	}

	assert.Empty(t, actual)
}

func TestControl_ListHostmapIndexesIter_Empty(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	hm.preferredRanges.Store(&[]netip.Prefix{})

	c := Control{
		f: &Interface{hostMap: hm},
		l: logrus.New(),
	}

	var actual []ControlHostInfo
	for host := range c.ListHostmapIndexesIter(false) {
		actual = append(actual, host)
	}

	assert.Empty(t, actual)
}

func testControlWithHostMap(t *testing.T) Control {
	t.Helper()

	l := test.NewLogger()
	hm := newHostMap(l)
	hm.preferredRanges.Store(&[]netip.Prefix{})

	remote1 := netip.MustParseAddrPort("10.0.0.1:4242")
	remote2 := netip.MustParseAddrPort("[2001:db8::1]:4242")

	remotes1 := NewRemoteList([]netip.Addr{netip.IPv4Unspecified()}, nil)
	remotes1.unlockedPrependV4(netip.IPv4Unspecified(), netAddrToProtoV4AddrPort(remote1.Addr(), remote1.Port()))
	remotes1.unlockedPrependV6(netip.IPv4Unspecified(), netAddrToProtoV6AddrPort(remote2.Addr(), remote2.Port()))

	remotes2 := NewRemoteList([]netip.Addr{netip.IPv4Unspecified()}, nil)
	remotes2.unlockedPrependV4(netip.IPv4Unspecified(), netAddrToProtoV4AddrPort(remote1.Addr(), remote1.Port()))

	vpn1 := netip.MustParseAddr("10.10.10.1")
	vpn2 := netip.MustParseAddr("10.10.10.2")

	hm.unlockedAddHostInfo(&HostInfo{
		remote:  remote1,
		remotes: remotes1,
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{Certificate: &dummyCert{}},
		},
		remoteIndexId: 101,
		localIndexId:  201,
		vpnAddrs:      []netip.Addr{vpn1},
		relayState: RelayState{
			relays:         nil,
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}, &Interface{})

	hm.unlockedAddHostInfo(&HostInfo{
		remote:  remote2,
		remotes: remotes2,
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{Certificate: &dummyCert{}},
		},
		remoteIndexId: 102,
		localIndexId:  202,
		vpnAddrs:      []netip.Addr{vpn2},
		relayState: RelayState{
			relays:         nil,
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}, &Interface{})

	return Control{
		f: &Interface{
			hostMap: hm,
		},
		l: logrus.New(),
	}
}

func sortControlHostInfosByVpnAddrs(hosts []ControlHostInfo) {
	sort.Slice(hosts, func(i, j int) bool {
		return vpnAddrsKey(hosts[i].VpnAddrs) < vpnAddrsKey(hosts[j].VpnAddrs)
	})
}

func vpnAddrsKey(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func sortControlHostInfosByLocalIndex(hosts []ControlHostInfo) {
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].LocalIndex < hosts[j].LocalIndex
	})
}

type fakeControlHostLister struct {
	hosts           []*HostInfo
	preferredRanges []netip.Prefix
}

func newFakeControlHostLister(t *testing.T) *fakeControlHostLister {
	t.Helper()

	remote1 := netip.MustParseAddrPort("10.1.0.1:4242")
	remote2 := netip.MustParseAddrPort("10.1.0.2:4242")

	remotes1 := NewRemoteList([]netip.Addr{netip.IPv4Unspecified()}, nil)
	remotes1.unlockedPrependV4(netip.IPv4Unspecified(), netAddrToProtoV4AddrPort(remote1.Addr(), remote1.Port()))

	remotes2 := NewRemoteList([]netip.Addr{netip.IPv4Unspecified()}, nil)
	remotes2.unlockedPrependV4(netip.IPv4Unspecified(), netAddrToProtoV4AddrPort(remote2.Addr(), remote2.Port()))

	return &fakeControlHostLister{
		preferredRanges: []netip.Prefix{},
		hosts: []*HostInfo{
			{
				remote:        remote1,
				remotes:       remotes1,
				remoteIndexId: 301,
				localIndexId:  401,
				vpnAddrs:      []netip.Addr{netip.MustParseAddr("172.16.0.1")},
				relayState: RelayState{
					relays:         nil,
					relayForByAddr: map[netip.Addr]*Relay{},
					relayForByIdx:  map[uint32]*Relay{},
				},
			},
			{
				remote:        remote2,
				remotes:       remotes2,
				remoteIndexId: 302,
				localIndexId:  402,
				vpnAddrs:      []netip.Addr{netip.MustParseAddr("172.16.0.2")},
				relayState: RelayState{
					relays:         nil,
					relayForByAddr: map[netip.Addr]*Relay{},
					relayForByIdx:  map[uint32]*Relay{},
				},
			},
		},
	}
}

func (f *fakeControlHostLister) QueryVpnAddr(vpnAddr netip.Addr) *HostInfo {
	for _, h := range f.hosts {
		if slices.Contains(h.vpnAddrs, vpnAddr) {
			return h
		}
	}
	return nil
}

func (f *fakeControlHostLister) ForEachIndex(each controlEach) {
	for _, h := range f.hosts {
		each(h)
	}
}

func (f *fakeControlHostLister) ForEachVpnAddr(each controlEach) {
	for _, h := range f.hosts {
		each(h)
	}
}

func (f *fakeControlHostLister) GetPreferredRanges() []netip.Prefix {
	return f.preferredRanges
}
