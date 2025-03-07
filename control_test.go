package nebula

import (
	"net"
	"net/netip"
	"reflect"
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
			relays:         map[netip.Addr]struct{}{},
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
			relays:         map[netip.Addr]struct{}{},
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
	assert.EqualValues(t, &expectedInfo, thi)
	test.AssertDeepCopyEqual(t, &expectedInfo, thi)

	// Make sure we don't panic if the host info doesn't have a cert yet
	assert.NotPanics(t, func() {
		thi = c.GetHostInfoByVpnAddr(vpnIp2, false)
	})
}

func TestListHostMapHostsIter(t *testing.T) {
	l := logrus.New()
	hm := newHostMap(l)
	hm.preferredRanges.Store(&[]netip.Prefix{})

	hosts := []struct {
		vpnIp         netip.Addr
		remoteAddr    netip.AddrPort
		localIndexId  uint32
		remoteIndexId uint32
	}{
		{vpnIp: netip.MustParseAddr("0.0.0.2"), remoteAddr: netip.MustParseAddrPort("0.0.0.101:4445"), localIndexId: 202, remoteIndexId: 201},
		{vpnIp: netip.MustParseAddr("0.0.0.3"), remoteAddr: netip.MustParseAddrPort("0.0.0.102:4446"), localIndexId: 203, remoteIndexId: 202},
		{vpnIp: netip.MustParseAddr("0.0.0.4"), remoteAddr: netip.MustParseAddrPort("0.0.0.103:4447"), localIndexId: 204, remoteIndexId: 203},
	}

	for _, h := range hosts {
		hm.unlockedAddHostInfo(&HostInfo{
			remote: h.remoteAddr,
			ConnectionState: &ConnectionState{
				peerCert: nil,
			},
			localIndexId:  h.localIndexId,
			remoteIndexId: h.remoteIndexId,
			vpnAddrs:      []netip.Addr{h.vpnIp},
		}, &Interface{})
	}

	iter := listHostMapHostsIter(hm)
	var results []ControlHostInfo

	for h := range iter {
		results = append(results, *h)
	}

	assert.Equal(t, len(hosts), len(results), "expected number of hosts in iterator")
	for i, h := range hosts {
		assert.Equal(t, h.vpnIp, results[i].VpnAddrs[0])
		assert.Equal(t, h.localIndexId, results[i].LocalIndex)
		assert.Equal(t, h.remoteIndexId, results[i].RemoteIndex)
		assert.Equal(t, h.remoteAddr, results[i].CurrentRemote)
	}
}

func TestListHostMapIndexesIter(t *testing.T) {
	l := logrus.New()
	hm := newHostMap(l)
	hm.preferredRanges.Store(&[]netip.Prefix{})

	hosts := []struct {
		vpnIp         netip.Addr
		remoteAddr    netip.AddrPort
		localIndexId  uint32
		remoteIndexId uint32
	}{
		{vpnIp: netip.MustParseAddr("0.0.0.2"), remoteAddr: netip.MustParseAddrPort("0.0.0.101:4445"), localIndexId: 202, remoteIndexId: 201},
		{vpnIp: netip.MustParseAddr("0.0.0.3"), remoteAddr: netip.MustParseAddrPort("0.0.0.102:4446"), localIndexId: 203, remoteIndexId: 202},
		{vpnIp: netip.MustParseAddr("0.0.0.4"), remoteAddr: netip.MustParseAddrPort("0.0.0.103:4447"), localIndexId: 204, remoteIndexId: 203},
	}

	for _, h := range hosts {
		hm.unlockedAddHostInfo(&HostInfo{
			remote: h.remoteAddr,
			ConnectionState: &ConnectionState{
				peerCert: nil,
			},
			localIndexId:  h.localIndexId,
			remoteIndexId: h.remoteIndexId,
			vpnAddrs:      []netip.Addr{h.vpnIp},
		}, &Interface{})
	}

	iter := listHostMapIndexesIter(hm)
	var results []ControlHostInfo

	for h := range iter {
		results = append(results, *h)
	}

	assert.Equal(t, len(hosts), len(results), "expected number of hosts in iterator")
	for i, h := range hosts {
		assert.Equal(t, h.vpnIp, results[i].VpnAddrs[0])
		assert.Equal(t, h.localIndexId, results[i].LocalIndex)
		assert.Equal(t, h.remoteIndexId, results[i].RemoteIndex)
		assert.Equal(t, h.remoteAddr, results[i].CurrentRemote)
	}
}

func assertFields(t *testing.T, expected []string, actualStruct interface{}) {
	val := reflect.ValueOf(actualStruct).Elem()
	fields := make([]string, val.NumField())
	for i := 0; i < val.NumField(); i++ {
		fields[i] = val.Type().Field(i).Name
	}

	assert.Equal(t, expected, fields)
}
