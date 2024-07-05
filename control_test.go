package nebula

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

func TestControl_GetHostInfoByVpnIp(t *testing.T) {
	l := test.NewLogger()
	// Special care must be taken to re-use all objects provided to the hostmap and certificate in the expectedInfo object
	// To properly ensure we are not exposing core memory to the caller
	hm := newHostMap(l, netip.Prefix{})
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

	crt := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           "test",
			Ips:            []*net.IPNet{&ipNet},
			Subnets:        []*net.IPNet{},
			Groups:         []string{"default-group"},
			NotBefore:      time.Unix(1, 0),
			NotAfter:       time.Unix(2, 0),
			PublicKey:      []byte{5, 6, 7, 8},
			IsCA:           false,
			Issuer:         "the-issuer",
			InvertedGroups: map[string]struct{}{"default-group": {}},
		},
		Signature: []byte{1, 2, 1, 2, 1, 3},
	}

	remotes := NewRemoteList(nil)
	remotes.unlockedPrependV4(netip.IPv4Unspecified(), NewIp4AndPortFromNetIP(remote1.Addr(), remote1.Port()))
	remotes.unlockedPrependV6(netip.IPv4Unspecified(), NewIp6AndPortFromNetIP(remote2.Addr(), remote2.Port()))

	vpnIp, ok := netip.AddrFromSlice(ipNet.IP)
	assert.True(t, ok)

	hm.unlockedAddHostInfo(&HostInfo{
		remote:  remote1,
		remotes: remotes,
		ConnectionState: &ConnectionState{
			peerCert: crt,
		},
		remoteIndexId: 200,
		localIndexId:  201,
		vpnIp:         vpnIp,
		relayState: RelayState{
			relays:        map[netip.Addr]struct{}{},
			relayForByIp:  map[netip.Addr]*Relay{},
			relayForByIdx: map[uint32]*Relay{},
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
		vpnIp:         vpnIp2,
		relayState: RelayState{
			relays:        map[netip.Addr]struct{}{},
			relayForByIp:  map[netip.Addr]*Relay{},
			relayForByIdx: map[uint32]*Relay{},
		},
	}, &Interface{})

	c := Control{
		f: &Interface{
			hostMap: hm,
		},
		l: logrus.New(),
	}

	thi := c.GetHostInfoByVpnIp(vpnIp, false)

	expectedInfo := ControlHostInfo{
		VpnIp:                  vpnIp,
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
	assertFields(t, []string{"VpnIp", "LocalIndex", "RemoteIndex", "RemoteAddrs", "Cert", "MessageCounter", "CurrentRemote", "CurrentRelaysToMe", "CurrentRelaysThroughMe"}, thi)
	assert.EqualValues(t, &expectedInfo, thi)
	//TODO: netip.Addr reuses global memory for zone identifiers which breaks our "no reused memory check" here
	//test.AssertDeepCopyEqual(t, &expectedInfo, thi)

	// Make sure we don't panic if the host info doesn't have a cert yet
	assert.NotPanics(t, func() {
		thi = c.GetHostInfoByVpnIp(vpnIp2, false)
	})
}

func assertFields(t *testing.T, expected []string, actualStruct interface{}) {
	val := reflect.ValueOf(actualStruct).Elem()
	fields := make([]string, val.NumField())
	for i := 0; i < val.NumField(); i++ {
		fields[i] = val.Type().Field(i).Name
	}

	assert.Equal(t, expected, fields)
}
