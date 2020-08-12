package nebula

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/assert"
)

func TestControl_GetHostInfoByVpnIP(t *testing.T) {
	// Special care must be taken to re-use all objects provided to the hostmap and certificate in the expectedInfo object
	// To properly ensure we are not exposing core memory to the caller
	hm := NewHostMap("test", &net.IPNet{}, make([]*net.IPNet, 0))
	remote1 := NewUDPAddr(100, 4444)
	remote2 := NewUDPAddr(101, 4444)
	ipNet := net.IPNet{
		IP:   net.IPv4(1, 2, 3, 4),
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
	counter := uint64(0)

	remotes := []*HostInfoDest{NewHostInfoDest(remote1), NewHostInfoDest(remote2)}
	hm.Add(ip2int(ipNet.IP), &HostInfo{
		remote:  remote1,
		Remotes: remotes,
		ConnectionState: &ConnectionState{
			peerCert:       crt,
			messageCounter: &counter,
		},
		remoteIndexId: 200,
		localIndexId:  201,
		hostId:        ip2int(ipNet.IP),
	})

	c := Control{
		f: &Interface{
			hostMap: hm,
		},
		l: logrus.New(),
	}

	thi := c.GetHostInfoByVpnIP(ip2int(ipNet.IP), false)

	expectedInfo := ControlHostInfo{
		VpnIP:          net.IPv4(1, 2, 3, 4).To4(),
		LocalIndex:     201,
		RemoteIndex:    200,
		RemoteAddrs:    []udpAddr{*remote1, *remote2},
		CachedPackets:  0,
		Cert:           crt.Copy(),
		MessageCounter: 0,
		CurrentRemote:  *NewUDPAddr(100, 4444),
	}

	// Make sure we don't have any unexpected fields
	assertFields(t, []string{"VpnIP", "LocalIndex", "RemoteIndex", "RemoteAddrs", "CachedPackets", "Cert", "MessageCounter", "CurrentRemote"}, thi)
	util.AssertDeepCopyEqual(t, &expectedInfo, thi)
}

func assertFields(t *testing.T, expected []string, actualStruct interface{}) {
	val := reflect.ValueOf(actualStruct).Elem()
	fields := make([]string, val.NumField())
	for i := 0; i < val.NumField(); i++ {
		fields[i] = val.Type().Field(i).Name
	}

	assert.Equal(t, expected, fields)
}
