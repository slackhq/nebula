package nebula

import (
	"net"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

//TODO: Add a test to ensure udpAddr is copied and not reused

func TestOldIPv4Only(t *testing.T) {
	// This test ensures our new ipv6 enabled LH protobuf IpAndPorts works with the old style to enable backwards compatibility
	b := []byte{8, 129, 130, 132, 80, 16, 10}
	var m Ip4AndPort
	err := proto.Unmarshal(b, &m)
	assert.NoError(t, err)
	assert.Equal(t, "10.1.1.1", int2ip(m.GetIp()).String())
}

func TestNewLhQuery(t *testing.T) {
	myIp := net.ParseIP("192.1.1.1")
	myIpint := ip2int(myIp)

	// Generating a new lh query should work
	a := NewLhQueryByInt(myIpint)

	// The result should be a nebulameta protobuf
	assert.IsType(t, &NebulaMeta{}, a)

	// It should also Marshal fine
	b, err := proto.Marshal(a)
	assert.Nil(t, err)

	// and then Unmarshal fine
	n := &NebulaMeta{}
	err = proto.Unmarshal(b, n)
	assert.Nil(t, err)

}

func Test_lhStaticMapping(t *testing.T) {
	l := NewTestLogger()
	lh1 := "10.128.0.2"
	lh1IP := net.ParseIP(lh1)

	udpServer, _ := NewListener(l, "0.0.0.0", 0, true)

	meh := NewLightHouse(l, true, 1, []uint32{ip2int(lh1IP)}, 10, 10003, udpServer, false, 1, false)
	meh.AddRemote(ip2int(lh1IP), NewUDPAddr(lh1IP, uint16(4242)), true)
	err := meh.ValidateLHStaticEntries()
	assert.Nil(t, err)

	lh2 := "10.128.0.3"
	lh2IP := net.ParseIP(lh2)

	meh = NewLightHouse(l, true, 1, []uint32{ip2int(lh1IP), ip2int(lh2IP)}, 10, 10003, udpServer, false, 1, false)
	meh.AddRemote(ip2int(lh1IP), NewUDPAddr(lh1IP, uint16(4242)), true)
	err = meh.ValidateLHStaticEntries()
	assert.EqualError(t, err, "Lighthouse 10.128.0.3 does not have a static_host_map entry")
}

func BenchmarkLighthouseHandleRequest(b *testing.B) {
	l := NewTestLogger()
	lh1 := "10.128.0.2"
	lh1IP := net.ParseIP(lh1)

	udpServer, _ := NewListener(l, "0.0.0.0", 0, true)

	lh := NewLightHouse(l, true, 1, []uint32{ip2int(lh1IP)}, 10, 10003, udpServer, false, 1, false)

	hAddr := NewUDPAddrFromString("4.5.6.7:12345")
	hAddr2 := NewUDPAddrFromString("4.5.6.7:12346")
	lh.addrMap[3] = &ip4And6{v4: []*Ip4AndPort{
		NewIp4AndPort(hAddr.IP, uint32(hAddr.Port)),
		NewIp4AndPort(hAddr2.IP, uint32(hAddr2.Port))},
	}

	rAddr := NewUDPAddrFromString("1.2.2.3:12345")
	rAddr2 := NewUDPAddrFromString("1.2.2.3:12346")
	lh.addrMap[2] = &ip4And6{v4: []*Ip4AndPort{
		NewIp4AndPort(rAddr.IP, uint32(rAddr.Port)),
		NewIp4AndPort(rAddr2.IP, uint32(rAddr2.Port))},
	}

	mw := &mockEncWriter{}

	b.Run("notfound", func(b *testing.B) {
		lhh := lh.NewRequestHandler()
		req := &NebulaMeta{
			Type: NebulaMeta_HostQuery,
			Details: &NebulaMetaDetails{
				VpnIp:       4,
				Ip4AndPorts: nil,
			},
		}
		p, err := proto.Marshal(req)
		assert.NoError(b, err)
		for n := 0; n < b.N; n++ {
			lhh.HandleRequest(rAddr, 2, p, nil, mw)
		}
	})
	b.Run("found", func(b *testing.B) {
		lhh := lh.NewRequestHandler()
		req := &NebulaMeta{
			Type: NebulaMeta_HostQuery,
			Details: &NebulaMetaDetails{
				VpnIp:       3,
				Ip4AndPorts: nil,
			},
		}
		p, err := proto.Marshal(req)
		assert.NoError(b, err)

		for n := 0; n < b.N; n++ {
			lhh.HandleRequest(rAddr, 2, p, nil, mw)
		}
	})
}

func Test_lhRemoteAllowList(t *testing.T) {
	l := NewTestLogger()
	c := NewConfig(l)
	c.Settings["remoteallowlist"] = map[interface{}]interface{}{
		"10.20.0.0/12": false,
	}
	allowList, err := c.GetAllowList("remoteallowlist", false)
	assert.Nil(t, err)

	lh1 := "10.128.0.2"
	lh1IP := net.ParseIP(lh1)

	udpServer, _ := NewListener(l, "0.0.0.0", 0, true)

	lh := NewLightHouse(l, true, 1, []uint32{ip2int(lh1IP)}, 10, 10003, udpServer, false, 1, false)
	lh.SetRemoteAllowList(allowList)

	remote1IP := net.ParseIP("10.20.0.3")
	lh.AddRemote(ip2int(remote1IP), NewUDPAddr(remote1IP, uint16(4242)), true)
	assert.Nil(t, lh.addrMap[ip2int(remote1IP)])

	remote2IP := net.ParseIP("10.128.0.3")
	remote2UDPAddr := NewUDPAddr(remote2IP, uint16(4242))

	lh.AddRemote(ip2int(remote2IP), remote2UDPAddr, true)
	assert.Equal(t, NewIp4AndPort(remote2UDPAddr.IP, uint32(remote2UDPAddr.Port)), lh.addrMap[ip2int(remote2IP)].learnedV4[0])

	remote3IP := net.ParseIP("10.128.0.4")
	remote3UDPAddr := NewUDPAddr(remote3IP, uint16(4243))

	lh.AddRemote(ip2int(remote2IP), remote3UDPAddr, true)
	assert.Equal(t, NewIp4AndPort(remote3UDPAddr.IP, uint32(remote3UDPAddr.Port)), lh.addrMap[ip2int(remote2IP)].learnedV4[0])
	assert.Equal(t, NewIp4AndPort(remote2UDPAddr.IP, uint32(remote2UDPAddr.Port)), lh.addrMap[ip2int(remote2IP)].learnedV4[1])
}

//func NewLightHouse(amLighthouse bool, myIp uint32, ips []string, interval int, nebulaPort int, pc *udpConn, punchBack bool) *LightHouse {

/*
func TestLHQuery(t *testing.T) {
	//n := NewLhQueryByIpString("10.128.0.3")
	_, myNet, _ := net.ParseCIDR("10.128.0.0/16")
	m := NewHostMap(myNet)
	y, _ := net.ResolveUDPAddr("udp", "10.128.0.3:11111")
	m.Add(ip2int(net.ParseIP("127.0.0.1")), y)
	//t.Errorf("%s", m)
	_ = m

	_, n, _ := net.ParseCIDR("127.0.0.1/8")

	/*udpServer, err := net.ListenUDP("udp", &net.UDPAddr{Port: 10009})
	if err != nil {
		t.Errorf("%s", err)
	}

	meh := NewLightHouse(n, m, []string{"10.128.0.2"}, false, 10, 10003, 10004)
	//t.Error(m.Hosts)
	meh2, err := meh.Query(ip2int(net.ParseIP("10.128.0.3")))
	t.Error(err)
	if err != nil {
		return
	}
	t.Errorf("%s", meh2)
	t.Errorf("%s", n)
}
*/
