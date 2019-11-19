package nebula

import (
	"net"
	"testing"

	proto "github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

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

func TestNewipandportfromudpaddr(t *testing.T) {
	blah := NewUDPAddrFromString("1.2.2.3:12345")
	meh := NewIpAndPortFromUDPAddr(*blah)
	assert.Equal(t, uint32(16908803), meh.Ip)
	assert.Equal(t, uint32(12345), meh.Port)
}

func TestNewipandportsfromudpaddrs(t *testing.T) {
	blah := NewUDPAddrFromString("1.2.2.3:12345")
	blah2 := NewUDPAddrFromString("9.9.9.9:47828")
	group := []udpAddr{*blah, *blah2}
	hah := NewIpAndPortsFromNetIps(group)
	assert.IsType(t, &[]*IpAndPort{}, hah)
	//t.Error(reflect.TypeOf(hah))

}

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
