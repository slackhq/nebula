package nebula

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

func Test_newPacket(t *testing.T) {
	p := &FirewallPacket{}

	// length fail
	err := newPacket([]byte{0, 1}, true, p)
	assert.EqualError(t, err, "packet is less than 20 bytes")

	// length fail with ip options
	h := ipv4.Header{
		Version: 1,
		Len:     100,
		Src:     net.IPv4(10, 0, 0, 1),
		Dst:     net.IPv4(10, 0, 0, 2),
		Options: []byte{0, 1, 0, 2},
	}

	b, _ := h.Marshal()
	err = newPacket(b, true, p)

	assert.EqualError(t, err, "packet is less than 28 bytes, ip header len: 24")

	// not an ipv4 packet
	err = newPacket([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true, p)
	assert.EqualError(t, err, "packet is not ipv4, type: 0")

	// invalid ihl
	err = newPacket([]byte{4<<4 | (8 >> 2 & 0x0f), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true, p)
	assert.EqualError(t, err, "packet had an invalid header length: 8")

	// account for variable ip header length - incoming
	h = ipv4.Header{
		Version:  1,
		Len:      100,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Options:  []byte{0, 1, 0, 2},
		Protocol: fwProtoTCP,
	}

	b, _ = h.Marshal()
	b = append(b, []byte{0, 3, 0, 4}...)
	err = newPacket(b, true, p)

	assert.Nil(t, err)
	assert.Equal(t, p.Protocol, uint8(fwProtoTCP))
	assert.Equal(t, p.LocalIP, ip2int(net.IPv4(10, 0, 0, 2)))
	assert.Equal(t, p.RemoteIP, ip2int(net.IPv4(10, 0, 0, 1)))
	assert.Equal(t, p.RemotePort, uint16(3))
	assert.Equal(t, p.LocalPort, uint16(4))

	// account for variable ip header length - outgoing
	h = ipv4.Header{
		Version:  1,
		Protocol: 2,
		Len:      100,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Options:  []byte{0, 1, 0, 2},
	}

	b, _ = h.Marshal()
	b = append(b, []byte{0, 5, 0, 6}...)
	err = newPacket(b, false, p)

	assert.Nil(t, err)
	assert.Equal(t, p.Protocol, uint8(2))
	assert.Equal(t, p.LocalIP, ip2int(net.IPv4(10, 0, 0, 1)))
	assert.Equal(t, p.RemoteIP, ip2int(net.IPv4(10, 0, 0, 2)))
	assert.Equal(t, p.RemotePort, uint16(6))
	assert.Equal(t, p.LocalPort, uint16(5))
}

func BenchmarkOutsideHotPath(b *testing.B) {
	l.SetLevel(logrus.WarnLevel)
	pHeader, _ := hex.DecodeString(
		// IP packet, 192.168.0.120 -> 192.168.0.1
		// UDP packet, port 52228 -> 9999
		// body: all zeros, total length 1500
		"450005dc75ad400040113d9ac0a80078c0a80001" + "cc04270f05c87f80",
	)

	packet := make([]byte, mtu)

	copy(packet[0:], pHeader)
	myIp, myNet, _ := net.ParseCIDR("192.168.0.1/24")
	myIpNet := &net.IPNet{
		IP:   myIp,
		Mask: myNet.Mask,
	}
	_, localToMe, _ := net.ParseCIDR("10.0.0.1/8")
	myIpNets := []*net.IPNet{myIpNet}
	preferredRanges := []*net.IPNet{localToMe}

	c := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           "host1",
			Ips:            myIpNets,
			InvertedGroups: map[string]struct{}{"default-group": {}, "test-group": {}},
		},
	}
	fw := NewFirewall(time.Second, time.Minute, time.Hour, &c)
	require.NoError(b, fw.AddRule(true, fwProtoAny, 0, 0, []string{"any"}, "", nil, "", ""))

	hostMap := NewHostMap("main", myIpNet, preferredRanges)
	hostMap.AddRemote(ip2int(net.ParseIP("192.168.0.120")), NewUDPAddrFromString("127.0.0.1:9"))
	info, _ := hostMap.QueryVpnIP(ip2int(net.ParseIP("192.168.0.120")))
	var mc uint64
	mc = 1
	info.ConnectionState = &ConnectionState{
		ready:          true,
		messageCounter: &mc,
		window:         NewBits(ReplayWindow),
	}
	info.HandshakeReady = true
	// Clear out bit 0, we never transmit it and we don't want it showing as packet loss
	info.ConnectionState.window.Update(0)

	tun := &dropTun{}

	hostMap.AddIndexHostInfo(info.remoteIndexId, info)
	ifce := &Interface{
		hostMap:    hostMap,
		firewall:   fw,
		lightHouse: &LightHouse{},
		inside:     tun,
	}
	ifce.connectionManager = newConnectionManager(ifce, 300, 300)

	udpAddr := NewUDPAddrFromString("127.0.0.1:9")
	plaintext := make([]byte, mtu)
	buffer := make([]byte, mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	nb := make([]byte, 12, 12)

	b.Run("AESGCM", func(b *testing.B) {
		eKey := testHotPathCipherState(b, noise.CipherAESGCM)
		info.ConnectionState.dKey = eKey
		info.ConnectionState.window.current = 0

		var err error

		// Encrypt the test payload
		buffer = HeaderEncode(buffer, Version, uint8(message), 0, info.remoteIndexId, 1)
		buffer, err = eKey.EncryptDanger(buffer, buffer, packet[:1500], 1, nb)
		require.NoError(b, err)

		// Prep the hot path, add to conntrack
		ifce.readOutsidePackets(udpAddr, plaintext[:0], buffer, header, fwPacket, nb)

		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			info.ConnectionState.window.current = 0
			ifce.readOutsidePackets(udpAddr, plaintext[:0], buffer, header, fwPacket, nb)
		}
		b.SetBytes(1500)
	})

	b.Run("ChaChaPoly", func(b *testing.B) {
		eKey := testHotPathCipherState(b, noise.CipherChaChaPoly)
		info.ConnectionState.dKey = eKey
		info.ConnectionState.window.current = 0

		var err error

		// Encrypt the test payload
		buffer = HeaderEncode(buffer, Version, uint8(message), 0, info.remoteIndexId, 1)
		buffer, err = eKey.EncryptDanger(buffer, buffer, packet[:1500], 1, nb)
		require.NoError(b, err)

		// Prep the hot path, add to conntrack
		ifce.readOutsidePackets(udpAddr, plaintext[:0], buffer, header, fwPacket, nb)

		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			info.ConnectionState.window.current = 0
			ifce.readOutsidePackets(udpAddr, plaintext[:0], buffer, header, fwPacket, nb)
		}
		b.SetBytes(1500)
	})
}

// Drop all outgoing packets, for Benchmark test
type dropTun struct{}

func (dropTun) Read(p []byte) (n int, err error)  { return 0, nil }
func (dropTun) Write(p []byte) (n int, err error) { return len(p), nil }
func (dropTun) Close() error                      { return nil }
func (dropTun) Activate() error                   { return nil }
func (dropTun) CidrNet() *net.IPNet               { return nil }
func (dropTun) DeviceName() string                { return "dropTun" }
func (dropTun) WriteRaw([]byte) error             { return nil }
