// +build linux

package nebula

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func BenchmarkInsideHotPath(b *testing.B) {
	l.SetLevel(logrus.WarnLevel)
	header, _ := hex.DecodeString(
		// IP packet, 192.168.0.120 -> 192.168.0.1
		// UDP packet, port 52228 -> 9999
		// body: all zeros, total length 1500
		"450005dc75ad400040113d9ac0a80078c0a80001" + "cc04270f05c87f80",
	)

	packet := make([]byte, mtu)
	copy(packet[0:], header)

	fwPacket := &FirewallPacket{}

	out := make([]byte, mtu)
	nb := make([]byte, 12, 12)

	myIp, myNet, _ := net.ParseCIDR("192.168.0.120/24")
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
	require.NoError(b, fw.AddRule(false, fwProtoAny, 0, 0, []string{"any"}, "", nil, "", ""))

	// We have to actually create a udp socket, since udpServer is not an interface
	udpServer, err := NewListener("127.0.0.1", 0, false)
	require.NoError(b, err)

	// We aren't going to read, so set the smallest recv buffer size so everything gets dropped
	require.NoError(b, unix.SetsockoptInt(udpServer.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUF, 0))

	uPort, err := udpServer.LocalAddr()
	require.NoError(b, err)

	hostMap := NewHostMap("main", myIpNet, preferredRanges)
	// TODO should we send to port 9 (discard protocol) instead of ourselves?
	// Sending to :9 seems to slow down the test since another service on the
	// box has to recv the messages. If we just send to ourselves, the packets
	// just fill the buffer and get thrown away.
	hostMap.AddRemote(ip2int(net.ParseIP("192.168.0.1")), NewUDPAddrFromString(fmt.Sprintf("127.0.0.1:%d", uPort.Port)))
	info, _ := hostMap.QueryVpnIP(ip2int(net.ParseIP("192.168.0.1")))
	var mc uint64
	info.ConnectionState = &ConnectionState{
		ready:          true,
		messageCounter: &mc,
	}
	info.HandshakeReady = true

	ifce := &Interface{
		hostMap:    hostMap,
		firewall:   fw,
		lightHouse: &LightHouse{},
		outside:    udpServer,
	}
	ifce.connectionManager = newConnectionManager(ifce, 300, 300)

	packet = packet[:1500]

	b.Run("AESGCM", func(b *testing.B) {
		info.ConnectionState.eKey = testHotPathCipherState(b, noise.CipherAESGCM)

		// Prep the hot path, add to conntrack
		ifce.consumeInsidePacket(packet, fwPacket, nb, out)

		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			ifce.consumeInsidePacket(packet, fwPacket, nb, out)
		}
		b.SetBytes(1500)
	})
	b.Run("ChaChaPoly", func(b *testing.B) {
		info.ConnectionState.eKey = testHotPathCipherState(b, noise.CipherChaChaPoly)

		// Prep the hot path, add to conntrack
		ifce.consumeInsidePacket(packet, fwPacket, nb, out)

		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			ifce.consumeInsidePacket(packet, fwPacket, nb, out)
		}
		b.SetBytes(1500)
	})
}

func testHotPathCipherState(t testing.TB, c noise.CipherFunc) *NebulaCipherState {
	cs := noise.NewCipherSuite(noise.DH25519, c, noise.HashSHA256)
	rng := rand.Reader
	staticR, _ := cs.GenerateKeypair(rng)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Random:      rng,
		Pattern:     noise.HandshakeN,
		Initiator:   true,
		PeerStatic:  staticR.Public,
	})
	require.NoError(t, err)

	_, eKey, _, err := hs.WriteMessage(nil, nil)
	require.NoError(t, err)

	return NewNebulaCipherState(eKey)
}
