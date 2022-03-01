package nebula

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
)

var vpnIp iputil.VpnIp

func Test_NewConnectionManagerTest(t *testing.T) {
	l := test.NewLogger()
	//_, tuncidr, _ := net.ParseCIDR("1.1.1.1/24")
	_, vpncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, localrange, _ := net.ParseCIDR("10.1.1.1/24")
	vpnIp = iputil.Ip2VpnIp(net.ParseIP("172.1.1.2"))
	preferredRanges := []*net.IPNet{localrange}

	// Very incomplete mock objects
	hostMap := NewHostMap(l, "test", vpncidr, preferredRanges)
	cs := &CertState{
		rawCertificate:      []byte{},
		privateKey:          []byte{},
		certificate:         &cert.NebulaCertificate{},
		rawCertificateNoKey: []byte{},
	}

	lh := &LightHouse{l: l, atomicStaticList: make(map[iputil.VpnIp]struct{}), atomicLighthouses: make(map[iputil.VpnIp]struct{})}
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &test.NoopTun{},
		outside:          &udp.Conn{},
		certState:        cs,
		firewall:         &Firewall{},
		lightHouse:       lh,
		handshakeManager: NewHandshakeManager(l, vpncidr, preferredRanges, hostMap, lh, &udp.Conn{}, defaultHandshakeConfig),
		l:                l,
	}
	now := time.Now()

	// Create manager
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nc := newConnectionManager(ctx, l, ifce, 5, 10)
	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)
	nc.HandleMonitorTick(now, p, nb, out)
	// Add an ip we have established a connection w/ to hostmap
	hostinfo, _ := nc.hostMap.AddVpnIp(vpnIp, nil)
	hostinfo.ConnectionState = &ConnectionState{
		certState: cs,
		H:         &noise.HandshakeState{},
	}

	// We saw traffic out to vpnIp
	nc.Out(vpnIp)
	assert.NotContains(t, nc.pendingDeletion, vpnIp)
	assert.Contains(t, nc.hostMap.Hosts, vpnIp)
	// Move ahead 5s. Nothing should happen
	next_tick := now.Add(5 * time.Second)
	nc.HandleMonitorTick(next_tick, p, nb, out)
	nc.HandleDeletionTick(next_tick)
	// Move ahead 6s. We haven't heard back
	next_tick = now.Add(6 * time.Second)
	nc.HandleMonitorTick(next_tick, p, nb, out)
	nc.HandleDeletionTick(next_tick)
	// This host should now be up for deletion
	assert.Contains(t, nc.pendingDeletion, vpnIp)
	assert.Contains(t, nc.hostMap.Hosts, vpnIp)
	// Move ahead some more
	next_tick = now.Add(45 * time.Second)
	nc.HandleMonitorTick(next_tick, p, nb, out)
	nc.HandleDeletionTick(next_tick)
	// The host should be evicted
	assert.NotContains(t, nc.pendingDeletion, vpnIp)
	assert.NotContains(t, nc.hostMap.Hosts, vpnIp)

}

func Test_NewConnectionManagerTest2(t *testing.T) {
	l := test.NewLogger()
	//_, tuncidr, _ := net.ParseCIDR("1.1.1.1/24")
	_, vpncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, localrange, _ := net.ParseCIDR("10.1.1.1/24")
	preferredRanges := []*net.IPNet{localrange}

	// Very incomplete mock objects
	hostMap := NewHostMap(l, "test", vpncidr, preferredRanges)
	cs := &CertState{
		rawCertificate:      []byte{},
		privateKey:          []byte{},
		certificate:         &cert.NebulaCertificate{},
		rawCertificateNoKey: []byte{},
	}

	lh := &LightHouse{l: l, atomicStaticList: make(map[iputil.VpnIp]struct{}), atomicLighthouses: make(map[iputil.VpnIp]struct{})}
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &test.NoopTun{},
		outside:          &udp.Conn{},
		certState:        cs,
		firewall:         &Firewall{},
		lightHouse:       lh,
		handshakeManager: NewHandshakeManager(l, vpncidr, preferredRanges, hostMap, lh, &udp.Conn{}, defaultHandshakeConfig),
		l:                l,
	}
	now := time.Now()

	// Create manager
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nc := newConnectionManager(ctx, l, ifce, 5, 10)
	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)
	nc.HandleMonitorTick(now, p, nb, out)
	// Add an ip we have established a connection w/ to hostmap
	hostinfo, _ := nc.hostMap.AddVpnIp(vpnIp, nil)
	hostinfo.ConnectionState = &ConnectionState{
		certState: cs,
		H:         &noise.HandshakeState{},
	}

	// We saw traffic out to vpnIp
	nc.Out(vpnIp)
	assert.NotContains(t, nc.pendingDeletion, vpnIp)
	assert.Contains(t, nc.hostMap.Hosts, vpnIp)
	// Move ahead 5s. Nothing should happen
	next_tick := now.Add(5 * time.Second)
	nc.HandleMonitorTick(next_tick, p, nb, out)
	nc.HandleDeletionTick(next_tick)
	// Move ahead 6s. We haven't heard back
	next_tick = now.Add(6 * time.Second)
	nc.HandleMonitorTick(next_tick, p, nb, out)
	nc.HandleDeletionTick(next_tick)
	// This host should now be up for deletion
	assert.Contains(t, nc.pendingDeletion, vpnIp)
	assert.Contains(t, nc.hostMap.Hosts, vpnIp)
	// We heard back this time
	nc.In(vpnIp)
	// Move ahead some more
	next_tick = now.Add(45 * time.Second)
	nc.HandleMonitorTick(next_tick, p, nb, out)
	nc.HandleDeletionTick(next_tick)
	// The host should be evicted
	assert.NotContains(t, nc.pendingDeletion, vpnIp)
	assert.Contains(t, nc.hostMap.Hosts, vpnIp)

}

// Check if we can disconnect the peer.
// Validate if the peer's certificate is invalid (expired, etc.)
// Disconnect only if disconnectInvalid: true is set.
func Test_NewConnectionManagerTest_DisconnectInvalid(t *testing.T) {
	now := time.Now()
	l := test.NewLogger()
	ipNet := net.IPNet{
		IP:   net.IPv4(172, 1, 1, 2),
		Mask: net.IPMask{255, 255, 255, 0},
	}
	_, vpncidr, _ := net.ParseCIDR("172.1.1.1/24")
	_, localrange, _ := net.ParseCIDR("10.1.1.1/24")
	preferredRanges := []*net.IPNet{localrange}
	hostMap := NewHostMap(l, "test", vpncidr, preferredRanges)

	// Generate keys for CA and peer's cert.
	pubCA, privCA, _ := ed25519.GenerateKey(rand.Reader)
	caCert := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      "ca",
			NotBefore: now,
			NotAfter:  now.Add(1 * time.Hour),
			IsCA:      true,
			PublicKey: pubCA,
		},
	}
	caCert.Sign(privCA)
	ncp := &cert.NebulaCAPool{
		CAs: cert.NewCAPool().CAs,
	}
	ncp.CAs["ca"] = &caCert

	pubCrt, _, _ := ed25519.GenerateKey(rand.Reader)
	peerCert := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      "host",
			Ips:       []*net.IPNet{&ipNet},
			Subnets:   []*net.IPNet{},
			NotBefore: now,
			NotAfter:  now.Add(60 * time.Second),
			PublicKey: pubCrt,
			IsCA:      false,
			Issuer:    "ca",
		},
	}
	peerCert.Sign(privCA)

	cs := &CertState{
		rawCertificate:      []byte{},
		privateKey:          []byte{},
		certificate:         &cert.NebulaCertificate{},
		rawCertificateNoKey: []byte{},
	}

	lh := &LightHouse{l: l, atomicStaticList: make(map[iputil.VpnIp]struct{}), atomicLighthouses: make(map[iputil.VpnIp]struct{})}
	ifce := &Interface{
		hostMap:           hostMap,
		inside:            &test.NoopTun{},
		outside:           &udp.Conn{},
		certState:         cs,
		firewall:          &Firewall{},
		lightHouse:        lh,
		handshakeManager:  NewHandshakeManager(l, vpncidr, preferredRanges, hostMap, lh, &udp.Conn{}, defaultHandshakeConfig),
		l:                 l,
		disconnectInvalid: true,
		caPool:            ncp,
	}

	// Create manager
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nc := newConnectionManager(ctx, l, ifce, 5, 10)
	ifce.connectionManager = nc
	hostinfo, _ := nc.hostMap.AddVpnIp(vpnIp, nil)
	hostinfo.ConnectionState = &ConnectionState{
		certState: cs,
		peerCert:  &peerCert,
		H:         &noise.HandshakeState{},
	}

	// Move ahead 45s.
	// Check if to disconnect with invalid certificate.
	// Should be alive.
	nextTick := now.Add(45 * time.Second)
	destroyed := nc.handleInvalidCertificate(nextTick, vpnIp, hostinfo)
	assert.False(t, destroyed)

	// Move ahead 61s.
	// Check if to disconnect with invalid certificate.
	// Should be disconnected.
	nextTick = now.Add(61 * time.Second)
	destroyed = nc.handleInvalidCertificate(nextTick, vpnIp, hostinfo)
	assert.True(t, destroyed)
}
