package nebula

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
)

func newTestLighthouse() *LightHouse {
	lh := &LightHouse{
		l:         test.NewLogger(),
		addrMap:   map[netip.Addr]*RemoteList{},
		queryChan: make(chan netip.Addr, 10),
	}
	lighthouses := map[netip.Addr]struct{}{}
	staticList := map[netip.Addr]struct{}{}

	lh.lighthouses.Store(&lighthouses)
	lh.staticList.Store(&staticList)

	return lh
}

func Test_NewConnectionManagerTest(t *testing.T) {
	l := test.NewLogger()
	//_, tuncidr, _ := net.ParseCIDR("1.1.1.1/24")
	vpncidr := netip.MustParsePrefix("172.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l, vpncidr)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		RawCertificate:      []byte{},
		PrivateKey:          []byte{},
		Certificate:         &cert.NebulaCertificate{},
		RawCertificateNoKey: []byte{},
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &test.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	// Create manager
	conf := config.NewC(l)
	punchy := NewPunchyFromConfig(l, conf)
	nc := newConnectionManagerFromConfig(l, conf, hostMap, punchy)
	nc.intf = ifce
	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	// Add an ip we have established a connection w/ to hostmap
	hostinfo := &HostInfo{
		vpnIp:         vpnIp,
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &cert.NebulaCertificate{},
		H:      &noise.HandshakeState{},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// We saw traffic out to vpnIp
	nc.Out(hostinfo)
	nc.In(hostinfo)
	assert.False(t, hostinfo.pendingDeletion.Load())
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnIp)
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.True(t, hostinfo.out.Load())
	assert.True(t, hostinfo.in.Load())

	// Do a traffic check tick, should not be pending deletion but should not have any in/out packets recorded
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.False(t, hostinfo.pendingDeletion.Load())
	assert.False(t, hostinfo.out.Load())
	assert.False(t, hostinfo.in.Load())

	// Do another traffic check tick, this host should be pending deletion now
	nc.Out(hostinfo)
	assert.True(t, hostinfo.out.Load())
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.True(t, hostinfo.pendingDeletion.Load())
	assert.False(t, hostinfo.out.Load())
	assert.False(t, hostinfo.in.Load())
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnIp)

	// Do a final traffic check tick, the host should now be removed
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.NotContains(t, nc.hostMap.Hosts, hostinfo.vpnIp)
	assert.NotContains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
}

func Test_NewConnectionManagerTest2(t *testing.T) {
	l := test.NewLogger()
	//_, tuncidr, _ := net.ParseCIDR("1.1.1.1/24")
	vpncidr := netip.MustParsePrefix("172.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l, vpncidr)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		RawCertificate:      []byte{},
		PrivateKey:          []byte{},
		Certificate:         &cert.NebulaCertificate{},
		RawCertificateNoKey: []byte{},
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &test.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	// Create manager
	conf := config.NewC(l)
	punchy := NewPunchyFromConfig(l, conf)
	nc := newConnectionManagerFromConfig(l, conf, hostMap, punchy)
	nc.intf = ifce
	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	// Add an ip we have established a connection w/ to hostmap
	hostinfo := &HostInfo{
		vpnIp:         vpnIp,
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &cert.NebulaCertificate{},
		H:      &noise.HandshakeState{},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// We saw traffic out to vpnIp
	nc.Out(hostinfo)
	nc.In(hostinfo)
	assert.True(t, hostinfo.in.Load())
	assert.True(t, hostinfo.out.Load())
	assert.False(t, hostinfo.pendingDeletion.Load())
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnIp)
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)

	// Do a traffic check tick, should not be pending deletion but should not have any in/out packets recorded
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.False(t, hostinfo.pendingDeletion.Load())
	assert.False(t, hostinfo.out.Load())
	assert.False(t, hostinfo.in.Load())

	// Do another traffic check tick, this host should be pending deletion now
	nc.Out(hostinfo)
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.True(t, hostinfo.pendingDeletion.Load())
	assert.False(t, hostinfo.out.Load())
	assert.False(t, hostinfo.in.Load())
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnIp)

	// We saw traffic, should no longer be pending deletion
	nc.In(hostinfo)
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.False(t, hostinfo.pendingDeletion.Load())
	assert.False(t, hostinfo.out.Load())
	assert.False(t, hostinfo.in.Load())
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnIp)
}

func Test_NewConnectionManager_DisconnectInactive(t *testing.T) {
	l := test.NewLogger()
	vpncidr := netip.MustParsePrefix("172.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l, vpncidr)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		RawCertificate:      []byte{},
		PrivateKey:          []byte{},
		Certificate:         &cert.NebulaCertificate{},
		RawCertificateNoKey: []byte{},
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &test.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	// Create manager
	conf := config.NewC(l)
	conf.Settings["tunnels"] = map[interface{}]interface{}{
		"drop_inactive": true,
	}
	punchy := NewPunchyFromConfig(l, conf)
	nc := newConnectionManagerFromConfig(l, conf, hostMap, punchy)
	assert.True(t, nc.dropInactive.Load())
	nc.intf = ifce

	// Add an ip we have established a connection w/ to hostmap
	hostinfo := &HostInfo{
		vpnIp:         vpnIp,
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &cert.NebulaCertificate{},
		H:      &noise.HandshakeState{},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// Do a traffic check tick, in and out should be cleared but should not be pending deletion
	nc.Out(hostinfo)
	nc.In(hostinfo)
	assert.True(t, hostinfo.out.Load())
	assert.True(t, hostinfo.in.Load())

	now := time.Now()
	decision, _, _ := nc.makeTrafficDecision(hostinfo.localIndexId, now)
	assert.Equal(t, tryRehandshake, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.pendingDeletion.Load())
	assert.False(t, hostinfo.out.Load())
	assert.False(t, hostinfo.in.Load())

	decision, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, now.Add(time.Second*5))
	assert.Equal(t, doNothing, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.pendingDeletion.Load())
	assert.False(t, hostinfo.out.Load())
	assert.False(t, hostinfo.in.Load())

	// Do another traffic check tick, should still not be pending deletion
	decision, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, now.Add(time.Second*10))
	assert.Equal(t, doNothing, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.pendingDeletion.Load())
	assert.False(t, hostinfo.out.Load())
	assert.False(t, hostinfo.in.Load())
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnIp)

	// Finally advance beyond the inactivity timeout
	decision, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, now.Add(time.Minute*10))
	assert.Equal(t, closeTunnel, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.pendingDeletion.Load())
	assert.False(t, hostinfo.out.Load())
	assert.False(t, hostinfo.in.Load())
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnIp)
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
	vpncidr := netip.MustParsePrefix("172.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}
	hostMap := newHostMap(l, vpncidr)
	hostMap.preferredRanges.Store(&preferredRanges)

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

	assert.NoError(t, caCert.Sign(cert.Curve_CURVE25519, privCA))
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
	assert.NoError(t, peerCert.Sign(cert.Curve_CURVE25519, privCA))

	cs := &CertState{
		RawCertificate:      []byte{},
		PrivateKey:          []byte{},
		Certificate:         &cert.NebulaCertificate{},
		RawCertificateNoKey: []byte{},
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &test.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
		pki:              &PKI{},
	}
	ifce.pki.cs.Store(cs)
	ifce.pki.caPool.Store(ncp)
	ifce.disconnectInvalid.Store(true)

	// Create manager
	conf := config.NewC(l)
	punchy := NewPunchyFromConfig(l, conf)
	nc := newConnectionManagerFromConfig(l, conf, hostMap, punchy)
	nc.intf = ifce
	ifce.connectionManager = nc

	hostinfo := &HostInfo{
		vpnIp: vpnIp,
		ConnectionState: &ConnectionState{
			myCert:   &cert.NebulaCertificate{},
			peerCert: &peerCert,
			H:        &noise.HandshakeState{},
		},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// Move ahead 45s.
	// Check if to disconnect with invalid certificate.
	// Should be alive.
	nextTick := now.Add(45 * time.Second)
	invalid := nc.isInvalidCertificate(nextTick, hostinfo)
	assert.False(t, invalid)

	// Move ahead 61s.
	// Check if to disconnect with invalid certificate.
	// Should be disconnected.
	nextTick = now.Add(61 * time.Second)
	invalid = nc.isInvalidCertificate(nextTick, hostinfo)
	assert.True(t, invalid)
}
