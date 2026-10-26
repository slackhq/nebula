package nebula

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/overlaytest"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLighthouse() *LightHouse {
	lh := &LightHouse{
		l:         test.NewLogger(),
		addrMap:   map[netip.Addr]*RemoteList{},
		queryChan: make(chan netip.Addr, 10),
		// Nothing drains queryChan here, so an 11th query is dropped.
		queryDropped: metrics.NilCounter{},
	}
	lighthouses := []netip.Addr{}
	staticList := map[netip.Addr]struct{}{}

	lh.localAddrsFn = func(*LocalAllowList) []netip.Addr { return nil }
	lh.lighthouses.Store(&lighthouses)
	lh.staticList.Store(&staticList)

	return lh
}

func Test_NewConnectionManagerTest(t *testing.T) {
	l := test.NewLogger()
	//_, tuncidr, _ := net.ParseCIDR("1.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	// Create manager
	conf := config.NewC(test.NewLogger())
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	nc.intf = ifce
	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	// Add an ip we have established a connection w/ to hostmap
	hostinfo := &HostInfo{
		vpnAddrs:      []netip.Addr{vpnIp},
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &dummyCert{version: cert.Version1},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// We saw traffic out to vpnIp
	nc.Out(hostinfo)
	nc.In(hostinfo)
	assert.False(t, hostinfo.isPendingDeletion())
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.True(t, hostinfo.sentSinceCheck())
	assert.True(t, (hostinfo.state.Load()&stateIn != 0))

	// Do a traffic check tick, should not be pending deletion but should not have any in/out packets recorded
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))

	// Do another traffic check tick, this host should be pending deletion now
	nc.Out(hostinfo)
	assert.True(t, hostinfo.sentSinceCheck())
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.True(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])

	// Do a final traffic check tick, the host should now be removed
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.NotContains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs)
	assert.NotContains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
}

func Test_NewConnectionManagerTest2(t *testing.T) {
	l := test.NewLogger()
	//_, tuncidr, _ := net.ParseCIDR("1.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	// Create manager
	conf := config.NewC(test.NewLogger())
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	nc.intf = ifce
	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	// Add an ip we have established a connection w/ to hostmap
	hostinfo := &HostInfo{
		vpnAddrs:      []netip.Addr{vpnIp},
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &dummyCert{version: cert.Version1},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// We saw traffic out to vpnIp
	nc.Out(hostinfo)
	nc.In(hostinfo)
	assert.True(t, (hostinfo.state.Load()&stateIn != 0))
	assert.True(t, hostinfo.sentSinceCheck())
	assert.False(t, hostinfo.isPendingDeletion())
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)

	// Do a traffic check tick, should not be pending deletion but should not have any in/out packets recorded
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))

	// Do another traffic check tick, this host should be pending deletion now
	nc.Out(hostinfo)
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.True(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])

	// We saw traffic, should no longer be pending deletion
	nc.In(hostinfo)
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])
}

func Test_NewConnectionManager_CounterLimits(t *testing.T) {
	l := test.NewLogger()
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		myVpnAddrs:       []netip.Addr{netip.MustParseAddr("172.1.1.1")}, // sorts below vpnIp so shouldSwapPrimary can proceed
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	conf := config.NewC(test.NewLogger())
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	nc.intf = ifce

	hostinfo := &HostInfo{
		vpnAddrs:      []netip.Addr{vpnIp},
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &dummyCert{version: cert.Version1},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// Below the rehandshake threshold, no handshake is started
	hostinfo.ConnectionState.messageCounter.Store(RehandshakeAfterMessages - 1)
	nc.tryRehandshake(hostinfo)
	assert.Nil(t, ifce.handshakeManager.QueryVpnAddr(vpnIp))

	// A tunnel on its current cert would normally swap to primary
	assert.True(t, nc.shouldSwapPrimary(hostinfo))

	// At the rehandshake threshold, a new handshake is started
	hostinfo.ConnectionState.messageCounter.Store(RehandshakeAfterMessages)
	nc.tryRehandshake(hostinfo)
	assert.NotNil(t, ifce.handshakeManager.QueryVpnAddr(vpnIp))

	// An exhausted tunnel being rolled must never swap back to primary onto its spent key
	assert.False(t, nc.shouldSwapPrimary(hostinfo))

	// Still below the reject limit, the tunnel stays up
	nc.In(hostinfo)
	decision, _, _, _ := nc.makeTrafficDecision(hostinfo.localIndexId, time.Now())
	assert.Equal(t, tryRehandshake, decision)

	// At the reject limit, the tunnel is deleted locally without a doomed CloseTunnel notify
	hostinfo.ConnectionState.messageCounter.Store(RejectAfterMessages)
	decision, _, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, time.Now())
	assert.Equal(t, deleteTunnel, decision)
}

func Test_NewConnectionManager_DisconnectInactive(t *testing.T) {
	l := test.NewLogger()
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnAddrs := []netip.Addr{netip.MustParseAddr("172.1.1.2")}
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	// Create manager
	conf := config.NewC(test.NewLogger())
	conf.Settings["tunnels"] = map[string]any{
		"drop_inactive": true,
	}
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	assert.True(t, nc.dropInactive.Load())
	nc.intf = ifce

	// Add an ip we have established a connection w/ to hostmap
	hostinfo := &HostInfo{
		vpnAddrs:      vpnAddrs,
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &dummyCert{version: cert.Version1},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// Do a traffic check tick, in and out should be cleared but should not be pending deletion
	nc.Out(hostinfo)
	nc.In(hostinfo)
	assert.True(t, hostinfo.sentSinceCheck())
	assert.True(t, (hostinfo.state.Load()&stateIn != 0))

	now := time.Now()
	decision, _, _, _ := nc.makeTrafficDecision(hostinfo.localIndexId, now)
	assert.Equal(t, tryRehandshake, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))

	decision, _, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, now.Add(time.Second*5))
	assert.Equal(t, doNothing, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))

	// Do another traffic check tick, should still not be pending deletion
	decision, _, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, now.Add(time.Second*10))
	assert.Equal(t, doNothing, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])

	// Finally advance beyond the inactivity timeout
	decision, _, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, now.Add(time.Minute*10))
	assert.Equal(t, closeTunnel, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])
}

// Check if we can disconnect the peer.
// Validate if the peer's certificate is invalid (expired, etc.)
// Disconnect only if disconnectInvalid: true is set.
func Test_NewConnectionManagerTest_DisconnectInvalid(t *testing.T) {
	now := time.Now()
	l := test.NewLogger()

	vpncidr := netip.MustParsePrefix("172.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	// Generate keys for CA and peer's cert.
	pubCA, privCA, _ := ed25519.GenerateKey(rand.Reader)
	tbs := &cert.TBSCertificate{
		Version:   1,
		Name:      "ca",
		IsCA:      true,
		NotBefore: now,
		NotAfter:  now.Add(1 * time.Hour),
		PublicKey: pubCA,
	}

	caCert, err := tbs.Sign(nil, cert.Curve_CURVE25519, privCA)
	require.NoError(t, err)
	ncp := cert.NewCAPool()
	require.NoError(t, ncp.AddCA(caCert))

	pubCrt, _, _ := ed25519.GenerateKey(rand.Reader)
	tbs = &cert.TBSCertificate{
		Version:   1,
		Name:      "host",
		Networks:  []netip.Prefix{vpncidr},
		NotBefore: now,
		NotAfter:  now.Add(60 * time.Second),
		PublicKey: pubCrt,
	}
	peerCert, err := tbs.Sign(caCert, cert.Curve_CURVE25519, privCA)
	require.NoError(t, err)

	cachedPeerCert, err := ncp.VerifyCertificate(now.Add(time.Second), peerCert)

	cs := &CertState{
		privateKey:   []byte{},
		v1Cert:       &dummyCert{},
		v1Credential: nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
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
	conf := config.NewC(test.NewLogger())
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	nc.intf = ifce
	ifce.connectionManager = nc

	hostinfo := &HostInfo{
		vpnAddrs: []netip.Addr{vpnIp},
		ConnectionState: &ConnectionState{
			myCert:   &dummyCert{},
			peerCert: cachedPeerCert,
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

type dummyCert struct {
	version        cert.Version
	curve          cert.Curve
	groups         []string
	isCa           bool
	issuer         string
	name           string
	networks       []netip.Prefix
	notAfter       time.Time
	notBefore      time.Time
	publicKey      []byte
	signature      []byte
	unsafeNetworks []netip.Prefix
}

func (d *dummyCert) Version() cert.Version {
	return d.version
}

func (d *dummyCert) Curve() cert.Curve {
	return d.curve
}

func (d *dummyCert) Groups() []string {
	return d.groups
}

func (d *dummyCert) IsCA() bool {
	return d.isCa
}

func (d *dummyCert) Issuer() string {
	return d.issuer
}

func (d *dummyCert) Name() string {
	return d.name
}

func (d *dummyCert) Networks() []netip.Prefix {
	return d.networks
}

func (d *dummyCert) NotAfter() time.Time {
	return d.notAfter
}

func (d *dummyCert) NotBefore() time.Time {
	return d.notBefore
}

func (d *dummyCert) PublicKey() []byte {
	return d.publicKey
}

func (d *dummyCert) MarshalPublicKeyPEM() []byte {
	return cert.MarshalPublicKeyToPEM(d.curve, d.publicKey)
}

func (d *dummyCert) Signature() []byte {
	return d.signature
}

func (d *dummyCert) UnsafeNetworks() []netip.Prefix {
	return d.unsafeNetworks
}

func (d *dummyCert) MarshalForHandshakes() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) Sign(curve cert.Curve, key []byte) error {
	return nil
}

func (d *dummyCert) CheckSignature(key []byte) bool {
	return true
}

func (d *dummyCert) Expired(t time.Time) bool {
	return false
}

func (d *dummyCert) CheckRootConstraints(signer cert.Certificate) error {
	return nil
}

func (d *dummyCert) VerifyPrivateKey(curve cert.Curve, key []byte) error {
	return nil
}

func (d *dummyCert) String() string {
	return ""
}

func (d *dummyCert) Marshal() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) MarshalPEM() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) Fingerprint() (string, error) {
	return "", nil
}

func (d *dummyCert) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) Copy() cert.Certificate {
	return d
}

// newPunchTestConnectionManager is a connection manager punching through conn, holding the tunnel from newPunchTarget
func newPunchTestConnectionManager(t *testing.T, conn udp.Conn) (*connectionManager, *HostInfo) {
	l := test.NewLogger()
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&[]netip.Prefix{})

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(&CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
	})

	punchy := newPunchyForTest(t, map[string]any{"punch": true}, conn)
	nc := newConnectionManagerFromConfig(l, config.NewC(l), hostMap, punchy)
	nc.intf = ifce
	ifce.connectionManager = nc
	// Tunnel sends go through conn too, though without a key from withTestKey they never get as far as writing
	ifce.writers = []udp.Conn{conn}
	ifce.metricTxDropped = metrics.NilCounter{}

	hostinfo := newPunchTarget()
	hostinfo.localIndexId = 1099
	hostinfo.remoteIndexId = 9901
	hostinfo.ConnectionState = &ConnectionState{myCert: &dummyCert{version: cert.Version1}}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)
	return nc, hostinfo
}

// A tunnel we are not sending on gets punched whether or not it is receiving, the punch is the only thing that
// would notice its remote has become unreachable.
func Test_makeTrafficDecision_punchesWhenNotSending(t *testing.T) {
	nc, hostinfo := newPunchTestConnectionManager(t, &recordingConn{})
	now := time.Now()

	// Receiving but not sending
	hostinfo.takeTraffic()
	nc.In(hostinfo)
	decision, _, _, punch := nc.makeTrafficDecision(hostinfo.localIndexId, now)
	assert.Equal(t, tryRehandshake, decision)
	assert.Same(t, hostinfo, punch)

	// Sending and receiving, our own traffic keeps the NAT state alive
	nc.Out(hostinfo)
	nc.In(hostinfo)
	decision, _, _, punch = nc.makeTrafficDecision(hostinfo.localIndexId, now)
	assert.Equal(t, tryRehandshake, decision)
	assert.Nil(t, punch)

	// Unused
	decision, decided, _, punch := nc.makeTrafficDecision(hostinfo.localIndexId, now)
	assert.Equal(t, doNothing, decision)
	assert.Nil(t, decided, "an unused tunnel has no relay usage to reset")
	assert.Same(t, hostinfo, punch)

	// Sending but not receiving gets a test packet instead, which finds an unreachable remote on its own
	nc.Out(hostinfo)
	decision, _, _, punch = nc.makeTrafficDecision(hostinfo.localIndexId, now)
	assert.Equal(t, sendTestPacket, decision)
	assert.Nil(t, punch)
}

func Test_sendPunch_probesWhenRemoteUnreachable(t *testing.T) {
	t.Run("unreachable", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV6: errNoRoute}}
		nc, hostinfo := newPunchTestConnectionManager(t, conn)

		nc.sendPunch(hostinfo)
		assert.Equal(t, []netip.AddrPort{punchTargetV6}, conn.wrote)
		assert.NotZero(t, hostinfo.nextUnreachableProbe.Load(), "the tunnel should have probed its other remotes")
		assert.Equal(t, []netip.Addr{hostinfo.vpnAddrs[0]}, drainQueries(nc.intf.lightHouse),
			"the probe should ask the lighthouse to have the peer punch us")

		// Within the probe interval nothing more goes out, however many sends fail
		nc.sendPunch(hostinfo)
		nc.sendPunch(hostinfo)
		assert.Empty(t, drainQueries(nc.intf.lightHouse))
	})

	t.Run("delivered", func(t *testing.T) {
		conn := &recordingConn{}
		nc, hostinfo := newPunchTestConnectionManager(t, conn)

		nc.sendPunch(hostinfo)
		assert.Equal(t, []netip.AddrPort{punchTargetV6}, conn.wrote)
		assert.Zero(t, hostinfo.nextUnreachableProbe.Load())
		assert.Empty(t, drainQueries(nc.intf.lightHouse))
	})

	t.Run("other failure", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV6: io.ErrShortWrite}}
		nc, hostinfo := newPunchTestConnectionManager(t, conn)

		nc.sendPunch(hostinfo)
		assert.Zero(t, hostinfo.nextUnreachableProbe.Load(), "only a missing route says to look elsewhere")
		assert.Empty(t, drainQueries(nc.intf.lightHouse))
	})
}

// A packet the data path had no route for names its tunnel in its header, the peer's index for it
func Test_sendUnreachable_findsTunnelFromHeader(t *testing.T) {
	head := func(st header.MessageSubType, remoteIndex uint32) []byte {
		return header.Encode(make([]byte, header.Len), header.Version, header.Message, st, remoteIndex, 1)
	}

	t.Run("direct", func(t *testing.T) {
		nc, hostinfo := newPunchTestConnectionManager(t, &recordingConn{})
		nc.intf.sendUnreachable(head(header.MessageNone, hostinfo.remoteIndexId), punchTargetV6)
		assert.NotZero(t, hostinfo.nextUnreachableProbe.Load(), "the tunnel should have probed its other remotes")
		assert.Equal(t, []netip.Addr{hostinfo.vpnAddrs[0]}, drainQueries(nc.intf.lightHouse))
	})

	t.Run("not its remote", func(t *testing.T) {
		nc, hostinfo := newPunchTestConnectionManager(t, &recordingConn{})
		nc.intf.sendUnreachable(head(header.MessageNone, hostinfo.remoteIndexId), punchTargetV4)
		assert.Zero(t, hostinfo.nextUnreachableProbe.Load(), "a failure on a remote the tunnel is not using is stale")
	})

	t.Run("relayed", func(t *testing.T) {
		nc, hostinfo := newPunchTestConnectionManager(t, &recordingConn{})
		// A relay header's index is the relay session's, it must not be taken for a tunnel's even when they collide
		nc.intf.sendUnreachable(head(header.MessageRelay, hostinfo.remoteIndexId), punchTargetV6)
		assert.Zero(t, hostinfo.nextUnreachableProbe.Load())
		assert.Empty(t, drainQueries(nc.intf.lightHouse))
	})

	t.Run("unknown tunnel", func(t *testing.T) {
		nc, hostinfo := newPunchTestConnectionManager(t, &recordingConn{})
		nc.intf.sendUnreachable(head(header.MessageNone, hostinfo.remoteIndexId+1), punchTargetV6)
		assert.Zero(t, hostinfo.nextUnreachableProbe.Load())
	})
}

// withTestKey gives a tunnel a real key so its sends get encrypted and written instead of returning early
func withTestKey(hostinfo *HostInfo) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	hostinfo.ConnectionState.eKey = noiseutil.NewCipherState(noise.UnsafeNewCipherState(cs, [32]byte{}, 0), noise.CipherAESGCM)
}

// The probe itself, end to end from a failed send: a test packet to every remote but the one we cannot reach, and a
// lighthouse query, through both places a send can fail.
func Test_remoteUnreachable_probesOtherRemotes(t *testing.T) {
	t.Run("control send", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV6: errNoRoute}}
		nc, hostinfo := newPunchTestConnectionManager(t, conn)
		withTestKey(hostinfo)

		nc.intf.SendMessageToHostInfo(header.Test, header.TestRequest, hostinfo, []byte{}, make([]byte, 12), make([]byte, mtu))
		assert.Equal(t, []netip.AddrPort{punchTargetV6, punchTargetV4}, conn.wrote, "the failed send, then the probe")
		assert.Equal(t, []header.MessageType{header.Test, header.Test}, conn.types)
		assert.Equal(t, []netip.Addr{hostinfo.vpnAddrs[0]}, drainQueries(nc.intf.lightHouse))
	})

	t.Run("data path batch", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV6: errNoRoute}}
		nc, hostinfo := newPunchTestConnectionManager(t, conn)
		withTestKey(hostinfo)

		// Two of the tunnel's packets fail in one batch, they probe once
		sb := batch.NewSendBatch(conn, 4, 4096)
		for c := uint64(1); c <= 2; c++ {
			pkt := header.Encode(sb.Reserve(64), header.Version, header.Message, header.MessageNone, hostinfo.remoteIndexId, c)
			sb.Commit(append(pkt, make([]byte, 32)...), punchTargetV6)
		}
		nc.intf.flushSendBatch(sb, 0)

		assert.Equal(t, []netip.AddrPort{punchTargetV6, punchTargetV6, punchTargetV4}, conn.wrote,
			"the failed packets, then one probe")
		assert.Equal(t, header.Test, conn.types[2])
		assert.Equal(t, []netip.Addr{hostinfo.vpnAddrs[0]}, drainQueries(nc.intf.lightHouse))
	})

	t.Run("closing", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV6: errNoRoute}}
		nc, hostinfo := newPunchTestConnectionManager(t, conn)
		withTestKey(hostinfo)

		nc.intf.SendMessageToHostInfo(header.CloseTunnel, 0, hostinfo, []byte{}, make([]byte, 12), make([]byte, mtu))
		assert.Equal(t, []netip.AddrPort{punchTargetV6}, conn.wrote, "a tunnel being torn down does not probe")
		assert.Empty(t, drainQueries(nc.intf.lightHouse))
	})

	t.Run("lighthouse", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV6: errNoRoute}}
		nc, hostinfo := newPunchTestConnectionManager(t, conn)
		withTestKey(hostinfo)
		nc.intf.lightHouse.amLighthouse = true

		nc.intf.SendMessageToHostInfo(header.Test, header.TestRequest, hostinfo, []byte{}, make([]byte, 12), make([]byte, mtu))
		assert.Equal(t, []netip.AddrPort{punchTargetV6}, conn.wrote, "a lighthouse does not roam its clients")
	})

	t.Run("nothing else to probe", func(t *testing.T) {
		conn := &recordingConn{fail: map[netip.AddrPort]error{punchTargetV6: errNoRoute}}
		nc, hostinfo := newPunchTestConnectionManager(t, conn)
		withTestKey(hostinfo)
		nc.intf.reQueryWait.Store(int64(time.Minute))
		// Forget the IPv4 remote, all the tunnel knows is the one it cannot reach
		hostinfo.remotes = NewRemoteList(hostinfo.vpnAddrs, nil)
		hostinfo.remotes.LearnRemote(hostinfo.vpnAddrs[0], punchTargetV6)

		nc.intf.SendMessageToHostInfo(header.Test, header.TestRequest, hostinfo, []byte{}, make([]byte, 12), make([]byte, mtu))
		assert.Equal(t, []netip.Addr{hostinfo.vpnAddrs[0]}, drainQueries(nc.intf.lightHouse),
			"the lighthouse is the only way to learn of another remote")

		// Past the probe interval, but the lighthouse is only asked again on the requery schedule
		hostinfo.nextUnreachableProbe.Store(0)
		nc.intf.SendMessageToHostInfo(header.Test, header.TestRequest, hostinfo, []byte{}, make([]byte, 12), make([]byte, mtu))
		assert.Empty(t, drainQueries(nc.intf.lightHouse))
		assert.Equal(t, []netip.AddrPort{punchTargetV6, punchTargetV6}, conn.wrote)
	})
}

// drainQueries returns every lighthouse query waiting to go out
func drainQueries(lh *LightHouse) []netip.Addr {
	var queries []netip.Addr
	for {
		select {
		case addr := <-lh.queryChan:
			queries = append(queries, addr)
		default:
			return queries
		}
	}
}
