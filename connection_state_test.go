package nebula

import (
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runTestHandshake runs a complete IX handshake between two freshly-built
// peers and returns the initiator and responder Results. Used to produce
// real cipher states for tests that need to exercise post-handshake glue.
func runTestHandshake(t *testing.T) (initR, respR *handshake.Result) {
	t.Helper()

	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	makeCreds := func(name string, networks []netip.Prefix) handshake.GetCredentialFunc {
		c, _, rawKey, _ := ct.NewTestCert(
			cert.Version2, cert.Curve_CURVE25519, ca, caKey,
			name, ca.NotBefore(), ca.NotAfter(), networks, nil, nil,
		)
		priv, _, _, err := cert.UnmarshalPrivateKeyFromPEM(rawKey)
		require.NoError(t, err)
		hsBytes, err := c.MarshalForHandshakes()
		require.NoError(t, err)
		ncs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
		cred := handshake.NewCredential(c, hsBytes, priv, ncs)
		return func(v cert.Version) *handshake.Credential {
			if v == cert.Version2 {
				return cred
			}
			return nil
		}
	}

	verifier := func(c cert.Certificate) (*cert.CachedCertificate, error) {
		return caPool.VerifyCertificate(time.Now(), c)
	}

	initCreds := makeCreds("initiator", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respCreds := makeCreds("responder", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initM, err := handshake.NewMachine(
		cert.Version2, initCreds, verifier,
		func() (uint32, error) { return 1000, nil },
		true, header.HandshakeIXPSK0,
	)
	require.NoError(t, err)

	respM, err := handshake.NewMachine(
		cert.Version2, respCreds, verifier,
		func() (uint32, error) { return 2000, nil },
		false, header.HandshakeIXPSK0,
	)
	require.NoError(t, err)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)

	resp, respR, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.NotNil(t, respR)

	_, initR, err = initM.ProcessPacket(nil, resp)
	require.NoError(t, err)
	require.NotNil(t, initR)

	return initR, respR
}

func TestConnectionState_NextMessageCounter(t *testing.T) {
	cs := &ConnectionState{}
	cs.messageCounter.Store(RejectAfterMessages - 2)

	c, ok := cs.NextMessageCounter()
	assert.True(t, ok)
	assert.Equal(t, RejectAfterMessages-1, c)

	// Hitting the limit refuses and pins the counter there
	c, ok = cs.NextMessageCounter()
	assert.False(t, ok)
	assert.Equal(t, RejectAfterMessages, c)
	assert.Equal(t, RejectAfterMessages, cs.messageCounter.Load())

	// Continued send attempts stay refused and the counter never wraps
	for range 10 {
		_, ok = cs.NextMessageCounter()
		assert.False(t, ok)
	}
	assert.Equal(t, RejectAfterMessages, cs.messageCounter.Load())
}

// TestSendNoMetricsDropsExhausted drives the send path to the exhausted drop; metric and out flag prove it.
func TestSendNoMetricsDropsExhausted(t *testing.T) {
	initR, _ := runTestHandshake(t)
	ci, err := newConnectionStateFromResult(initR)
	require.NoError(t, err)
	ci.messageCounter.Store(RejectAfterMessages - 1)

	f := &Interface{l: test.NewLogger(), messageMetrics: &MessageMetrics{txExhausted: metrics.NewCounter()}}
	hostinfo := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, ConnectionState: ci}

	f.sendNoMetrics(header.Message, 0, ci, hostinfo, netip.AddrPort{}, []byte{}, make([]byte, 12), make([]byte, mtu), 0)

	// The crossing send is refused: it records an exhaustion drop and never reaches connectionManager.Out.
	assert.Equal(t, int64(1), f.messageMetrics.txExhausted.Count())
	assert.False(t, hostinfo.sentSinceCheck())
}

// TestSendNoMetricsCloseTunnelKeepsRebindEpoch pins that a closing tunnel does not consume a rebind, a later
// packet on a re-established tunnel still needs that edge to trigger the far-side punch.
func TestSendNoMetricsCloseTunnelKeepsRebindEpoch(t *testing.T) {
	initR, _ := runTestHandshake(t)
	ci, err := newConnectionStateFromResult(initR)
	require.NoError(t, err)

	f := &Interface{
		l:                 test.NewLogger(),
		messageMetrics:    &MessageMetrics{txExhausted: metrics.NewCounter()},
		writers:           []udp.Conn{udp.NoopConn{}},
		connectionManager: &connectionManager{},
	}
	hostinfo := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, ConnectionState: ci}

	// Tunnel is on epoch 0, then we rebind.
	hostinfo.markOut(0)
	f.rebindEpoch.Add(1)

	remote := netip.MustParseAddrPort("10.0.0.2:4242")
	f.sendNoMetrics(header.CloseTunnel, 0, ci, hostinfo, remote, []byte{}, make([]byte, 12), make([]byte, mtu), 0)

	// markOut at the new epoch still reports the move, so the edge was preserved.
	assert.True(t, hostinfo.markOut(1), "a CloseTunnel send must not consume the rebind epoch")
}

// capturingConn is a udp.Conn that records every WriteTo.
type capturingConn struct {
	udp.NoopConn
	writes [][]byte
	addrs  []netip.AddrPort
}

func (c *capturingConn) WriteTo(b []byte, addr netip.AddrPort) error {
	c.writes = append(c.writes, append([]byte(nil), b...))
	c.addrs = append(c.addrs, addr)
	return nil
}

// TestSendNoMetricsViaRelay sends through a relay from the mtu sized buffer the cached packet flush uses. Payloads up
// to overlay.MaxMTU go out intact, anything bigger is dropped rather than outgrowing the buffer, which once panicked.
func TestSendNoMetricsViaRelay(t *testing.T) {
	tests := []struct {
		n    int
		sent bool
	}{
		{0, true},
		{1300, true},
		{overlay.MaxMTU, true},
		{overlay.MaxMTU + 1, false}, // too big for the relay's tag
		{mtu - 47, false},           // too big for the inner tag, this panicked
		{9000, false},               // a full packet at tun.mtu 9000
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.n), func(t *testing.T) {
			// One tunnel to the target, carried end to end, and one to the relay that wraps it
			targetInit, targetResp := runTestHandshake(t)
			relayInit, relayResp := runTestHandshake(t)
			ci, err := newConnectionStateFromResult(targetInit)
			require.NoError(t, err)
			relayCI, err := newConnectionStateFromResult(relayInit)
			require.NoError(t, err)

			targetAddr := netip.MustParseAddr("10.0.0.2")
			relayAddr := netip.MustParseAddr("10.0.0.3")
			relayRemote := netip.MustParseAddrPort("192.0.2.1:4242")

			relay := &Relay{Type: TerminalType, State: Established, LocalIndex: 5, RemoteIndex: 6, PeerAddr: targetAddr}
			relayHI := &HostInfo{
				vpnAddrs:        []netip.Addr{relayAddr},
				ConnectionState: relayCI,
				relayState: RelayState{
					relayForByAddr: map[netip.Addr]*Relay{targetAddr: relay},
					relayForByIdx:  map[uint32]*Relay{relay.LocalIndex: relay},
				},
			}
			relayHI.remote.Store(&relayRemote)

			// No remote of its own, so the send has to go via the relay
			hostinfo := &HostInfo{
				vpnAddrs:        []netip.Addr{targetAddr},
				ConnectionState: ci,
				remoteIndexId:   7,
				relayState: RelayState{
					relays:         []netip.Addr{relayAddr},
					relayForByAddr: map[netip.Addr]*Relay{},
					relayForByIdx:  map[uint32]*Relay{},
				},
			}

			l := test.NewLogger()
			hm := newHostMap(l)
			hm.Hosts[relayAddr] = relayHI
			conn := &capturingConn{}
			f := &Interface{
				l:              l,
				hostMap:        hm,
				messageMetrics: &MessageMetrics{txExhausted: metrics.NewCounter()},
				writers:        []udp.Conn{conn},
			}
			f.connectionManager = &connectionManager{intf: f, relayUsed: map[uint32]struct{}{}, relayUsedLock: &sync.RWMutex{}}

			payload := make([]byte, tt.n)
			for i := range payload {
				payload[i] = byte(i)
			}
			counter := ci.messageCounter.Load()
			f.sendNoMetrics(header.Message, 0, ci, hostinfo, netip.AddrPort{}, payload, make([]byte, 12), make([]byte, mtu), 0)

			if !tt.sent {
				assert.Empty(t, conn.writes)
				assert.Equal(t, counter, ci.messageCounter.Load(), "a dropped packet must not spend a counter")
				return
			}
			require.Len(t, conn.writes, 1)
			assert.Equal(t, relayRemote, conn.addrs[0])
			pkt := conn.writes[0]

			// The relay authenticates the whole packet under its own header
			outer := &header.H{}
			require.NoError(t, outer.Parse(pkt))
			assert.Equal(t, header.MessageRelay, outer.Subtype)
			assert.Equal(t, relay.RemoteIndex, outer.RemoteIndex)
			relayPeer, err := newConnectionStateFromResult(relayResp)
			require.NoError(t, err)
			require.NoError(t, relayPeer.VerifyRelay(l, outer.MessageCounter, pkt, make([]byte, 12)))

			// Inside it, the target decrypts the end to end packet back to the payload
			inner := pkt[header.Len : len(pkt)-relayPeer.dKey.Overhead()]
			h := &header.H{}
			require.NoError(t, h.Parse(inner))
			assert.Equal(t, header.Message, h.Type)
			assert.Equal(t, hostinfo.remoteIndexId, h.RemoteIndex)
			targetPeer, err := newConnectionStateFromResult(targetResp)
			require.NoError(t, err)
			got, err := targetPeer.Decrypt(l, h.MessageCounter, inner, make([]byte, 12))
			require.NoError(t, err)
			assert.Equal(t, payload, got)
		})
	}
}

func TestNewConnectionStateFromResult(t *testing.T) {
	initR, respR := runTestHandshake(t)

	t.Run("initiator", func(t *testing.T) {
		ci, err := newConnectionStateFromResult(initR)
		require.NoError(t, err)
		assert.True(t, ci.initiator)
		assert.Equal(t, initR.MyCert, ci.myCert)
		assert.Equal(t, initR.RemoteCert, ci.peerCert)
		assert.NotNil(t, ci.eKey)
		assert.NotNil(t, ci.dKey)

		// IX has 2 handshake messages; the next data-plane send is counter=3.
		assert.Equal(t, uint64(2), ci.messageCounter.Load(),
			"messageCounter must equal Result.MessageIndex so the next send is N+1")

		// Both handshake counters must be marked seen so they don't appear lost.
		// Check returns false if an index has already been recorded.
		assert.False(t, ci.window.Check(nil, 1), "counter 1 must already be seen")
		assert.False(t, ci.window.Check(nil, 2), "counter 2 must already be seen")
		// Counter 3 is the next data-plane message and must NOT be pre-marked.
		assert.True(t, ci.window.Check(nil, 3), "counter 3 must not be pre-seeded")
	})

	t.Run("message index too large is refused", func(t *testing.T) {
		bad := *initR
		bad.MessageIndex = ReplayWindow
		ci, err := newConnectionStateFromResult(&bad)
		require.Error(t, err)
		assert.Nil(t, ci)
	})

	t.Run("responder", func(t *testing.T) {
		ci, err := newConnectionStateFromResult(respR)
		require.NoError(t, err)
		assert.False(t, ci.initiator)
		assert.Equal(t, respR.MyCert, ci.myCert)
		assert.Equal(t, respR.RemoteCert, ci.peerCert)
		assert.NotNil(t, ci.eKey)
		assert.NotNil(t, ci.dKey)
		assert.Equal(t, uint64(2), ci.messageCounter.Load())
	})
}
