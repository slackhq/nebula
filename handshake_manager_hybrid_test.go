package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/handshake/fragment"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ixHybridFragmented = header.HandshakeIXHybridFragmented

// hybridPeer is a node on the hybrid curve: its cert state, and the CA that signed it.
type hybridPeer struct {
	cs *CertState
}

func newHybridPeers(t *testing.T) (ca cert.Certificate, responder, initiator hybridPeer) {
	t.Helper()
	if err := cert.HybridAvailable(); err != nil {
		t.Skip(err)
	}
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_P384_MLKEM1024_MLDSA87, time.Time{}, time.Time{}, nil, nil, nil)
	mk := func(name, network string) hybridPeer {
		c, _, keyPEM, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_P384_MLKEM1024_MLDSA87, ca, caKey, name, time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix(network)}, nil, nil)
		key, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(keyPEM)
		require.NoError(t, err)
		cs, err := newCertState(cert.Version2, nil, c, false, curve, key, "aes")
		require.NoError(t, err)
		return hybridPeer{cs: cs}
	}
	return ca, mk("responder", "10.0.0.1/24"), mk("initiator", "10.0.0.2/24")
}

// newHybridTestManager is newFragTestManager for a responder on the hybrid curve that trusts ca.
func newHybridTestManager(t *testing.T, ca cert.Certificate, cs *CertState) (*HandshakeManager, *captureConn) {
	t.Helper()
	hm, conn := newFragTestManager(t)
	hm.f.pki.cs.Store(cs)
	pool := cert.NewCAPool()
	require.NoError(t, pool.AddCA(ca))
	hm.f.pki.caPool.Store(pool)
	hm.lightHouse.remoteAllowList.Store(&RemoteAllowList{})
	hm.f.lightHouse = hm.lightHouse
	hm.f.hostMap = hm.mainHostMap
	hm.f.myVpnAddrsTable = cs.myVpnAddrsTable
	hm.f.myVpnNetworksTable = cs.myVpnNetworksTable
	// A completing responder confirms over the new tunnel, which records its traffic.
	conf := config.NewC(test.NewLogger())
	hm.f.connectionManager = newConnectionManagerFromConfig(test.NewLogger(), conf, hm.mainHostMap, NewPunchyFromConfig(test.NewLogger(), conf, nil))
	hm.f.connectionManager.intf = hm.f
	hm.f.writers = []udp.Conn{conn}
	return hm, conn
}

// hybridMsg1 is a msg1 from the initiator's hybrid Machine, and the Machine.
func hybridMsg1(t *testing.T, ca cert.Certificate, initiator hybridPeer) ([]byte, *handshake.Machine) {
	t.Helper()
	pool := cert.NewCAPool()
	require.NoError(t, pool.AddCA(ca))
	m, err := handshake.NewMachine(cert.Version2, initiator.cs.GetCredential,
		func(c cert.Certificate) (*cert.CachedCertificate, error) {
			return pool.VerifyCertificate(time.Now(), c)
		},
		func() (uint32, error) { return 777, nil }, true, header.HandshakeIXHybrid)
	require.NoError(t, err)
	msg1, err := m.Initiate(nil)
	require.NoError(t, err)
	return msg1, m
}

// responderFragIDs returns the FragIDs of the msg2 fragments among pkts, and how many there were.
func responderFragIDs(t *testing.T, pkts [][]byte) (map[uint32]int, int) {
	t.Helper()
	ids := map[uint32]int{}
	n := 0
	for _, p := range pkts {
		var h header.H
		require.NoError(t, h.Parse(p))
		if h.Subtype != ixHybridFragmented || h.MessageCounter != 2 {
			continue
		}
		fh, _, err := fragment.Parse(p[header.Len:])
		require.NoError(t, err)
		ids[fh.FragID]++
		n++
	}
	return ids, n
}

// decodeMsg2 reassembles the msg2 among pkts into the packet the initiator's Machine reads.
func decodeMsg2(t *testing.T, pkts [][]byte) []byte {
	t.Helper()
	var a *fragment.Assembly
	var h header.H
	for _, p := range pkts {
		require.NoError(t, h.Parse(p))
		if h.MessageCounter != 2 {
			continue
		}
		fh, sym, err := fragment.Parse(p[header.Len:])
		require.NoError(t, err)
		if a == nil {
			a, err = fragment.NewAssembly(fh)
			require.NoError(t, err)
		}
		ready, err := a.Add(fh, sym)
		require.NoError(t, err)
		if ready {
			pkt, err := a.Decode(make([]byte, header.Len))
			require.NoError(t, err)
			return reassembled(&h, pkt)
		}
	}
	t.Fatal("msg2 never completed")
	return nil
}

func pendingResponders(hm *HandshakeManager) int {
	hm.RLock()
	defer hm.RUnlock()
	return len(hm.hybrid.responders)
}

func pendingIndexes(hm *HandshakeManager) int {
	hm.RLock()
	defer hm.RUnlock()
	return len(hm.indexes)
}

// A repeat of a hybrid msg1 while its responder waits for msg3 gets msg2 again, from the same responder, rather than
// starting a second handshake under a second index.
func TestHybridRepeatWhilePending(t *testing.T) {
	ca, responder, initiator := newHybridPeers(t)
	hm, conn := newHybridTestManager(t, ca, responder.cs)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.2:4242")}
	msg1, _ := hybridMsg1(t, ca, initiator)
	var h header.H
	require.NoError(t, h.Parse(msg1))
	in := msg1Info{fragmented: true, validated: true}

	hm.beginHandshake(via, msg1, &h, in)
	require.Equal(t, 1, pendingResponders(hm))
	require.Equal(t, 1, pendingIndexes(hm))
	first, n := responderFragIDs(t, conn.take())
	require.Len(t, first, 1)
	assert.Equal(t, 9+3, n, "msg2 went out")

	hm.beginHandshake(via, msg1, &h, in)
	assert.Equal(t, 1, pendingResponders(hm), "no second pending responder")
	assert.Equal(t, 1, pendingIndexes(hm), "no second index")
	again, n := responderFragIDs(t, conn.take())
	assert.Positive(t, n, "msg2 resent")
	assert.Len(t, again, 1)
	for id := range again {
		assert.Contains(t, first, id, "by the same responder")
	}
}

// A repeat of a hybrid msg1 whose tunnel is already up starts no pending responder: the initiator has its tunnel.
func TestHybridRepeatAfterComplete(t *testing.T) {
	ca, responder, initiator := newHybridPeers(t)
	hm, conn := newHybridTestManager(t, ca, responder.cs)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.2:4242")}
	msg1, im := hybridMsg1(t, ca, initiator)
	var h header.H
	require.NoError(t, h.Parse(msg1))
	in := msg1Info{fragmented: true, validated: true}

	hm.beginHandshake(via, msg1, &h, in)
	msg2 := decodeMsg2(t, conn.take())
	msg3, res, err := im.ProcessPacket(nil, msg2)
	require.NoError(t, err)
	require.NotNil(t, res, "the initiator completes on msg2")

	s, err := fragment.NewSender(msg3, 777)
	require.NoError(t, err)
	pkts, later, err := s.Attempt(0)
	require.NoError(t, err)
	for _, p := range append(pkts, later...) {
		var ph header.H
		require.NoError(t, ph.Parse(p))
		hm.HandleIncoming(via, p, &ph)
	}
	require.Zero(t, pendingResponders(hm), "msg3 completed the responder")
	require.NotNil(t, hm.mainHostMap.QueryVpnAddr(netip.MustParseAddr("10.0.0.2")), "the tunnel is up")
	conn.take()

	hm.beginHandshake(via, msg1, &h, in)
	assert.Zero(t, pendingResponders(hm), "a repeat after completion starts nothing")
	assert.Zero(t, pendingIndexes(hm))
	_, n := responderFragIDs(t, conn.take())
	assert.Positive(t, n, "the cached msg2 is resent, as for a classical repeat")
}

// A node answers msg1s for its own curve only, and an unfragmented hybrid packet is malformed.
func TestHybridAnswersPattern(t *testing.T) {
	ca, responder, _ := newHybridPeers(t)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}

	hybrid, _ := newHybridTestManager(t, ca, responder.cs)
	assert.True(t, hybrid.answersPattern(via, header.HandshakeIXHybrid))
	assert.True(t, hybrid.answersPattern(via, ixHybridFragmented))
	assert.False(t, hybrid.answersPattern(via, header.HandshakeIXPSK0))
	assert.False(t, hybrid.answersPattern(via, header.HandshakeIXPSK0Fragmented))

	classical, _ := newFragTestManager(t)
	assert.True(t, classical.answersPattern(via, header.HandshakeIXPSK0))
	assert.True(t, classical.answersPattern(via, header.HandshakeIXPSK0Fragmented))
	assert.False(t, classical.answersPattern(via, header.HandshakeIXHybrid))
	assert.False(t, classical.answersPattern(via, ixHybridFragmented))

	// A classical node drops a hybrid msg1 fragment before it reaches the table, a hybrid node a classical one.
	p, h := hybridMsg1Fragment(t, 7)
	classical.HandleIncoming(via, p, h)
	assert.Zero(t, classical.fragTable.Len())
	p, h = msg1Fragment(t, 8, nil)
	hybrid.HandleIncoming(via, p, h)
	assert.Zero(t, hybrid.fragTable.Len())

	// Hybrid fragments do reach the table on a hybrid node, even with handshakes.fragment never.
	hybrid.frag.Store(&fragmentConfig{mode: fragmentNever})
	p, h = hybridMsg1Fragment(t, 9)
	hybrid.HandleIncoming(via, p, h)
	assert.Equal(t, 1, hybrid.fragTable.Len(), "never leaves hybrid fragments alone")

	// An unfragmented hybrid packet goes nowhere.
	single := header.Encode(make([]byte, header.Len, header.Len+100), header.Version, header.Handshake, header.HandshakeIXHybrid, 0, 1)
	single = append(single, make([]byte, 100)...)
	var sh header.H
	require.NoError(t, sh.Parse(single))
	hybrid.HandleIncoming(via, single, &sh)
	assert.Equal(t, 1, hybrid.fragTable.Len())
	assert.Zero(t, pendingResponders(hybrid))
}

// hybridMsg1Fragment builds the first fragment of a hybrid msg1.
func hybridMsg1Fragment(t *testing.T, fragID uint32) ([]byte, *header.H) {
	t.Helper()
	pkt := header.Encode(make([]byte, header.Len, header.Len+2000), header.Version, header.Handshake, header.HandshakeIXHybrid, 0, 1)
	s, err := fragment.NewSender(append(pkt, make([]byte, 2000)...), fragID)
	require.NoError(t, err)
	pkts, _, err := s.Attempt(0)
	require.NoError(t, err)
	var h header.H
	require.NoError(t, h.Parse(pkts[0]))
	return pkts[0], &h
}

// A hybrid node initiates ix_hybrid, always as fragments, whatever handshakes.fragment says.
func TestHybridInitiates(t *testing.T) {
	ca, responder, _ := newHybridPeers(t)
	hm, _ := newHybridTestManager(t, ca, responder.cs)
	hm.frag.Store(&fragmentConfig{mode: fragmentNever})
	hh := &HandshakeHostInfo{hostinfo: &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}, HandshakePacket: map[uint8][]byte{}}}
	require.True(t, hm.buildStage0Packet(hh))
	assert.Equal(t, header.HandshakeIXHybrid, hh.machine.Subtype())
	require.NotNil(t, hh.sender, "msg1 travels as fragments")
	now, later, err := hh.stage0Packets()
	require.NoError(t, err)
	for _, p := range append(now, later...) {
		var h header.H
		require.NoError(t, h.Parse(p))
		assert.Equal(t, ixHybridFragmented, h.Subtype)
		assert.LessOrEqual(t, len(p), fragment.MaxPacketLen)
	}
}
