package nebula

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/overlaytest"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testMyAddr   = netip.MustParseAddr("10.0.0.1")
	testPeerAddr = netip.MustParseAddr("10.0.0.2")
)

// newTestLaneSet builds a lane set from a real handshake result so the sessions
// it derives hold usable keys.
func newTestLaneSet(t *testing.T, r *handshake.Result, myLanes int, peerPorts, peerBase, peerTxLanes uint32) *laneSet {
	t.Helper()
	r.PeerPortCount = peerPorts
	r.PeerBasePort = peerBase
	r.PeerTxLanes = peerTxLanes
	return newLaneSet(r, myLanes, testMyAddr, testPeerAddr)
}

// laneSessionFor derives lane s's session and installs it, standing in for the
// data-plane call that would normally be the first to need it.
func laneSessionFor(t *testing.T, ls *laneSet, s int) *ConnectionState {
	t.Helper()
	cs, err := ls.session(s)
	require.NoError(t, err)
	require.NotNil(t, cs)
	return cs
}

func newTestLaneHostInfo(t *testing.T, r *handshake.Result, ls *laneSet) *HostInfo {
	t.Helper()
	cs, err := newConnectionStateFromResult(r)
	require.NoError(t, err)
	hi := &HostInfo{
		vpnAddrs:        []netip.Addr{testPeerAddr},
		localIndexId:    100,
		remoteIndexId:   200,
		remotes:         NewRemoteList([]netip.Addr{testPeerAddr}, nil),
		HandshakePacket: map[uint8][]byte{},
		ConnectionState: cs,
		lanes:           ls,
	}
	hi.SetRemote(netip.MustParseAddrPort("192.0.2.1:4242"))
	return hi
}

func TestLanePortOffset(t *testing.T) {
	a := netip.MustParseAddr("10.0.0.1")
	b := netip.MustParseAddr("10.0.0.2")

	// Deterministic and in range.
	for _, count := range []uint16{1, 2, 3, 4, 16, 256} {
		o := lanePortOffset(a, b, count)
		assert.Equal(t, o, lanePortOffset(a, b, count), "count %d not deterministic", count)
		assert.Less(t, o, count, "count %d out of range", count)
	}
	assert.Equal(t, uint16(0), lanePortOffset(a, b, 0), "zero port count")

	// The two sides' rotations cancel when port counts match, preserving the
	// lane-i-reverses-lane-j conntrack pairing.
	for _, count := range []uint16{2, 3, 4, 7, 16} {
		for i := range 32 {
			peer := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
			oA := lanePortOffset(a, peer, count)
			oB := lanePortOffset(peer, a, count)
			assert.Equal(t, uint16(0), (oA+oB)%count,
				"offsets don't cancel for peer %s count %d", peer, count)
		}
	}

	// Distinct small peers land on distinct rotations of a big peer's range,
	// not all on the same first ports.
	const bigPeerPorts = 16
	distinct := map[uint16]struct{}{}
	for i := range 64 {
		client := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		distinct[lanePortOffset(client, a, bigPeerPorts)] = struct{}{}
	}
	assert.GreaterOrEqual(t, len(distinct), 8, "64 clients only produced %d distinct offsets", len(distinct))
}

func TestLaneTargetPort(t *testing.T) {
	ls := &laneSet{peerBasePort: 4242, peerPortCount: 4}

	// No rotation: lane i targets base+i, wrapping past the peer's range.
	for i, want := range map[int]uint16{1: 4243, 2: 4244, 3: 4245, 5: 4243} {
		assert.Equal(t, want, ls.laneTargetPortLocked(i), "lane %d", i)
	}

	// Rotation shifts the whole mapping; the wrapped lane lands on the base
	// port itself, which is a valid distinct 4-tuple (our source port differs).
	ls.portOffset = 3
	for i, want := range map[int]uint16{1: 4242, 2: 4243, 3: 4244} {
		assert.Equal(t, want, ls.laneTargetPortLocked(i), "rotated lane %d", i)
	}

	// Fewer peer ports than local lanes: rotation still spreads across all of
	// the peer's ports.
	ls = &laneSet{peerBasePort: 4242, peerPortCount: 2, portOffset: 1}
	assert.Equal(t, uint16(4242), ls.laneTargetPortLocked(1))
	assert.Equal(t, uint16(4243), ls.laneTargetPortLocked(2))
}

// A lane's keys are derived, not negotiated, so the whole design rests on the
// two sides landing on the same pair without exchanging anything.
func TestLaneKeyDerivationSymmetry(t *testing.T) {
	initR, respR := runTestHandshake(t)

	initLS := newTestLaneSet(t, initR, 4, 4, 4242, 4)
	respLS := newTestLaneSet(t, respR, 4, 4, 4242, 4)
	require.Len(t, initLS.sessions, 4)
	assert.Nil(t, initLS.sessions[0].Load(), "lane 0 is the base session, not a derived one")

	nb := make([]byte, 12)
	for s := 1; s < 4; s++ {
		out := header.EncodeLane(make([]byte, 0, mtu), header.Version, header.Message, 0, 200, 1, uint8(s))
		ct, err := laneSessionFor(t, initLS, s).eKey.EncryptDanger(out, out, []byte("lane payload"), 1, nb)
		require.NoError(t, err)

		pt, err := laneSessionFor(t, respLS, s).Decrypt(test.NewLogger(), 1, ct, nb)
		require.NoError(t, err, "lane %d keys did not match", s)
		assert.Equal(t, []byte("lane payload"), pt)
	}

	// Distinct lanes get distinct keys: lane 2's session must not open lane 1's
	// ciphertext, or the header's lane index would be forgeable in effect.
	out := header.EncodeLane(make([]byte, 0, mtu), header.Version, header.Message, 0, 200, 7, 1)
	ct, err := laneSessionFor(t, initLS, 1).eKey.EncryptDanger(out, out, []byte("lane payload"), 7, nb)
	require.NoError(t, err)
	_, err = laneSessionFor(t, respLS, 2).Decrypt(test.NewLogger(), 7, ct, nb)
	assert.Error(t, err)
}

func TestNewLaneSetSizing(t *testing.T) {
	initR, _ := runTestHandshake(t)

	// A peer with no multiport advert gets no lanes at all.
	assert.Nil(t, newLaneSet(&handshake.Result{}, 4, testMyAddr, testPeerAddr))

	// One lane means only the base tunnel, which is not a lane set.
	assert.Nil(t, newLaneSet(&handshake.Result{PeerPortCount: 4, PeerTxLanes: 1}, 1, testMyAddr, testPeerAddr))

	// Sessions cover both directions: enough for everything the peer may send,
	// even though we may only send on a few.
	ls := newTestLaneSet(t, initR, 2, 8, 4242, 6)
	assert.Len(t, ls.sessions, 6, "sessions must cover the peer's tx lanes")
	assert.Equal(t, 2, ls.txLanes, "we may only send on our own lanes")

	// The peer's advert sizes the session table but nothing else. Its lane count
	// is its own choice, so it must not be able to make us allocate per-lane tx
	// state we will never use.
	assert.Len(t, ls.txAddr, 2)
	assert.Len(t, ls.demand, 2)
	assert.Len(t, ls.probe, 2)

	// Nothing is derived up front, for the same reason.
	for s := range ls.sessions {
		assert.Nil(t, ls.sessions[s].Load(), "lane %d derived before anything needed it", s)
	}

	// Our tx lanes are clamped to the ports the peer actually bound: a lane
	// aimed past the peer's range would land on some unrelated socket.
	ls = newTestLaneSet(t, initR, 8, 3, 4242, 8)
	assert.Equal(t, 3, ls.txLanes)
	assert.Len(t, ls.sessions, 8)
}

// The handshake log lines carry the negotiated lanes, so an operator can tell a
// peer that got none from one that was never asked.
func TestLaneLogAttr(t *testing.T) {
	initR, _ := runTestHandshake(t)

	// Not running multiport: an empty attr, which slog drops entirely.
	assert.Equal(t, slog.Attr{}, laneLogAttr(0, nil))

	// Running multiport against a peer that isn't: zeros, not silence.
	assert.Equal(t, m{"tx": 0, "sessions": 0}, laneLogAttr(4, nil).Value.Any())

	ls := newTestLaneSet(t, initR, 2, 8, 4242, 6)
	attr := laneLogAttr(2, ls)
	assert.Equal(t, "lanes", attr.Key)
	assert.Equal(t, m{
		"tx":           2,
		"sessions":     6,
		"peerBasePort": uint16(4242),
		"peerPorts":    uint16(8),
		"portOffset":   ls.portOffset,
	}, attr.Value.Any())
}

// The RX path must not cache a session for a lane until a packet on it has
// actually decrypted, or a spoofer naming lanes at random could make us hold a
// replay window and two cipher states per lane without authenticating anything.
func TestLaneSessionRxDerivation(t *testing.T) {
	initR, respR := runTestHandshake(t)
	respLS := newTestLaneSet(t, respR, 4, 4, 4242, 4)
	hi := newTestLaneHostInfo(t, respR, respLS)

	ci, cached, err := hi.laneSession(2)
	require.NoError(t, err)
	require.NotNil(t, ci)
	assert.False(t, cached, "the first packet on a lane derives, it does not hit")
	assert.Nil(t, respLS.sessions[2].Load(), "an unauthenticated packet must not install a session")

	// The lane the peer really is using decrypts, and that is what installs it.
	nb := make([]byte, 12)
	out := header.EncodeLane(make([]byte, 0, mtu), header.Version, header.Message, 0, 200, 1, 2)
	ct, err := laneSessionFor(t, newTestLaneSet(t, initR, 4, 4, 4242, 4), 2).
		eKey.EncryptDanger(out, out, []byte("real lane traffic"), 1, nb)
	require.NoError(t, err)
	pt, err := ci.Decrypt(test.NewLogger(), 1, ct, nb)
	require.NoError(t, err)
	assert.Equal(t, []byte("real lane traffic"), pt)

	respLS.installSession(test.NewLogger(), 2, ci, 1)
	assert.Same(t, ci, respLS.sessions[2].Load())

	// Now it is a hit, and the replay window the decrypt above advanced is the
	// one the next packet sees.
	got, cached, err := hi.laneSession(2)
	require.NoError(t, err)
	assert.True(t, cached)
	assert.Same(t, ci, got)

	// A racing install loses rather than swapping the session out, which would
	// throw away the replay window the live one has been accumulating. The loser's
	// packet still has to be marked seen on the winner, or dropping its session
	// would make that one counter replayable.
	other, err := newLaneConnectionState(&respLS.material, 2)
	require.NoError(t, err)
	require.True(t, ci.window.Check(test.NewLogger(), 7), "counter 7 seen before the race")
	respLS.installSession(test.NewLogger(), 2, other, 7)
	assert.Same(t, ci, respLS.sessions[2].Load())
	assert.False(t, ci.window.Check(test.NewLogger(), 7),
		"the loser's counter was not carried to the surviving window")
}

func TestLaneTxGate(t *testing.T) {
	initR, _ := runTestHandshake(t)
	ls := newTestLaneSet(t, initR, 4, 4, 4242, 4)

	// A down lane hands back nothing and raises demand, which is what gets it
	// probed.
	ci, addr := ls.txLane(1)
	assert.Nil(t, ci)
	assert.False(t, addr.IsValid())
	assert.True(t, ls.demand[1].Load())
	assert.False(t, ls.demand[2].Load(), "demand raised on an untouched lane")

	// An up lane with no session derived yet cannot happen — the probe that
	// promoted it derived one — but it must fall back rather than send in the
	// clear if it ever does.
	want := netip.MustParseAddrPort("192.0.2.1:4243")
	ls.txAddr[1].Store(&want)
	ci, _ = ls.txLane(1)
	assert.Nil(t, ci)

	// Promotion publishes the session and destination together.
	sess := laneSessionFor(t, ls, 1)
	ls.demand[1].Store(false)
	ci, addr = ls.txLane(1)
	assert.Same(t, sess, ci)
	assert.Equal(t, want, addr)
	assert.False(t, ls.demand[1].Load(), "a hit must not raise demand")

	// Lane 0 is the base tunnel and lanes at or above txLanes are receive-only.
	ci, _ = ls.txLane(0)
	assert.Nil(t, ci)
	ci, _ = ls.txLane(4)
	assert.Nil(t, ci)
}

func TestLaneSessionLookup(t *testing.T) {
	initR, _ := runTestHandshake(t)
	ls := newTestLaneSet(t, initR, 3, 4, 4242, 3)
	hi := newTestLaneHostInfo(t, initR, ls)

	assertNoLane := func(s uint8, msg string) {
		t.Helper()
		ci, cached, err := hi.laneSession(s)
		require.NoError(t, err)
		assert.Nil(t, ci, msg)
		assert.False(t, cached, msg)
	}

	assertNoLane(0, "lane 0 is the base session")
	assertNoLane(3, "a lane beyond what this tunnel covers")
	assertNoLane(255, "a lane beyond what this tunnel covers")

	// An already-derived lane is returned as a hit.
	sess := laneSessionFor(t, ls, 2)
	ci, cached, err := hi.laneSession(2)
	require.NoError(t, err)
	assert.Same(t, sess, ci)
	assert.True(t, cached)

	// A peer without lanes answers nil for every lane rather than panicking.
	bare := &HostInfo{}
	ci, _, err = bare.laneSession(1)
	require.NoError(t, err)
	assert.Nil(t, ci)
}

func TestMaxMessageCounter(t *testing.T) {
	initR, _ := runTestHandshake(t)
	ls := newTestLaneSet(t, initR, 3, 4, 4242, 3)
	hi := newTestLaneHostInfo(t, initR, ls)

	hi.ConnectionState.messageCounter.Store(5)
	assert.Equal(t, uint64(5), hi.maxMessageCounter())

	// A lane past the base is what the rehandshake threshold has to notice: the
	// base counter would sit still while the lane burns through its nonces.
	laneSessionFor(t, ls, 2).messageCounter.Store(9000)
	assert.Equal(t, uint64(9000), hi.maxMessageCounter())

	assert.Equal(t, uint64(0), (&HostInfo{}).maxMessageCounter())
}

func TestLaneRetryDelay(t *testing.T) {
	assert.Equal(t, laneRetryBase, laneRetryDelay(0))
	assert.Equal(t, 2*laneRetryBase, laneRetryDelay(1))
	assert.Equal(t, laneRetryMax, laneRetryDelay(laneMaxFails), "backoff must saturate")
}

func newLaneTestInterface(hostMap *HostMap) *Interface {
	l := test.NewLogger()
	lh := newTestLighthouse()
	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}
	ifce := &Interface{
		hostMap:            hostMap,
		inside:             &overlaytest.NoopTun{},
		outside:            &udp.NoopConn{},
		firewall:           &Firewall{},
		lightHouse:         lh,
		pki:                &PKI{},
		handshakeManager:   NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		myVpnNetworksTable: new(bart.Lite),
		messageMetrics:     newMessageMetricsOnlyRecvError(),
		writers:            []udp.Conn{&udp.NoopConn{}, &udp.NoopConn{}, &udp.NoopConn{}, &udp.NoopConn{}},
		l:                  l,
	}
	ifce.pki.cs.Store(cs)

	conf := config.NewC(l)
	punchy := NewPunchyFromConfig(l, conf, nil)
	cm := newConnectionManagerFromConfig(l, conf, hostMap, punchy)
	cm.intf = ifce
	ifce.connectionManager = cm
	ifce.handshakeManager.f = ifce
	return ifce
}

// The full TX lifecycle of a lane: demand -> probe -> ack -> up, then an
// unanswered keepalive -> demoted.
func TestLaneProbeLifecycle(t *testing.T) {
	hostMap := newHostMap(test.NewLogger())
	ifce := newLaneTestInterface(hostMap)

	initR, _ := runTestHandshake(t)
	ls := newTestLaneSet(t, initR, 4, 4, 5353, 4)
	hi := newTestLaneHostInfo(t, initR, ls)

	nb := make([]byte, 12)
	out := make([]byte, mtu)
	now := time.Now()

	// No demand: nothing is probed, so a peer we barely talk to costs nothing
	// beyond its base tunnel.
	ifce.probeLanes(hi, now, nb, out)
	ls.mu.Lock()
	for s := 1; s < 4; s++ {
		assert.True(t, ls.probe[s].sentAt.IsZero(), "lane %d probed without demand", s)
	}
	ls.mu.Unlock()

	// Demand on lane 1 alone probes lane 1 alone, aimed at the peer's port for
	// that lane.
	ls.demand[1].Store(true)
	ifce.probeLanes(hi, now, nb, out)
	ls.mu.Lock()
	require.False(t, ls.probe[1].sentAt.IsZero(), "demand did not produce a probe")
	assert.True(t, ls.probe[2].sentAt.IsZero())
	wantPort := ls.laneTargetPortLocked(1)
	assert.Equal(t, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), wantPort), ls.probe[1].target)
	gen := ls.probe[1].gen
	assert.False(t, ls.demand[1].Load(), "the probe did not consume the demand")
	ls.mu.Unlock()

	// The lane stays down until the ack lands, and a stale generation cannot
	// bring it up.
	assert.Nil(t, ls.txAddr[1].Load())
	assert.False(t, ls.noteAck(1, gen+1, now), "an ack for a superseded probe promoted the lane")
	assert.Nil(t, ls.txAddr[1].Load())

	// The matching ack promotes it, and the destination is the probed target.
	assert.True(t, ls.noteAck(1, gen, now))
	addr := ls.txAddr[1].Load()
	require.NotNil(t, addr)
	assert.Equal(t, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), wantPort), *addr)

	// A second ack is a keepalive, not a promotion.
	ls.mu.Lock()
	ls.probe[1].sentAt = now
	ls.mu.Unlock()
	assert.False(t, ls.noteAck(1, gen, now))
	assert.NotNil(t, ls.txAddr[1].Load())

	// An up lane is left alone until the keepalive comes due.
	ifce.probeLanes(hi, now, nb, out)
	ls.mu.Lock()
	assert.True(t, ls.probe[1].sentAt.IsZero(), "an up lane was re-probed early")
	ls.mu.Unlock()

	// Past the keepalive it re-proves its path...
	now = now.Add(laneKeepalive + time.Second)
	ifce.probeLanes(hi, now, nb, out)
	ls.mu.Lock()
	require.False(t, ls.probe[1].sentAt.IsZero(), "keepalive did not probe")
	ls.mu.Unlock()
	assert.NotNil(t, ls.txAddr[1].Load(), "lane demoted before its probe aged out")

	// ...and an unanswered keepalive demotes it with backoff, so the routine
	// falls back to the base tunnel.
	now = now.Add(laneProbeTimeout + time.Second)
	ifce.probeLanes(hi, now, nb, out)
	assert.Nil(t, ls.txAddr[1].Load(), "unanswered keepalive did not demote the lane")
	ls.mu.Lock()
	assert.Equal(t, uint8(1), ls.probe[1].fails)
	assert.True(t, ls.probe[1].retryAt.After(now))
	ls.mu.Unlock()

	// The backoff holds even with fresh demand.
	ls.demand[1].Store(true)
	ifce.probeLanes(hi, now, nb, out)
	ls.mu.Lock()
	assert.True(t, ls.probe[1].sentAt.IsZero(), "backoff was ignored")
	ls.mu.Unlock()
}

// A roam is a new path with no derivable relationship to the old lane ports, so
// every lane has to be rebuilt rather than moved.
func TestLaneProbeRoamResets(t *testing.T) {
	hostMap := newHostMap(test.NewLogger())
	ifce := newLaneTestInterface(hostMap)

	initR, _ := runTestHandshake(t)
	ls := newTestLaneSet(t, initR, 4, 4, 5353, 4)
	hi := newTestLaneHostInfo(t, initR, ls)

	now := time.Now()
	nb := make([]byte, 12)
	out := make([]byte, mtu)

	ls.demand[1].Store(true)
	ifce.probeLanes(hi, now, nb, out)
	ls.mu.Lock()
	gen := ls.probe[1].gen
	ls.mu.Unlock()
	require.True(t, ls.noteAck(1, gen, now))
	require.NotNil(t, ls.txAddr[1].Load())

	// New remote address: the lane is taken down, not retargeted.
	hi.SetRemote(netip.MustParseAddrPort("198.51.100.7:4242"))
	ifce.probeLanes(hi, now, nb, out)
	assert.Nil(t, ls.txAddr[1].Load(), "lane survived a roam")
	ls.mu.Lock()
	assert.Zero(t, ls.probe[1].fails, "a roam is not a lane failure")
	assert.Equal(t, netip.MustParseAddr("198.51.100.7"), ls.peerAddr)
	ls.mu.Unlock()

	// Relayed (no direct remote) means no lanes at all.
	ls.demand[1].Store(true)
	ifce.probeLanes(hi, now, nb, out)
	ls.mu.Lock()
	gen = ls.probe[1].gen
	ls.mu.Unlock()
	require.True(t, ls.noteAck(1, gen, now))
	hi.SetRemote(netip.AddrPort{})
	ifce.probeLanes(hi, now, nb, out)
	assert.Nil(t, ls.txAddr[1].Load(), "lane survived losing the direct path")
}

// A lane probe is answered on the base tunnel, echoing the header's lane, so a
// peer cannot get us to vouch for a lane it never probed.
func TestHandleLaneProbe(t *testing.T) {
	hostMap := newHostMap(test.NewLogger())
	ifce := newLaneTestInterface(hostMap)

	initR, respR := runTestHandshake(t)
	ls := newTestLaneSet(t, respR, 4, 4, 4242, 4)
	hi := newTestLaneHostInfo(t, respR, ls)

	rxc := &rxContext{nb: make([]byte, 12), scratch: make([]byte, mtu)}
	sent := &recordingUdpConn{}
	ifce.writers = []udp.Conn{sent, &udp.NoopConn{}, &udp.NoopConn{}, &udp.NoopConn{}}

	// The payload's lane is ignored in favour of the header's.
	ifce.handleLaneProbe(hi, 2, []byte{3, 42}, rxc)
	require.Len(t, sent.bufs, 1, "the ack must ride the base tunnel's socket")

	h := &header.H{}
	require.NoError(t, h.Parse(sent.bufs[0]))
	assert.Equal(t, header.Test, h.Type)
	assert.Equal(t, header.LaneProbeAck, h.Subtype)
	assert.Equal(t, uint8(0), h.Lane(), "the ack is base-tunnel traffic")

	pt, err := laneSessionFor(t, newTestLaneSet(t, initR, 4, 4, 4242, 4), 1).dKey.DecryptDanger(
		nil, sent.bufs[0][:header.Len], sent.bufs[0][header.Len:], h.MessageCounter, make([]byte, 12))
	_ = pt
	assert.Error(t, err, "the ack must not be readable with a lane key")

	// A probe claiming lane 0 or with a truncated payload is answered with
	// nothing at all.
	sent.bufs = nil
	ifce.handleLaneProbe(hi, 0, []byte{1, 2}, rxc)
	ifce.handleLaneProbe(hi, 1, []byte{1}, rxc)
	assert.Empty(t, sent.bufs)
}

func TestHandleLaneProbeAck(t *testing.T) {
	hostMap := newHostMap(test.NewLogger())
	ifce := newLaneTestInterface(hostMap)

	initR, _ := runTestHandshake(t)
	ls := newTestLaneSet(t, initR, 4, 4, 5353, 4)
	hi := newTestLaneHostInfo(t, initR, ls)

	now := time.Now()
	ls.demand[1].Store(true)
	ifce.probeLanes(hi, now, make([]byte, 12), make([]byte, mtu))
	ls.mu.Lock()
	gen := ls.probe[1].gen
	ls.mu.Unlock()

	// A short or out-of-range ack is ignored, and a peer without lanes does not
	// panic the handler.
	ifce.handleLaneProbeAck(hi, []byte{1})
	ifce.handleLaneProbeAck(hi, []byte{99, gen})
	ifce.handleLaneProbeAck(&HostInfo{}, []byte{1, gen})
	assert.Nil(t, ls.txAddr[1].Load())

	ifce.handleLaneProbeAck(hi, []byte{1, gen})
	assert.NotNil(t, ls.txAddr[1].Load())
}

// recordingUdpConn records what was written to it, one datagram per write.
type recordingUdpConn struct {
	udp.NoopConn
	bufs [][]byte
	dsts []netip.AddrPort
}

func (c *recordingUdpConn) WriteTo(b []byte, addr netip.AddrPort) error {
	c.bufs = append(c.bufs, append([]byte(nil), b...))
	c.dsts = append(c.dsts, addr)
	return nil
}

// recordingBatchWriter satisfies batch's writer interface and records what
// was flushed to it.
type recordingBatchWriter struct {
	bufs [][]byte
	dsts []netip.AddrPort
}

func (w *recordingBatchWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	for i := range bufs {
		w.bufs = append(w.bufs, append([]byte(nil), bufs[i]...))
		w.dsts = append(w.dsts, addrs[i])
	}
	return len(bufs), nil
}

func TestSendInsideMessageLaneSwap(t *testing.T) {
	hostMap := newHostMap(test.NewLogger())
	ifce := newLaneTestInterface(hostMap)

	initR, respR := runTestHandshake(t)
	ls := newTestLaneSet(t, initR, 4, 4, 5353, 4)
	hi := newTestLaneHostInfo(t, initR, ls)
	peerLS := newTestLaneSet(t, respR, 4, 4, 4242, 4)

	baseWriter := &recordingBatchWriter{}
	laneWriter := &recordingBatchWriter{}
	newTx := func(laneSlot int) *txQueue {
		return &txQueue{
			laneSlot: laneSlot,
			base:     batch.NewSendBatch(baseWriter, batch.SendBatchCap, 1<<16),
			lane:     batch.NewSendBatch(laneWriter, batch.SendBatchCap, 1<<16),
		}
	}
	tx1 := newTx(1)
	tx2 := newTx(2)

	pkt := tio.Packet{Bytes: []byte{0x45, 0, 0, 4, 1, 2, 3, 4}}
	nb := make([]byte, 12)

	// A down lane rides the base tunnel and asks for a probe.
	ifce.sendInsideMessage(hi, pkt, nb, tx1)
	tx1.flush(ifce)
	require.Len(t, baseWriter.bufs, 1)
	assert.Empty(t, laneWriter.bufs)
	assert.True(t, ls.demand[1].Load(), "a miss did not raise demand")
	assert.False(t, ls.demand[2].Load(), "demand raised on an untouched lane")

	h := &header.H{}
	require.NoError(t, h.Parse(baseWriter.bufs[0]))
	assert.Equal(t, uint8(0), h.Lane())

	// Once the lane is up, slot-1 traffic rides the lane session, the lane
	// socket and the lane's destination, tagged with the lane index. Promotion
	// normally happens on the ack of a probe, which is also what derived the
	// session, so stand both up here.
	laneRemote := netip.MustParseAddrPort("192.0.2.1:5354")
	laneSessionFor(t, ls, 1)
	ls.txAddr[1].Store(&laneRemote)
	ls.demand[1].Store(false)
	ifce.sendInsideMessage(hi, pkt, nb, tx1)
	tx1.flush(ifce)
	require.Len(t, laneWriter.bufs, 1)
	assert.Equal(t, laneRemote, laneWriter.dsts[0])
	assert.False(t, ls.demand[1].Load(), "a hit raised demand")

	require.NoError(t, h.Parse(laneWriter.bufs[0]))
	assert.Equal(t, uint8(1), h.Lane())
	assert.Equal(t, hi.remoteIndexId, h.RemoteIndex)

	// And the peer's derived lane-1 session is what opens it.
	pt, err := laneSessionFor(t, peerLS, 1).Decrypt(test.NewLogger(), h.MessageCounter, laneWriter.bufs[0], nb)
	require.NoError(t, err)
	assert.Equal(t, pkt.Bytes, pt)

	// An overflow routine sharing slot 1 (multiport.lanes < routines) rides the
	// same lane session.
	tx1b := newTx(1)
	ifce.sendInsideMessage(hi, pkt, nb, tx1b)
	tx1b.flush(ifce)
	require.Len(t, laneWriter.bufs, 2)
	require.NoError(t, h.Parse(laneWriter.bufs[1]))
	assert.Equal(t, uint8(1), h.Lane())

	// Slot 2's lane is still down: base tunnel, base batch, lane 0.
	ifce.sendInsideMessage(hi, pkt, nb, tx2)
	tx2.flush(ifce)
	require.Len(t, baseWriter.bufs, 2)
	assert.Equal(t, hi.GetRemote(), baseWriter.dsts[1])
	require.NoError(t, h.Parse(baseWriter.bufs[1]))
	assert.Equal(t, uint8(0), h.Lane())

	// Demotion falls back to the base tunnel on the very next packet.
	ls.txAddr[1].Store(nil)
	ifce.sendInsideMessage(hi, pkt, nb, tx1)
	tx1.flush(ifce)
	require.Len(t, baseWriter.bufs, 3)
	require.Len(t, laneWriter.bufs, 2)
}

func TestLaneSlotFor(t *testing.T) {
	// Overflow routines wrap onto the configured lanes round-robin.
	f := &Interface{multiport: true, laneCount: 2}
	for i, want := range []int{0, 1, 0, 1, 0, 1} {
		assert.Equal(t, want, f.laneSlotFor(i), "routine %d", i)
	}

	// Full lane count: identity mapping, one lane per routine.
	f = &Interface{multiport: true, laneCount: 4}
	for i := range 4 {
		assert.Equal(t, i, f.laneSlotFor(i), "routine %d", i)
	}

	// Multiport off: identity, each routine keeps its own writer.
	f = &Interface{multiport: false, laneCount: 0}
	for i := range 4 {
		assert.Equal(t, i, f.laneSlotFor(i), "routine %d", i)
	}
}

// Regression: deleting a hostinfo whose pending entry is NOT the one recorded
// in vpnIps must not evict a concurrently pending handshake for that address.
func TestHandshakeManagerVpnIpsIdentityDelete(t *testing.T) {
	l := test.NewLogger()
	hostMap := newHostMap(l)
	lh := newTestLighthouse()
	hm := NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig)

	vpnIp := netip.MustParseAddr("172.1.1.4")
	pendingBase := hm.StartHandshake(vpnIp, nil)
	require.NotNil(t, pendingBase)

	other := &HostInfo{vpnAddrs: []netip.Addr{vpnIp}, localIndexId: 999}
	hm.DeleteHostInfo(other)

	// The pending base handshake must still be tracked.
	assert.Equal(t, pendingBase, hm.QueryVpnAddr(vpnIp))

	// And deleting the actual owner still works.
	hm.DeleteHostInfo(pendingBase)
	assert.Nil(t, hm.QueryVpnAddr(vpnIp))
}
