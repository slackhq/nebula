package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/overlaytest"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestBaseHostInfo(vpnIp netip.Addr, localIdx, remoteIdx uint32, laneCount int) *HostInfo {
	base := &HostInfo{
		vpnAddrs:        []netip.Addr{vpnIp},
		localIndexId:    localIdx,
		remoteIndexId:   remoteIdx,
		remotes:         NewRemoteList([]netip.Addr{vpnIp}, nil),
		HandshakePacket: map[uint8][]byte{},
	}
	base.SetRemote(netip.MustParseAddrPort("192.0.2.1:4242"))
	base.lanes = newLaneState(laneCount, uint16(laneCount), 4242)
	return base
}

func newTestLaneHostInfo(base *HostInfo, laneIndex uint16, localIdx, remoteIdx uint32, owned bool) *HostInfo {
	lane := &HostInfo{
		vpnAddrs:        base.vpnAddrs,
		localIndexId:    localIdx,
		remoteIndexId:   remoteIdx,
		remotes:         NewRemoteList(base.vpnAddrs, nil),
		HandshakePacket: map[uint8][]byte{},
		sockIdx:         int(laneIndex),
		laneIndex:       laneIndex,
		laneOwned:       owned,
		parent:          base,
	}
	lane.SetRemote(netip.MustParseAddrPort("192.0.2.1:4243"))
	return lane
}

func TestLaneHostmapLifecycle(t *testing.T) {
	l := test.NewLogger()
	hostMap := newHostMap(l)
	ifce := &Interface{l: l} // connectionManager nil is tolerated by unlockedAddLane

	vpnIp := netip.MustParseAddr("172.1.1.2")
	base := newTestBaseHostInfo(vpnIp, 100, 200, 4)

	hostMap.Lock()
	hostMap.unlockedAddHostInfo(base, ifce)
	hostMap.Unlock()

	lane := newTestLaneHostInfo(base, 1, 101, 201, true)
	hostMap.Lock()
	hostMap.unlockedAddLane(lane, ifce)
	hostMap.Unlock()
	base.lanes.txLanes[1].Store(lane)

	// The lane is reachable by index (RX demux, recv_error) but never a Hosts primary.
	assert.Equal(t, lane, hostMap.QueryIndex(101))
	assert.Equal(t, lane, hostMap.QueryReverseIndex(201))
	assert.Equal(t, base, hostMap.Hosts[vpnIp])

	// A lane can never be promoted to primary.
	hostMap.Lock()
	assert.False(t, hostMap.unlockedMakePrimary(lane))
	hostMap.Unlock()
	assert.Equal(t, base, hostMap.Hosts[vpnIp])

	// Deleting the lane clears only its slot, applies backoff, and never
	// reports "no more tunnels to peer" (final).
	final := hostMap.DeleteHostInfo(lane)
	assert.False(t, final)
	assert.Nil(t, hostMap.QueryIndex(101))
	assert.Equal(t, base, hostMap.Hosts[vpnIp])
	assert.Nil(t, base.lanes.txLanes[1].Load())
	base.lanes.Lock()
	assert.Equal(t, uint8(1), base.lanes.txFails[1])
	assert.False(t, base.lanes.txPending[1])
	assert.True(t, base.lanes.txRetryAt[1].After(time.Now()))
	base.lanes.Unlock()

	// Idempotent: deleting again must not bump the backoff further.
	hostMap.DeleteHostInfo(lane)
	base.lanes.Lock()
	assert.Equal(t, uint8(2), base.lanes.txFails[1]) // noteLaneFailure still runs, but slot CAS is a no-op
	base.lanes.Unlock()
}

func TestLaneHostmapCascadeDelete(t *testing.T) {
	l := test.NewLogger()
	hostMap := newHostMap(l)
	ifce := &Interface{l: l}

	vpnIp := netip.MustParseAddr("172.1.1.3")
	base := newTestBaseHostInfo(vpnIp, 300, 400, 4)

	hostMap.Lock()
	hostMap.unlockedAddHostInfo(base, ifce)
	hostMap.Unlock()

	owned := newTestLaneHostInfo(base, 1, 301, 401, true)
	peer := newTestLaneHostInfo(base, 2, 302, 402, false)
	hostMap.Lock()
	hostMap.unlockedAddLane(owned, ifce)
	hostMap.unlockedAddLane(peer, ifce)
	hostMap.Unlock()
	base.lanes.txLanes[1].Store(owned)
	base.lanes.Lock()
	base.lanes.peerLanes = append(base.lanes.peerLanes, peer)
	base.lanes.Unlock()

	// Deleting the base takes the whole lane family with it.
	final := hostMap.DeleteHostInfo(base)
	assert.True(t, final)
	assert.Nil(t, hostMap.QueryIndex(300))
	assert.Nil(t, hostMap.QueryIndex(301))
	assert.Nil(t, hostMap.QueryIndex(302))
	assert.Nil(t, hostMap.Hosts[vpnIp])
}

// Regression: deleting a hostinfo whose pending entry is NOT the one recorded
// in vpnIps (e.g. a lane, whose vpnAddrs alias the base's) must not evict a
// concurrently pending base handshake for the same address.
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

func newLaneTestConnectionManager(hostMap *HostMap) (*connectionManager, *Interface) {
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
		l:                  l,
	}
	ifce.pki.cs.Store(cs)

	conf := config.NewC(test.NewLogger())
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	cm := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	cm.intf = ifce
	ifce.connectionManager = cm
	ifce.handshakeManager.f = ifce
	return cm, ifce
}

func TestLaneTrafficDecision(t *testing.T) {
	hostMap := newHostMap(test.NewLogger())
	cm, ifce := newLaneTestConnectionManager(hostMap)

	vpnIp := netip.MustParseAddr("172.1.1.5")
	base := newTestBaseHostInfo(vpnIp, 500, 600, 4)
	base.ConnectionState = &ConnectionState{}
	hostMap.Lock()
	hostMap.unlockedAddHostInfo(base, ifce)
	hostMap.Unlock()

	lane := newTestLaneHostInfo(base, 1, 501, 601, true)
	lane.ConnectionState = &ConnectionState{}
	hostMap.Lock()
	hostMap.unlockedAddLane(lane, ifce)
	hostMap.Unlock()
	base.lanes.txLanes[1].Store(lane)

	now := time.Now()

	// A lane with inbound traffic is alive and never swaps primary or
	// migrates relays.
	lane.in.Store(true)
	decision, resolved, _ := cm.makeTrafficDecision(lane.localIndexId, now)
	assert.Equal(t, doNothing, decision)
	assert.Equal(t, lane, resolved)
	assert.False(t, lane.pendingDeletion.Load())

	// An idle lane gets an active keepalive test...
	decision, _, _ = cm.makeTrafficDecision(lane.localIndexId, now)
	assert.Equal(t, sendTestPacket, decision)
	assert.True(t, lane.pendingDeletion.Load())

	// ...and is declared dead when the test goes unanswered.
	decision, _, _ = cm.makeTrafficDecision(lane.localIndexId, now)
	assert.Equal(t, deleteTunnel, decision)
}

func TestBaseInactiveConsidersLanes(t *testing.T) {
	hostMap := newHostMap(test.NewLogger())
	cm, _ := newLaneTestConnectionManager(hostMap)
	cm.dropInactive.Store(true)
	cm.inactivityTimeout.Store(int64(10 * time.Minute))

	now := time.Now()
	vpnIp := netip.MustParseAddr("172.1.1.6")
	base := newTestBaseHostInfo(vpnIp, 700, 800, 4)
	base.lastUsed = now.Add(-time.Hour)

	// Base alone: inactive.
	_, inactive := cm.isInactive(base, now)
	assert.True(t, inactive)

	// A recently used lane keeps the base alive.
	lane := newTestLaneHostInfo(base, 1, 701, 801, true)
	lane.lastUsed = now.Add(-time.Minute)
	base.lanes.txLanes[1].Store(lane)
	_, inactive = cm.isInactive(base, now)
	assert.False(t, inactive)

	// Peer-owned lanes count too.
	base.lanes.txLanes[1].Store(nil)
	base.lanes.Lock()
	base.lanes.peerLanes = append(base.lanes.peerLanes, lane)
	base.lanes.Unlock()
	_, inactive = cm.isInactive(base, now)
	assert.False(t, inactive)
}

// recordingBatchWriter satisfies batch's writer interface and records what
// was flushed to it.
type recordingBatchWriter struct {
	bufs [][]byte
	dsts []netip.AddrPort
}

func (w *recordingBatchWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort, outerECNs []byte) error {
	for i := range bufs {
		w.bufs = append(w.bufs, append([]byte(nil), bufs[i]...))
		w.dsts = append(w.dsts, addrs[i])
	}
	return nil
}

func TestSendInsideMessageLaneSwap(t *testing.T) {
	hostMap := newHostMap(test.NewLogger())
	cm, ifce := newLaneTestConnectionManager(hostMap)
	_ = cm

	vpnIp := netip.MustParseAddr("172.1.1.7")
	base := newTestBaseHostInfo(vpnIp, 900, 1000, 4)
	lane := newTestLaneHostInfo(base, 1, 901, 1001, true)

	// Real cipher states from a real handshake so encryption works.
	baseInit, _ := runTestHandshake(t)
	laneInit, _ := runTestHandshake(t)
	base.ConnectionState = newConnectionStateFromResult(baseInit)
	lane.ConnectionState = newConnectionStateFromResult(laneInit)

	baseWriter := &recordingBatchWriter{}
	laneWriter := &recordingBatchWriter{}
	tx := &txQueue{
		base: batch.NewSendBatch(baseWriter, batch.SendBatchCap, 1<<16),
		lane: batch.NewSendBatch(laneWriter, batch.SendBatchCap, 1<<16),
	}

	pkt := tio.Packet{Bytes: []byte{0x45, 0, 0, 4, 1, 2, 3, 4}}
	nb := make([]byte, 12)

	// With the lane published, routine 1's traffic uses the lane session and
	// the lane batch.
	base.lanes.txLanes[1].Store(lane)
	ifce.sendInsideMessage(base, pkt, nb, tx, 1)
	tx.flush(ifce.l, 1)
	require.Len(t, laneWriter.bufs, 1)
	require.Empty(t, baseWriter.bufs)
	assert.Equal(t, lane.GetRemote(), laneWriter.dsts[0])

	h := &header.H{}
	require.NoError(t, h.Parse(laneWriter.bufs[0]))
	assert.Equal(t, lane.remoteIndexId, h.RemoteIndex)

	// Routine 2 has no lane: base tunnel, base batch.
	ifce.sendInsideMessage(base, pkt, nb, tx, 2)
	tx.flush(ifce.l, 1)
	require.Len(t, baseWriter.bufs, 1)
	assert.Equal(t, base.GetRemote(), baseWriter.dsts[0])
	require.NoError(t, h.Parse(baseWriter.bufs[0]))
	assert.Equal(t, base.remoteIndexId, h.RemoteIndex)

	// Lane death: slot cleared, instant fallback to base.
	base.lanes.txLanes[1].Store(nil)
	ifce.sendInsideMessage(base, pkt, nb, tx, 1)
	tx.flush(ifce.l, 1)
	require.Len(t, baseWriter.bufs, 2)
	require.Len(t, laneWriter.bufs, 1)
}

func TestCompleteLaneResponder(t *testing.T) {
	hostMap := newHostMap(test.NewLogger())
	_, ifce := newLaneTestConnectionManager(hostMap)
	ifce.writers = []udp.Conn{&udp.NoopConn{}, &udp.NoopConn{}, &udp.NoopConn{}, &udp.NoopConn{}}
	ifce.messageMetrics = newMessageMetricsOnlyRecvError()

	hm := ifce.handshakeManager
	hm.config.laneCount = 4
	hm.config.lanePortCount = 4
	hm.config.laneBasePort = 4242

	// A real handshake supplies usable keys and a peer cert.
	_, respR := runTestHandshake(t)
	respR.PeerLaneIndex = 2
	respR.PeerPortCount = 4
	respR.PeerBasePort = 5353

	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.9:5355"), SockIdx: 2}
	packet := make([]byte, header.Len+8)
	copy(packet[header.Len:], []byte("stage0!!"))
	vpnAddrs := []netip.Addr{netip.MustParseAddr("172.1.1.9")}

	// No base tunnel: the lane handshake is dropped, nothing registered.
	hm.completeLaneResponder(via, packet, []byte("resp"), respR, vpnAddrs)
	assert.Nil(t, hostMap.QueryIndex(respR.LocalIndex))

	// With a live base the lane attaches to it.
	base := newTestBaseHostInfo(vpnAddrs[0], 1300, 1400, 4)
	base.ConnectionState = &ConnectionState{}
	hostMap.Lock()
	hostMap.unlockedAddHostInfo(base, ifce)
	hostMap.Unlock()

	hm.completeLaneResponder(via, packet, []byte("resp"), respR, vpnAddrs)
	lane := hostMap.QueryIndex(respR.LocalIndex)
	require.NotNil(t, lane)
	assert.True(t, lane.isLane())
	assert.False(t, lane.laneOwned)
	assert.Equal(t, uint16(2), lane.laneIndex)
	assert.Equal(t, 2, lane.sockIdx)
	assert.Equal(t, via.UdpAddr, lane.GetRemote())
	assert.Equal(t, base, hostMap.Hosts[vpnAddrs[0]], "lane must not displace the base as primary")
	base.lanes.Lock()
	assert.Len(t, base.lanes.peerLanes, 1)
	base.lanes.Unlock()

	// A byte-identical stage-0 retransmit resends the cached response and
	// must not register a second lane.
	hm.completeLaneResponder(via, packet, []byte("resp"), respR, vpnAddrs)
	base.lanes.Lock()
	assert.Len(t, base.lanes.peerLanes, 1)
	base.lanes.Unlock()

	// An out-of-range lane index is refused.
	respR2 := *respR
	respR2.PeerLaneIndex = 9
	respR2.LocalIndex = respR.LocalIndex + 1
	hm.completeLaneResponder(via, packet, []byte("resp"), &respR2, vpnAddrs)
	assert.Nil(t, hostMap.QueryIndex(respR2.LocalIndex))
}

func TestEnsureLanesBackoffOnStage0Failure(t *testing.T) {
	hostMap := newHostMap(test.NewLogger())
	_, ifce := newLaneTestConnectionManager(hostMap)

	// laneCount enables multiport in the manager; the dummy CertState has no
	// credential, so stage-0 construction must fail and release the slot with
	// backoff rather than leaving it claimed forever.
	hm := ifce.handshakeManager
	hm.config.laneCount = 4
	hm.config.lanePortCount = 4
	hm.config.laneBasePort = 4242

	vpnIp := netip.MustParseAddr("172.1.1.8")
	base := newTestBaseHostInfo(vpnIp, 1100, 1200, 4)

	hm.EnsureLanes(base)

	base.lanes.Lock()
	defer base.lanes.Unlock()
	for i := 1; i < 4; i++ {
		assert.False(t, base.lanes.txPending[i], "slot %d still pending", i)
		assert.Equal(t, uint8(1), base.lanes.txFails[i], "slot %d fails", i)
		assert.True(t, base.lanes.txRetryAt[i].After(time.Now()), "slot %d retryAt", i)
	}
}
