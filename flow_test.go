//go:build linux && !android && !e2e_testing

package nebula

import (
	"encoding/binary"
	"io"
	"math"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/require"
)

// flowTestMSS is the segment payload size of the synthetic TSO superpackets.
const flowTestMSS = 1200

var (
	flowTestLocal  = netip.MustParseAddr("10.0.0.1")
	flowTestRemote = netip.MustParseAddr("10.0.0.2")
	flowTestUnder  = netip.MustParseAddrPort("192.0.2.2:4242")
)

// flowTCPSuperpacket builds an IPv4/TCP TSO superpacket from local to remote carrying segs segments. Segment i's
// payload starts with the flow id, the superpacket seq and i, so a receiver can check what it got and in which order.
func flowTCPSuperpacket(flow uint16, seq uint32, segs int) tio.Packet {
	const hdr = 40
	pay := segs * flowTestMSS
	b := make([]byte, hdr+pay)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(min(hdr+pay, 65535)))
	b[8] = 64
	b[9] = iputil.IPProtocolTCP
	copy(b[12:16], flowTestLocal.AsSlice())
	copy(b[16:20], flowTestRemote.AsSlice())
	binary.BigEndian.PutUint16(b[20:22], 10000+flow)
	binary.BigEndian.PutUint16(b[22:24], 80)
	binary.BigEndian.PutUint32(b[24:28], seq*uint32(pay))
	b[32] = 0x50
	b[33] = 0x10 // ACK
	binary.BigEndian.PutUint16(b[34:36], 65535)
	for i := range segs {
		p := b[hdr+i*flowTestMSS:]
		binary.BigEndian.PutUint16(p[0:2], flow)
		binary.BigEndian.PutUint32(p[2:6], seq)
		binary.BigEndian.PutUint16(p[6:8], uint16(i))
	}
	if segs == 1 {
		return tio.Packet{Bytes: b}
	}
	return tio.Packet{Bytes: b, GSO: tio.GSOInfo{Size: flowTestMSS, HdrLen: hdr, CsumStart: 20, Proto: tio.GSOProtoTCP}}
}

// decodedSeg identifies one segment by the marker flowTCPSuperpacket put in its payload.
type decodedSeg struct {
	flow uint16
	seq  uint32
	idx  uint16
}

func decodeSeg(p []byte) decodedSeg {
	return decodedSeg{flow: binary.BigEndian.Uint16(p[0:2]), seq: binary.BigEndian.Uint32(p[2:6]), idx: binary.BigEndian.Uint16(p[6:8])}
}

// flowTestBatches builds n reads of per superpackets of segs segments, across flows interleaved flows, and the
// segments they carry in order.
func flowTestBatches(n, per, flows, segs int) ([][]tio.Packet, []decodedSeg) {
	var batches [][]tio.Packet
	var want []decodedSeg
	seq := make([]uint32, flows)
	for range n {
		var b []tio.Packet
		for j := range per {
			flow := uint16(j % flows)
			b = append(b, flowTCPSuperpacket(flow, seq[flow], segs))
			for s := range segs {
				want = append(want, decodedSeg{flow: flow, seq: seq[flow], idx: uint16(s)})
			}
			seq[flow]++
		}
		batches = append(batches, b)
	}
	return batches, want
}

// flowTestPeer is one end of a tunnel: the interface, the hostinfo for the other end, and its capture points.
type flowTestPeer struct {
	f        *Interface
	hostinfo *HostInfo
	conn     *flowCaptureConn
	tun      *flowTunCapture
}

// newFlowTestPair builds two interfaces joined by one real tunnel (keys from an actual handshake). sender sends from
// flowTestLocal to flowTestRemote, receiver is the far side.
func newFlowTestPair(t testing.TB, cipher noise.CipherFunc) (sender, receiver *flowTestPeer) {
	t.Helper()
	initR, respR := runTestHandshakeWith(t, cipher)
	sci, err := newConnectionStateFromResult(initR)
	require.NoError(t, err)
	rci, err := newConnectionStateFromResult(respR)
	require.NoError(t, err)
	sender = newFlowTestPeer(t, flowTestLocal, flowTestRemote, sci, 100, 200)
	receiver = newFlowTestPeer(t, flowTestRemote, flowTestLocal, rci, 200, 100)
	return sender, receiver
}

func newFlowTestPeer(t testing.TB, me, them netip.Addr, ci *ConnectionState, localIdx, remoteIdx uint32) *flowTestPeer {
	l := test.NewLogger()
	hm := newHostMap(l)
	hm.preferredRanges.Store(&[]netip.Prefix{})

	myNets, myAddrs := &bart.Lite{}, &bart.Lite{}
	myNets.Insert(netip.PrefixFrom(me, 24))
	myAddrs.Insert(netip.PrefixFrom(me, 32))
	myCert := &dummyCert{version: cert.Version1, networks: []netip.Prefix{netip.PrefixFrom(me, 24)}}
	theirCert := &dummyCert{version: cert.Version1, networks: []netip.Prefix{netip.PrefixFrom(them, 24)}, name: "peer"}
	ci.peerCert = &cert.CachedCertificate{Certificate: theirCert, InvertedGroups: map[string]struct{}{}}

	fw := NewFirewall(l, time.Minute, time.Minute, time.Minute, myCert)
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))

	conn, tun := &flowCaptureConn{}, &flowTunCapture{}
	lh := newTestLighthouse()
	lh.remoteAllowList.Store(&RemoteAllowList{})

	f := &Interface{
		hostMap:            hm,
		outside:            conn,
		firewall:           fw,
		lightHouse:         lh,
		pki:                &PKI{},
		myVpnNetworksTable: myNets,
		myVpnAddrsTable:    myAddrs,
		routines:           1,
		writers:            []udp.Conn{conn},
		messageMetrics:     &MessageMetrics{txExhausted: metrics.NewCounter()},
		metricTxDropped:    metrics.NilCounter{},
		l:                  l,
	}
	f.ctx = t.Context()
	f.pki.caPool.Store(cert.NewCAPool())
	// Never promote or requery, those would put extra test packets on the wire
	f.tryPromoteEvery.Store(math.MaxUint32)
	f.reQueryEvery.Store(math.MaxUint32)
	f.batchers = []*batch.MultiCoalescer{batch.NewMultiCoalescer(tun, l)}
	f.connectionManager = &connectionManager{
		intf:          f,
		relayUsed:     map[uint32]struct{}{},
		relayUsedLock: &sync.RWMutex{},
		trafficTimer:  NewLockingTimerWheel[uint32](time.Second, time.Minute),
	}
	f.handshakeManager = NewHandshakeManager(l, hm, lh, conn, defaultHandshakeConfig)
	f.handshakeManager.f = f

	hostinfo := &HostInfo{
		ConnectionState: ci,
		vpnAddrs:        []netip.Addr{them},
		localIndexId:    localIdx,
		remoteIndexId:   remoteIdx,
		relayState:      RelayState{relayForByAddr: map[netip.Addr]*Relay{}, relayForByIdx: map[uint32]*Relay{}},
	}
	hostinfo.remote.Store(&flowTestUnder)
	hostinfo.buildNetworks(myNets, theirCert)
	hm.unlockedAddHostInfo(hostinfo, f)

	return &flowTestPeer{f: f, hostinfo: hostinfo, conn: conn, tun: tun}
}

// flowCaptureConn records every packet sent, in order, as copies.
type flowCaptureConn struct {
	udp.NoopConn
	mu    sync.Mutex
	pkts  [][]byte
	addrs []netip.AddrPort
	// delay, when set, slows every WriteBatch down so batches pile up in flight
	delay time.Duration
}

func (c *flowCaptureConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	time.Sleep(c.delay)
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, b := range bufs {
		c.pkts = append(c.pkts, append([]byte(nil), b...))
		c.addrs = append(c.addrs, addrs[i])
	}
	return len(bufs), nil
}

func (c *flowCaptureConn) WriteTo(b []byte, addr netip.AddrPort) error {
	_, err := c.WriteBatch([][]byte{b}, []netip.AddrPort{addr})
	return err
}

func (c *flowCaptureConn) captured() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.pkts...)
}

// flowTunCapture is a tun queue that records every plaintext write.
type flowTunCapture struct {
	mu     sync.Mutex
	writes [][]byte
	// delay, when set, slows every write down
	delay time.Duration
}

func (c *flowTunCapture) Read() ([]tio.Packet, error) { return nil, io.EOF }
func (c *flowTunCapture) Close() error                { return nil }
func (c *flowTunCapture) Write(b []byte) (int, error) {
	time.Sleep(c.delay)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

// decryptWire checks every wire packet decrypts on the receiver, in order, with strictly increasing counters, and
// returns what each one carried. It uses its own replay window and copies, so the wire can still be fed to the
// receiver afterwards.
func decryptWire(t testing.TB, receiver *flowTestPeer, wire [][]byte) []decodedSeg {
	t.Helper()
	peer := receiver.hostinfo.ConnectionState
	ci := &ConnectionState{dKey: peer.dKey, window: NewBits(peer.window.length)}
	nb := make([]byte, 12)
	var last uint64
	out := make([]decodedSeg, 0, len(wire))
	for i, pkt := range wire {
		h := &header.H{}
		require.NoError(t, h.Parse(pkt))
		require.Equal(t, header.Message, h.Type)
		require.Equal(t, receiver.hostinfo.localIndexId, h.RemoteIndex)
		require.Greater(t, h.MessageCounter, last, "wire packet %d: counter %d after %d", i, h.MessageCounter, last)
		last = h.MessageCounter
		plain, err := ci.Decrypt(receiver.f.l, h.MessageCounter, append([]byte(nil), pkt...), nb)
		require.NoError(t, err, "wire packet %d", i)
		out = append(out, decodeSeg(plain[40:]))
	}
	return out
}
