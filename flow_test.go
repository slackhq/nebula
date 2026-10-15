//go:build linux && !android && !e2e_testing

package nebula

import (
	"encoding/binary"
	"io"
	"math"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
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
func newFlowTestPair(t testing.TB, cipher noise.CipherFunc, sc stagedConfig) (sender, receiver *flowTestPeer) {
	t.Helper()
	initR, respR := runTestHandshakeWith(t, cipher)
	sci, err := newConnectionStateFromResult(initR)
	require.NoError(t, err)
	rci, err := newConnectionStateFromResult(respR)
	require.NoError(t, err)
	sender = newFlowTestPeer(t, flowTestLocal, flowTestRemote, sci, 100, 200)
	receiver = newFlowTestPeer(t, flowTestRemote, flowTestLocal, rci, 200, 100)
	sender.f.staged, receiver.f.staged = sc, sc
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

// segments decodes what reached the tun. The coalescer may have merged segments back into superpackets, so this
// walks each payload in MSS steps.
func (c *flowTunCapture) segments(t testing.TB) []decodedSeg {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []decodedSeg
	for _, w := range c.writes {
		pay := w[40:]
		require.Zero(t, len(pay)%flowTestMSS, "tun write payload %d bytes", len(pay))
		for off := 0; off < len(pay); off += flowTestMSS {
			out = append(out, decodeSeg(pay[off:]))
		}
	}
	return out
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

// flowBatchQueue is a handoffQueue that hands out scripted Read batches, then fails with io.EOF. Every batch is copied
// into the current receive buffer, so a test sees the buffer ownership the Offload queue has.
type flowBatchQueue struct {
	batches [][]tio.Packet
	rxBuf   []byte
	out     []tio.Packet
	closed  chan struct{}
	// reads counts the batches handed out
	reads atomic.Int64
}

func newFlowBatchQueue(batches [][]tio.Packet) *flowBatchQueue {
	return &flowBatchQueue{batches: batches, rxBuf: make([]byte, 8*65536), closed: make(chan struct{})}
}

func (q *flowBatchQueue) Read() ([]tio.Packet, error) {
	select {
	case <-q.closed:
		return nil, os.ErrClosed
	default:
	}
	n := int(q.reads.Load())
	if n == len(q.batches) {
		return nil, io.EOF
	}
	q.out = q.out[:0]
	off := 0
	for _, p := range q.batches[n] {
		l := copy(q.rxBuf[off:], p.Bytes)
		q.out = append(q.out, tio.Packet{Bytes: q.rxBuf[off : off+l : off+l], GSO: p.GSO})
		off += l
	}
	q.reads.Add(1)
	return q.out, nil
}

func (q *flowBatchQueue) SwapRxBuf(buf []byte) []byte {
	if buf == nil {
		buf = make([]byte, len(q.rxBuf))
	}
	old := q.rxBuf
	q.rxBuf = buf
	// Scribble over the buffer we are handed, a staged batch that still pointed into it would be corrupted
	for i := range buf {
		buf[i] = 0xa5
	}
	return old
}

func (q *flowBatchQueue) Write(b []byte) (int, error) { return len(b), nil }

func (q *flowBatchQueue) Close() error { close(q.closed); return nil }

// delayedCipher changes scheduling through the real cipher interface, only in tests.
type delayedCipher struct {
	noiseutil.CipherState
	before func(uint64)
}

func (c delayedCipher) EncryptDanger(out, ad, plain []byte, n uint64, nb []byte) ([]byte, error) {
	c.before(n)
	return c.CipherState.EncryptDanger(out, ad, plain, n, nb)
}

func (c delayedCipher) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	c.before(n)
	return c.CipherState.DecryptDanger(out, ad, ciphertext, n, nb)
}

func delayCrypto(peer *flowTestPeer, before func(uint64)) {
	ci := peer.hostinfo.ConnectionState
	ci.eKey = delayedCipher{ci.eKey, before}
	ci.dKey = delayedCipher{ci.dKey, before}
}

// stagedOn enables staging with n workers.
func stagedOn(n int) stagedConfig {
	return stagedConfig{workers: n, tx: true, rx: true}
}

func stagedName(sc stagedConfig) string {
	switch {
	case sc.workers == 0:
		return "inline"
	default:
		return "staged"
	}
}

// TestFlowStagedFallback: a tun queue that cannot hand off its buffer, or a conn that cannot hand off its batches,
// keeps that direction on the inline path.
func TestFlowStagedFallback(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(3))
	batches, want := flowTestBatches(10, 2, 1, 4)
	tx := metrics.GetOrRegisterCounter("flow.tx.batches", nil)
	tx0, rx0 := tx.Count(), rxBatches.Count()
	sender.f.listenIn(plainQueue{newFlowBatchQueue(batches)}, 0)
	wire := sender.conn.captured()
	require.Equal(t, want, decryptWire(t, receiver, wire))
	require.Equal(t, tx0, tx.Count())
	receiver.receive(plainConn{&rxConn{wire: wire, batchLen: 16}})
	require.Equal(t, want, receiver.tun.segments(t))
	require.Equal(t, rx0, rxBatches.Count())
}

// plainQueue and plainConn hide SwapRxBuf and ListenOutHandoff, so they cannot hand off their batches.
type plainQueue struct{ tio.Queue }

// wireFor produces the wire packets the sender emits for batches, inline.
func wireFor(t testing.TB, sender *flowTestPeer, batches [][]tio.Packet) [][]byte {
	t.Helper()
	sc := sender.f.staged
	sender.f.staged = stagedConfig{}
	sender.f.listenIn(newFlowBatchQueue(batches), 0)
	sender.f.staged = sc
	wire := sender.conn.captured()
	sender.conn.pkts, sender.conn.addrs = nil, nil
	return wire
}

// rxConn plays wire back to listenOut through the buffer handoff, in batches of batchLen or of the scripted sizes
// (the last one repeating), and captures what is sent back. Every buffer handed back is scribbled over before it is
// read into, so a stage still using one shows corruption. from, when set, picks each packet's source address by its
// index in wire.
type rxConn struct {
	flowCaptureConn
	wire     [][]byte
	batchLen int
	sizes    []int
	from     func(i int) netip.AddrPort
	swaps    int
}

func (c *rxConn) ListenOut(r udp.EncReader, flush func()) error {
	return c.ListenOutHandoff(r, func(bufs [][]byte) [][]byte {
		flush()
		return bufs
	})
}

func (c *rxConn) ListenOutHandoff(r udp.EncReader, handoff func(bufs [][]byte) [][]byte) error {
	n := c.batchLen
	for _, size := range c.sizes {
		n = max(n, size)
	}
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, udp.MTU)
	}
	for off, k := 0, 0; off < len(c.wire); k++ {
		size := c.batchLen
		if len(c.sizes) > 0 {
			size = c.sizes[min(k, len(c.sizes)-1)]
		}
		end := min(off+size, len(c.wire))
		for i, p := range c.wire[off:end] {
			n := copy(bufs[i], p)
			from := flowTestUnder
			if c.from != nil {
				from = c.from(off + i)
			}
			r(from, bufs[i][:n:n])
		}
		next := handoff(bufs)
		if len(next) != len(bufs) {
			panic("handoff returned the wrong number of buffers")
		}
		bufs = next
		for _, b := range bufs {
			for j := range b[:udp.MTU] {
				b[j] = 0x5a
			}
		}
		c.swaps++
		off = end
	}
	return os.ErrClosed
}

type plainConn struct{ udp.Conn }

var rxBatches = metrics.GetOrRegisterCounter("flow.rx.batches", nil)

// receive runs the peer's listenOut over conn until conn runs out.
func (p *flowTestPeer) receive(conn udp.Conn) {
	p.f.writers = []udp.Conn{conn}
	p.f.outside = conn
	p.f.listenOut(0)
}

// TestFlowStagedFirewallParity: both paths apply the same outbound and inbound policy. An authenticated inbound
// denial still consumes its replay counter, exactly as inline Decrypt does.
func TestFlowStagedFirewallParity(t *testing.T) {
	for _, sc := range []stagedConfig{{}, stagedOn(2)} {
		t.Run(stagedName(sc), func(t *testing.T) {
			batches, _ := flowTestBatches(4, 3, 1, 8)
			sender, _ := newFlowTestPair(t, noise.CipherChaChaPoly, sc)
			sender.f.firewall.OutRules = newFirewallTable()
			sender.f.listenIn(newFlowBatchQueue(batches), 0)
			require.Empty(t, sender.conn.captured())

			sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, sc)
			wire := wireFor(t, sender, batches)
			receiver.f.firewall.InRules = newFirewallTable()
			receiver.receive(&rxConn{wire: wire, batchLen: 64})
			require.Empty(t, receiver.tun.writes)
			for _, pkt := range wire {
				h := &header.H{}
				require.NoError(t, h.Parse(pkt))
				require.False(t, receiver.hostinfo.ConnectionState.window.Check(receiver.f.l, h.MessageCounter))
			}
		})
	}
}

// TestFlowStagedCipherFallback runs the parsed configuration with the real AES cipher: transmit falls back to inline
// when the build needs nonce-ordered encryption (BoringCrypto, FIPS), receive decryption stays staged.
func TestFlowStagedCipherFallback(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	c.Settings = map[string]any{"tun": map[string]any{"staged": map[string]any{"workers": 2}}}
	sender, receiver := newFlowTestPair(t, noiseutil.CipherAESGCM, parseStagedConfig(c, l))
	require.Equal(t, !noiseutil.EncryptLockNeeded, sender.f.staged.tx)
	require.True(t, sender.f.staged.rx)
	batches, want := flowTestBatches(4, 8, 1, 45)
	tx := metrics.GetOrRegisterCounter("flow.tx.batches", nil)
	tx0, rx0 := tx.Count(), rxBatches.Count()
	sender.f.listenIn(newFlowBatchQueue(batches), 0)
	if noiseutil.EncryptLockNeeded {
		require.Equal(t, tx0, tx.Count())
	}
	receiver.receive(&rxConn{wire: sender.conn.captured(), batchLen: 512})
	require.Greater(t, rxBatches.Count(), rx0)
	require.Equal(t, want, receiver.tun.segments(t))
}
