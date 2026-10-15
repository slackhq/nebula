//go:build linux && !android && !e2e_testing

package nebula

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/cpupick"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"
)

// TestReservedEncryptionMatchesInline encrypts a batch with counters reserved up front: the receiver accepts every
// segment, in order.
func TestReservedEncryptionMatchesInline(t *testing.T) {
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedConfig{})
	packets, want := flowTestBatches(1, 3, 3, 9)
	r := txReserver{f: sender.f}
	items := r.collect(nil, packets[0], &firewall.ParsedPacket{}, make([]byte, mtu), 0, nil)
	require.Equal(t, uint64(len(want)), r.tunnels[0].n)
	sb := batch.NewSendBatch(sender.conn, 128, 65536)
	for _, it := range r.reserve(items) {
		sender.f.encryptTxItem(&it, make([]byte, 12), sb)
	}
	sender.f.flushSendBatch(sb, 0)
	require.Equal(t, want, decryptWire(t, receiver, sender.conn.captured()))
}

// TestSegmentCount checks tio.Packet.SegmentCount predicts exactly the segments tio.SegmentSuperpacket cuts, odd tails included.
func TestSegmentCount(t *testing.T) {
	require.Equal(t, 1, tio.Packet{Bytes: make([]byte, 60)}.SegmentCount())
	for _, segs := range []int{1, 2, 3, 45} {
		for _, tail := range []int{0, 1, flowTestMSS - 1} {
			pkt := flowTCPSuperpacket(0, 0, segs)
			pkt.Bytes = pkt.Bytes[:len(pkt.Bytes)-tail]
			pkt.GSO = tio.GSOInfo{Size: flowTestMSS, HdrLen: 40, CsumStart: 20, Proto: tio.GSOProtoTCP}
			want, got := pkt.SegmentCount(), 0
			require.NoError(t, tio.SegmentSuperpacket(pkt, func([]byte) error { got++; return nil }))
			require.Equal(t, want, got, "segs %d tail %d", segs, tail)
		}
	}
}

// TestFlowStagedTXOrderAndCounters runs the staged transmit pipeline with shuffled workers and a slow socket, so the
// sender lags and the reader runs into backpressure, then fails the tun read with batches in flight: the wire must
// carry every segment once, in tun read order, under strictly increasing counters that were each reserved exactly
// once, and the read error is still reported.
func TestFlowStagedTXOrderAndCounters(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, cipher := range []noise.CipherFunc{noiseutil.CipherAESGCM, noise.CipherChaChaPoly} {
		t.Run(cipher.CipherName(), func(t *testing.T) {
			if cipher.CipherName() == noiseutil.CipherAESGCM.CipherName() && noiseutil.EncryptLockNeeded {
				t.Skip("AES-GCM requires encryption in nonce order")
			}
			sender, receiver := newFlowTestPair(t, cipher, stagedOn(4))
			delayCrypto(sender, func(n uint64) {
				if n%54 == 0 {
					time.Sleep(time.Millisecond)
				}
			})
			// Far slower than the reader, even under the race detector
			sender.conn.delay = 8 * time.Millisecond
			batches, want := flowTestBatches(60, 6, 3, 9)
			start := sender.hostinfo.ConnectionState.messageCounter.Load()
			tx := metrics.GetOrRegisterCounter("flow.tx.batches", nil)
			tx0 := tx.Count()
			sender.f.listenIn(newFlowBatchQueue(batches), 0)
			require.Equal(t, int64(len(batches)), tx.Count()-tx0, "every batch uses the ordered sender")
			require.Equal(t, want, decryptWire(t, receiver, sender.conn.captured()), "wire order must match tun read order")
			require.Equal(t, start+uint64(len(want)), sender.hostinfo.ConnectionState.messageCounter.Load())
			require.NotNil(t, sender.f.fatalErr.Load())
		})
	}
}

// TestFlowStagedTXCloseInFlight closes the interface and tun while batches are in flight, 20 times over.
func TestFlowStagedTXCloseInFlight(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for range 20 {
		sender, _ := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(3))
		sender.conn.delay = time.Millisecond
		batches, _ := flowTestBatches(400, 4, 2, 8)
		q := newFlowBatchQueue(batches)
		done := make(chan struct{})
		go func() { sender.f.listenIn(q, 0); close(done) }()
		require.Eventually(t, func() bool { return q.reads.Load() > 5 }, 5*time.Second, 100*time.Microsecond)
		sender.f.closed.Store(true)
		require.NoError(t, q.Close())
		<-done
	}
}

// TestFlowStagedTXExhausted drops every batch of a tunnel whose counter runs out, like inline sends do.
func TestFlowStagedTXExhausted(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	sender, _ := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(2))
	ci := sender.hostinfo.ConnectionState
	ci.messageCounter.Store(RejectAfterMessages - 3)
	sender.f.listenIn(newFlowBatchQueue([][]tio.Packet{{flowTCPSuperpacket(0, 0, 10)}, {flowTCPSuperpacket(0, 1, 2)}}), 0)
	require.Empty(t, sender.conn.captured())
	require.Equal(t, RejectAfterMessages, ci.messageCounter.Load())
	require.Equal(t, int64(12), sender.f.messageMetrics.txExhausted.Count())
	require.Zero(t, ci.txBudget.state.Load())
}

// TestFlowStagedTXRelay sends staged batches, and an empty read, through a relay: outer and inner layers both verify,
// in order, and go to the relay.
// With a tiny MSS, the middle superpacket alone exceeds the tunnels' whole credit: it must be split, not admitted as an
// unbounded lone batch, with either replay window.
func TestFlowStagedTXRelay(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, window := range budgetWindows {
		t.Run(fmt.Sprintf("window=%d", window), func(t *testing.T) {
			sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(2))
			sender.hostinfo.ConnectionState.window = NewBits(window)
			receiver.hostinfo.ConnectionState.window = NewBits(window)
			relayRemote, relayHI, relayPeer := addTestRelay(t, sender, window)
			batches, want := flowTestBatches(2, 3, 1, 6)
			var payload []byte
			large := flowTCPSuperpacket(0, 9, 45)
			large.GSO.Size = 1
			payload = append([]byte(nil), large.Bytes[40:]...)
			batches = [][]tio.Packet{batches[0], {large}, batches[1]}
			sender.f.listenIn(newFlowBatchQueue(append(batches, nil)), 0)
			wire := sender.conn.captured()
			require.Len(t, wire, len(want)+len(payload))
			var got []decodedSeg
			var tiny []byte
			var lastOuter, lastInner uint64
			for i, pkt := range wire {
				require.Equal(t, relayRemote, sender.conn.addrs[i])
				h := &header.H{}
				require.NoError(t, h.Parse(pkt))
				require.Greater(t, h.MessageCounter, lastOuter)
				lastOuter = h.MessageCounter
				require.NoError(t, relayPeer.VerifyRelay(nil, h.MessageCounter, pkt, make([]byte, 12)))
				pkt = pkt[header.Len : len(pkt)-16]
				require.NoError(t, h.Parse(pkt))
				require.Greater(t, h.MessageCounter, lastInner)
				lastInner = h.MessageCounter
				plain, err := receiver.hostinfo.ConnectionState.Decrypt(receiver.f.l, h.MessageCounter, pkt, make([]byte, 12))
				require.NoError(t, err)
				if len(plain) == 41 {
					tiny = append(tiny, plain[40])
				} else {
					got = append(got, decodeSeg(plain[40:]))
				}
			}
			require.Equal(t, want, got)
			require.Equal(t, payload, tiny)
			require.Zero(t, sender.hostinfo.ConnectionState.txBudget.state.Load())
			require.Zero(t, relayHI.ConnectionState.txBudget.state.Load())
		})
	}
}

// addTestRelay makes sender reach its peer only through a relay tunnel with replay windows of window. It returns the
// relay's underlay address, its hostinfo and the relay's side of the tunnel.
func addTestRelay(t testing.TB, sender *flowTestPeer, window uint64) (netip.AddrPort, *HostInfo, *ConnectionState) {
	relayInit, relayResp := runTestHandshake(t)
	relayCI, err := newConnectionStateFromResult(relayInit)
	require.NoError(t, err)
	relayPeer, err := newConnectionStateFromResult(relayResp)
	require.NoError(t, err)
	relayCI.window, relayPeer.window = NewBits(window), NewBits(window)

	relayAddr := netip.MustParseAddr("10.0.0.3")
	relayRemote := netip.MustParseAddrPort("192.0.2.3:4242")
	relay := &Relay{Type: TerminalType, State: Established, LocalIndex: 5, RemoteIndex: 6, PeerAddr: flowTestRemote}
	relayHI := &HostInfo{
		vpnAddrs:        []netip.Addr{relayAddr},
		ConnectionState: relayCI,
		relayState: RelayState{
			relayForByAddr: map[netip.Addr]*Relay{flowTestRemote: relay},
			relayForByIdx:  map[uint32]*Relay{relay.LocalIndex: relay},
		},
	}
	relayHI.remote.Store(&relayRemote)
	sender.f.hostMap.Hosts[relayAddr] = relayHI
	sender.hostinfo.remote.Store(&netip.AddrPort{})
	sender.hostinfo.relayState.relays = []netip.Addr{relayAddr}
	return relayRemote, relayHI, relayPeer
}

// affinityQueue makes every read start with an idle pipeline: before each read it waits until conn has sent what was
// read before, recording how many sends that took, then samples the reader's actual thread affinity.
type affinityQueue struct {
	*flowBatchQueue
	conn       *affinityConn
	sent       int
	boundaries []int
	masks      []unix.CPUSet
}

func (q *affinityQueue) Read() ([]tio.Packet, error) {
	if n := q.reads.Load(); n > 0 {
		for _, p := range q.batches[n-1] {
			q.sent += p.SegmentCount()
		}
	}
	q.boundaries = append(q.boundaries, q.conn.waitFor(q.sent))
	q.masks = append(q.masks, threadMask())
	return q.flowBatchQueue.Read()
}

// affinityConn captures every send, sampling the sending thread's actual affinity in each WriteBatch.
type affinityConn struct {
	flowCaptureConn
	masks []unix.CPUSet
}

func (c *affinityConn) WriteBatch(p [][]byte, addrs []netip.AddrPort) (int, error) {
	mask := threadMask()
	c.mu.Lock()
	c.masks = append(c.masks, mask)
	c.mu.Unlock()
	return c.flowCaptureConn.WriteBatch(p, addrs)
}

// waitFor waits until n packets were sent and returns how many WriteBatch calls that took.
func (c *affinityConn) waitFor(n int) int {
	for len(c.captured()) < n {
		time.Sleep(50 * time.Microsecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.masks)
}

func threadMask() unix.CPUSet {
	var mask unix.CPUSet
	if err := unix.SchedGetaffinity(0, &mask); err != nil {
		panic(err)
	}
	return mask
}

// requireFlowCPU checks every mask is just cpu, or with cpu -1, the whole allowed set.
func requireFlowCPU(t *testing.T, masks []unix.CPUSet, cpu int, allowed []int) {
	t.Helper()
	require.NotEmpty(t, masks)
	for _, mask := range masks {
		if cpu >= 0 {
			require.Equal(t, 1, mask.Count())
			require.True(t, mask.IsSet(cpu), "expected CPU %d", cpu)
			continue
		}
		require.Equal(t, len(allowed), mask.Count())
		for _, c := range allowed {
			require.True(t, mask.IsSet(c))
		}
	}
}

// TestFlowStagedTXAffinity sends large, small and large reads, each from an idle pipeline, and checks the order on the
// wire and where the reader and each send actually ran, for every CPU placement, with one routine and with several. A
// staged sender is only pinned to an explicit entry other than its reader's CPU, and inline sends stay on the reader.
// With the threshold, only the small read goes inline.
// The reader only reads again once its earlier reads are on the wire, so this also checks the sender never waits for
// the reader. Pinning threads changes the process, so the test runs in a child.
func TestFlowStagedTXAffinity(t *testing.T) {
	if os.Getenv("NEBULA_FLOW_AFFINITY_TEST") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFlowStagedTXAffinity$")
		cmd.Env = append(os.Environ(), "NEBULA_FLOW_AFFINITY_TEST=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		return
	}
	allowed, err := util.AllowedCPUs()
	require.NoError(t, err)
	for _, placement := range []string{"fallback", "automatic", "explicit", "explicit-single"} {
		for _, pin := range []bool{false, true} {
			for _, sc := range sendPaths() {
				for _, routines := range []int{1, 2} {
					t.Run(fmt.Sprintf("%s/pin=%t/%s/routines=%d", placement, pin, stagedName(sc), routines), func(t *testing.T) {
						if pin && len(allowed) < 2 {
							t.Skip("requires at least two allowed CPUs")
						}
						sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, sc)
						f := sender.f
						f.pinThreads, f.routines = pin, routines
						switch placement {
						case "automatic":
							f.defaultCpuAffinity = cpupick.Default(routines, 4242, nil)
						case "explicit":
							f.cpuAffinity = []int{allowed[len(allowed)-1], allowed[0]}
						case "explicit-single":
							f.cpuAffinity = allowed[len(allowed)-1:]
						}
						readerCPU, sendCPU := -1, -1
						if pin {
							readerCPU = f.threadCPU(0)
							sendCPU = readerCPU
							if sc.tx {
								// Never the reader's CPU, and no automatic choice: unpinned unless an explicit entry fits
								sendCPU = -1
								if placement == "explicit" {
									sendCPU = f.cpuAffinity[1]
								}
							}
						}
						smallCPU := sendCPU
						if sc.inlineBelow > 0 {
							smallCPU = readerCPU
						}
						conn := &affinityConn{}
						f.writers = []udp.Conn{conn}
						batches, want := flowTestBatches(3, 8, 1, 45)
						batches[1] = batches[1][:1]
						want = append(want[:405], want[720:]...)
						q := &affinityQueue{flowBatchQueue: newFlowBatchQueue(batches), conn: conn}
						inline := metrics.GetOrRegisterCounter("flow.tx.inline", nil)
						inline0 := inline.Count()
						f.listenIn(q, 0)
						require.Equal(t, want, decryptWire(t, receiver, conn.captured()))
						if sc.inlineBelow > 0 {
							require.Equal(t, int64(1), inline.Count()-inline0)
						}
						b := q.boundaries
						requireFlowCPU(t, q.masks, readerCPU, allowed)
						requireFlowCPU(t, conn.masks[:b[1]], sendCPU, allowed)
						requireFlowCPU(t, conn.masks[b[1]:b[2]], smallCPU, allowed)
						requireFlowCPU(t, conn.masks[b[2]:], sendCPU, allowed)
					})
				}
			}
		}
	}
}

// sendPaths is inline, staged and, with the threshold, adaptive transmit.
func sendPaths() []stagedConfig {
	return []stagedConfig{{}, stagedOn(2), adaptive(2)}
}

// requireAccepted checks the receiver accepts every packet of wire in the order given. With several readers the wire
// order differs from counter order, but every packet must still authenticate and fit within the replay window.
func requireAccepted(t *testing.T, receiver *flowTestPeer, wire [][]byte) {
	t.Helper()
	for _, pkt := range wire {
		h := &header.H{}
		require.NoError(t, h.Parse(pkt))
		_, err := receiver.hostinfo.ConnectionState.Decrypt(receiver.f.l, h.MessageCounter, pkt, make([]byte, 12))
		require.NoError(t, err, "counter %d", h.MessageCounter)
	}
}

// slowConn delays every WriteBatch, then writes to the shared capture.
type slowConn struct {
	*flowCaptureConn
	delay time.Duration
}

func (c slowConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	time.Sleep(c.delay)
	return c.flowCaptureConn.WriteBatch(bufs, addrs)
}

// TestFlowTXBudgetManyReaders saturates one tunnel from eight readers, one of them on a slow socket that lets the
// others overtake it, alongside a burst of unreserved control messages: in the order they reach the wire, every packet
// is accepted by the receiver's replay window, so none was sent twice or displaced past the window.
func TestFlowTXBudgetManyReaders(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, window := range budgetWindows {
		t.Run(fmt.Sprintf("window=%d", window), func(t *testing.T) {
			sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(3))
			ci := sender.hostinfo.ConnectionState
			ci.window = NewBits(window)
			receiver.hostinfo.ConnectionState.window = NewBits(window)
			sender.f.routines = 8
			sender.f.writers = append([]udp.Conn{slowConn{sender.conn, 4 * time.Millisecond}}, slices.Repeat(sender.f.writers, 8)...)
			start := ci.messageCounter.Load()
			var wg sync.WaitGroup
			for q := range 8 {
				wg.Go(func() {
					batches, _ := flowTestBatches(28, 8, 2, 45)
					p := newStagedTx(sender.f, newFlowBatchQueue(nil), q)
					defer p.close()
					for _, packets := range batches {
						p.send(packets)
					}
				})
			}
			// A bounded burst of unreserved control messages uses the documented margin, on writer 8
			wg.Go(func() {
				for range 128 {
					sender.f.sendNoMetrics(header.Test, header.TestRequest, ci, sender.hostinfo, flowTestUnder, []byte("x"), make([]byte, 12), make([]byte, mtu), 8)
					time.Sleep(100 * time.Microsecond)
				}
			})
			wg.Wait()
			require.Zero(t, ci.txBudget.state.Load())
			wire := sender.conn.captured()
			require.Len(t, wire, 8*28*360+128)
			require.Equal(t, start+uint64(len(wire)), ci.messageCounter.Load())
			requireAccepted(t, receiver, wire)
		})
	}
}

// TestFlowStagedTXInlineOnlyWhenEmpty: a small read behind a staged batch still in flight must not go inline, it
// would overtake that batch.
func TestFlowStagedTXInlineOnlyWhenEmpty(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	sc := adaptive(2)
	sc.inlineBelow = 4
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, sc)
	p := newStagedTx(sender.f, newFlowBatchQueue(nil), 0)
	block := make(chan struct{})
	delayCrypto(sender, func(uint64) { <-block })
	batches, want := flowTestBatches(1, 4, 1, 3)
	p.send(batches[0][:3]) // its worker is blocked
	p.send(batches[0][3:])
	close(block)
	p.close()
	require.Equal(t, want, decryptWire(t, receiver, sender.conn.captured()))
}

// TestFlowStagedTXInlineBelowZero: with inline_below 0 an idle reader never sends a batch itself, in either
// direction: every read goes through the workers and the ordered sender or writer.
func TestFlowStagedTXInlineBelowZero(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	l := test.NewLogger()
	c := config.NewC(l)
	c.Settings = map[string]any{"tun": map[string]any{"staged": map[string]any{"workers": 2, "inline_below": 0}}}
	sc := parseStagedConfig(c, l)
	if !sc.tx {
		t.Skip("transmit stays inline in this build")
	}
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, sc)
	batches, want := flowTestBatches(20, 2, 1, 4)
	txInline := metrics.GetOrRegisterCounter("flow.tx.inline", nil)
	tx := metrics.GetOrRegisterCounter("flow.tx.batches", nil)
	rxInline := metrics.GetOrRegisterCounter("flow.rx.inline", nil)
	txInline0, tx0, rxInline0, rx0 := txInline.Count(), tx.Count(), rxInline.Count(), rxBatches.Count()
	sender.f.listenIn(newFlowBatchQueue(batches), 0)
	wire := sender.conn.captured()
	require.Equal(t, want, decryptWire(t, receiver, wire))
	require.Zero(t, txInline.Count()-txInline0)
	require.Equal(t, int64(len(batches)), tx.Count()-tx0)
	receiver.receive(&rxConn{wire: wire, sizes: []int{1, 2, 4}})
	require.Equal(t, want, receiver.tun.segments(t))
	require.Zero(t, rxInline.Count()-rxInline0)
	require.Positive(t, rxBatches.Count()-rx0)
}

// TestFlowStagedTXDisabled: with tx false the reader never builds a staged pipeline, even on a queue that could hand
// off its batches. Receive stays staged.
func TestFlowStagedTXDisabled(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	l := test.NewLogger()
	c := config.NewC(l)
	c.Settings = map[string]any{"tun": map[string]any{"staged": map[string]any{"workers": 2, "tx": false}}}
	sc := parseStagedConfig(c, l)
	require.False(t, sc.tx)
	require.True(t, sc.rx)
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, sc)
	batches, want := flowTestBatches(4, 8, 1, 45)
	tx := metrics.GetOrRegisterCounter("flow.tx.batches", nil)
	txInline := metrics.GetOrRegisterCounter("flow.tx.inline", nil)
	tx0, txInline0, rx0 := tx.Count(), txInline.Count(), rxBatches.Count()
	q := &swapCountQueue{flowBatchQueue: newFlowBatchQueue(batches)}
	sender.f.listenIn(q, 0)
	wire := sender.conn.captured()
	require.Equal(t, want, decryptWire(t, receiver, wire))
	require.Zero(t, q.swaps, "newStagedTx always takes the queue's buffer, so it never ran")
	require.Equal(t, tx0, tx.Count())
	require.Equal(t, txInline0, txInline.Count())
	receiver.receive(&rxConn{wire: wire, batchLen: 512})
	require.Equal(t, want, receiver.tun.segments(t))
	require.Greater(t, rxBatches.Count(), rx0)
}

// swapCountQueue counts SwapRxBuf calls.
type swapCountQueue struct {
	*flowBatchQueue
	swaps int
}

func (q *swapCountQueue) SwapRxBuf(buf []byte) []byte {
	q.swaps++
	return q.flowBatchQueue.SwapRxBuf(buf)
}

// TestFlowStagedTXAdaptiveBudget: a fast reader's adaptive sends must stop spending credit until another reader's
// earlier reservation reaches the wire.
func TestFlowStagedTXAdaptiveBudget(t *testing.T) {
	for _, shape := range []struct {
		name              string
		packets, segments int
	}{
		{"single", 1, 1}, {"batch", 8, 30},
	} {
		t.Run(shape.name, func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, adaptive(2))
			sender.f.routines = 2
			sender.f.writers = []udp.Conn{sender.conn, sender.conn}
			ci := sender.hostinfo.ConnectionState
			start := ci.messageCounter.Load()
			entered, unblock := make(chan struct{}), make(chan struct{})
			delayCrypto(sender, func(n uint64) {
				if n == start+1 {
					close(entered)
					<-unblock
				}
			})
			p0 := newStagedTx(sender.f, newFlowBatchQueue(nil), 0)
			p1 := newStagedTx(sender.f, newFlowBatchQueue(nil), 1)
			defer p0.close()
			defer p1.close()
			var release sync.Once
			defer release.Do(func() { close(unblock) })
			large, _ := flowTestBatches(1, 8, 1, 45)
			p0.send(large[0])
			<-entered
			perBatch := shape.packets * shape.segments
			small, _ := flowTestBatches(9600/perBatch, shape.packets, 1, shape.segments)
			fits := int(ci.txBudgetLimit()-360) / perBatch
			for _, packets := range small[:fits] {
				p1.send(packets)
			}
			require.Equal(t, uint64(360+fits*perBatch), (ci.txBudget.state.Load()>>24)&txBudgetMask, "inline sends must spend shared credit")
			done := make(chan struct{})
			go func() {
				defer close(done)
				for _, packets := range small[fits:] {
					p1.send(packets)
				}
			}()
			select {
			case <-done:
				t.Error("adaptive reader bypassed outstanding credit")
			case <-time.After(50 * time.Millisecond):
			}
			require.LessOrEqual(t, ci.messageCounter.Load()-start, ci.txBudgetLimit())
			release.Do(func() { close(unblock) })
			<-done
			p0.drain()
			p1.drain()
			wire := sender.conn.captured()
			require.Len(t, wire, 360+40*240)
			requireAccepted(t, receiver, wire)
			require.Zero(t, ci.txBudget.state.Load())
		})
	}
}

// BenchmarkFlowStagedTX runs reads of eight 45-segment superpackets through listenIn into a socket that discards
// them, inline and staged.
func BenchmarkFlowStagedTX(b *testing.B) {
	for _, cipher := range []noise.CipherFunc{noiseutil.CipherAESGCM, noise.CipherChaChaPoly} {
		for _, sc := range []stagedConfig{{}, stagedOn(4)} {
			b.Run(cipher.CipherName()+"/"+stagedName(sc), func(b *testing.B) {
				if sc.tx && cipher.CipherName() == noiseutil.CipherAESGCM.CipherName() && noiseutil.EncryptLockNeeded {
					b.Skip("AES-GCM requires encryption in nonce order")
				}
				sender, _ := newFlowTestPair(b, cipher, sc)
				sender.f.writers = []udp.Conn{udp.NoopConn{}}
				batch, _ := flowTestBatches(1, 8, 4, 45)
				batches := make([][]tio.Packet, b.N)
				for i := range batches {
					batches[i] = batch[0]
				}
				b.SetBytes(int64(8 * 45 * flowTestMSS))
				b.ReportAllocs()
				b.ResetTimer()
				sender.f.listenIn(newFlowBatchQueue(batches), 0)
			})
		}
	}
}
