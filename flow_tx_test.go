//go:build linux && !android && !e2e_testing

package nebula

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cpupick"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/tio"
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

// TestSegmentCount checks segmentCount predicts exactly the segments tio.SegmentSuperpacket cuts, odd tails included.
func TestSegmentCount(t *testing.T) {
	require.Equal(t, uint64(1), segmentCount(tio.Packet{Bytes: make([]byte, 60)}))
	for _, segs := range []int{1, 2, 3, 45} {
		for _, tail := range []int{0, 1, flowTestMSS - 1} {
			pkt := flowTCPSuperpacket(0, 0, segs)
			pkt.Bytes = pkt.Bytes[:len(pkt.Bytes)-tail]
			pkt.GSO = tio.GSOInfo{Size: flowTestMSS, HdrLen: 40, CsumStart: 20, Proto: tio.GSOProtoTCP}
			want, got := segmentCount(pkt), uint64(0)
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
}

// TestFlowStagedTXRelay sends staged batches, and an empty read, through a relay: outer and inner layers both verify,
// in order, and go to the relay.
func TestFlowStagedTXRelay(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, window := range []uint64{ReplayWindow} {
		t.Run(fmt.Sprintf("window=%d", window), func(t *testing.T) {
			sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(2))
			sender.hostinfo.ConnectionState.window = NewBits(window)
			receiver.hostinfo.ConnectionState.window = NewBits(window)
			relayRemote, _, relayPeer := addTestRelay(t, sender, window)
			batches, want := flowTestBatches(2, 3, 1, 6)
			var payload []byte
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
			q.sent += int(segmentCount(p))
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
						conn := &affinityConn{}
						f.writers = []udp.Conn{conn}
						batches, want := flowTestBatches(3, 8, 1, 45)
						batches[1] = batches[1][:1]
						want = append(want[:405], want[720:]...)
						q := &affinityQueue{flowBatchQueue: newFlowBatchQueue(batches), conn: conn}
						f.listenIn(q, 0)
						require.Equal(t, want, decryptWire(t, receiver, conn.captured()))
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
	return []stagedConfig{{}, stagedOn(2)}
}
