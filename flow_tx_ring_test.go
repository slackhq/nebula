//go:build linux && !android && !e2e_testing

package nebula

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"os"
	"os/exec"
	"testing"

	"github.com/slackhq/nebula/overlay/tio"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/require"
)

// queuedWire models two CPU-selected NIC queues with independent completion: the reader's
// queue is congested, while another CPU's queue drains immediately. WriteBatch returning only
// means the kernel accepted the packets; draining staged slots does not drain a NIC queue.
// The sampled affinity makes the schedule deterministic without a real socket or NIC. An
// unpinned sender alternates between allowed CPUs, even if it happened not to in this run.
func (c *affinityConn) queuedWire(readerCPU int) [][]byte {
	var slow, fast [][]byte
	wire := c.captured()
	off := 0
	for i, n := range c.sizes {
		mask := c.masks[i]
		if mask.IsSet(readerCPU) && (mask.Count() == 1 || i%2 == 0) {
			slow = append(slow, wire[off:off+n]...)
		} else {
			fast = append(fast, wire[off:off+n]...)
		}
		off += n
	}
	return append(fast, slow...)
}

// TestFlowStagedTXRelayQueuedWire reproduces reorder after successful, ordered socket
// submissions. Mixed reads switch the sticky gate with an empty software pipeline; relayed
// data must stay on the reader throughout, without moving the direct sender. Each routine owns a flow.
func TestFlowStagedTXRelayQueuedWire(t *testing.T) {
	if os.Getenv("NEBULA_FLOW_RING_TEST") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFlowStagedTXRelayQueuedWire$")
		cmd.Env = append(os.Environ(), "NEBULA_FLOW_RING_TEST=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		return
	}
	allowed, err := util.AllowedCPUs()
	require.NoError(t, err)
	if len(allowed) < 2 {
		t.Skip("requires two allowed CPUs")
	}
	for _, mode := range []string{"gate", "always-staged", "oversized"} {
		for _, explicit := range []bool{false, true} {
			for _, routines := range []int{1, 2} {
				for q := range routines {
					t.Run(fmt.Sprintf("%s/explicit=%t/routines=%d/q=%d", mode, explicit, routines, q), func(t *testing.T) {
						sc := gated(stagedGateHold)
						if mode != "gate" {
							sc.inlineBelow = 0
						}
						sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, sc)
						f := sender.f
						f.pinThreads, f.routines = true, routines
						if explicit {
							f.cpuAffinity = allowed[:2]
						}
						_, relayHI, relayPeer := addTestRelay(t, sender, ReplayWindow)
						conn := &affinityConn{}
						f.writers = make([]udp.Conn, routines)
						for i := range f.writers {
							f.writers[i] = conn
						}
						shape := append(repeatBool(false, 2), repeatBool(true, stagedGateHold+2)...)
						shape = append(shape, repeatBool(false, stagedGateHold+2)...)
						if mode != "gate" {
							shape = []bool{false, true, false, true}
						}
						reads, want := gateReads(shape...)
						if mode == "oversized" {
							// A deliberately tiny outer budget alone forces the oversized fallback.
							relayHI.ConnectionState.window = NewBits(16)
						}
						queue := &affinityQueue{flowBatchQueue: newFlowBatchQueue(reads), conn: conn}
						// Each Read waits for all previous socket submissions, making software drain
						// irrelevant to the independently queued packets in queuedWire.
						f.listenIn(queue, q)
						unwrap := func(wire [][]byte) [][]byte {
							inner := make([][]byte, 0, len(wire))
							for _, pkt := range wire {
								inner = append(inner, pkt[header.Len:len(pkt)-relayPeer.dKey.Overhead()])
							}
							return inner
						}
						require.Equal(t, want, decryptWire(t, receiver, unwrap(conn.captured())), "socket submission order")
						require.Equal(t, want, decryptWire(t, receiver, unwrap(conn.queuedWire(f.threadCPU(q)))), "NIC queue completion order")
					})
				}
			}
		}
	}
}

// Mixed reads must keep direct sends on the original staged sender, including when relay data is present.
func TestFlowStagedTXMixedPlacement(t *testing.T) {
	if os.Getenv("NEBULA_FLOW_MIXED_TEST") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFlowStagedTXMixedPlacement$")
		cmd.Env = append(os.Environ(), "NEBULA_FLOW_MIXED_TEST=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		return
	}
	allowed, err := util.AllowedCPUs()
	require.NoError(t, err)
	if len(allowed) < 2 {
		t.Skip("requires two allowed CPUs")
	}
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit=%t", explicit), func(t *testing.T) {
			sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(2))
			_, _, relayPeer := addTestRelay(t, sender, ReplayWindow)
			direct, directReceiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(2))
			directAddr := netip.MustParseAddr("10.0.0.4")
			direct.hostinfo.vpnAddrs = []netip.Addr{directAddr}
			f := sender.f
			f.hostMap.Hosts[directAddr] = direct.hostinfo
			f.pinThreads, f.routines = true, 2
			sendCPU := -1
			if explicit {
				f.cpuAffinity = allowed[:2]
				sendCPU = allowed[1]
			}
			conn := &affinityConn{}
			f.writers = []udp.Conn{conn, conn}
			var reads [][]tio.Packet
			var wantRelay, wantDirect []decodedSeg
			for seq := range uint32(6) {
				r := flowTCPSuperpacket(0, seq, 3)
				d := flowTCPSuperpacket(1, seq, 9)
				copy(d.Bytes[16:20], directAddr.AsSlice())
				reads = append(reads, []tio.Packet{r, d})
				for i := range 3 {
					wantRelay = append(wantRelay, decodedSeg{seq: seq, idx: uint16(i)})
				}
				for i := range 9 {
					wantDirect = append(wantDirect, decodedSeg{flow: 1, seq: seq, idx: uint16(i)})
				}
			}
			queue := &affinityQueue{flowBatchQueue: newFlowBatchQueue(reads), conn: conn}
			f.listenIn(queue, 0)
			wire := conn.captured()
			var directWire, relayWire [][]byte
			off := 0
			for i, n := range conn.sizes {
				for _, pkt := range wire[off : off+n] {
					var h header.H
					require.NoError(t, h.Parse(pkt))
					cpu := sendCPU
					if h.Subtype == header.MessageRelay {
						cpu = f.threadCPU(0)
						require.NoError(t, relayPeer.VerifyRelay(nil, h.MessageCounter, pkt, make([]byte, 12)))
						relayWire = append(relayWire, pkt[header.Len:len(pkt)-relayPeer.dKey.Overhead()])
					} else {
						directWire = append(directWire, pkt)
					}
					requireFlowCPU(t, conn.masks[i:i+1], cpu, allowed)
				}
				off += n
			}
			require.Equal(t, wantDirect, decryptWire(t, directReceiver, directWire))
			require.Equal(t, wantRelay, decryptWire(t, receiver, relayWire))
		})
	}
}

// A relayed batch shares its outer tunnel with older staged direct data on the SAME routine. Inline completion
// must not refund that direct sender's credit while its oldest reservation is stalled.
func TestFlowStagedTXRelaySharedBudget(t *testing.T) {
	sender, _ := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(2))
	_, via, _ := addTestRelay(t, sender, ReplayWindow)
	// Give the relay host the same ordinary peer metadata as a direct tunnel.
	direct := newFlowTestPeer(t, flowTestLocal, via.vpnAddrs[0], via.ConnectionState, 300, 400)
	via.buildNetworks(sender.f.myVpnNetworksTable, direct.hostinfo.ConnectionState.peerCert.Certificate)
	via.remoteIndexId = direct.hostinfo.remoteIndexId
	ci := via.ConnectionState
	ci.window = NewBits(32)
	start := ci.messageCounter.Load()
	entered, unblock := make(chan struct{}), make(chan struct{})
	var release sync.Once
	delayCrypto(direct, func(n uint64) {
		if n == start+1 {
			close(entered)
			<-unblock
		}
	})
	p := newStagedTx(sender.f, newFlowBatchQueue(nil), 0)
	defer p.close()
	defer release.Do(func() { close(unblock) })
	d := flowTCPSuperpacket(1, 0, 9)
	copy(d.Bytes[16:20], via.vpnAddrs[0].AsSlice())
	p.send([]tio.Packet{d})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("direct worker did not start")
	}
	for seq := range uint32(7) {
		p.send([]tio.Packet{flowTCPSuperpacket(0, seq, 1)})
	}
	require.Equal(t, uint64(16), (ci.txBudget.state.Load()>>24)&txBudgetMask)
	done := make(chan struct{})
	go func() { defer close(done); p.send([]tio.Packet{flowTCPSuperpacket(0, 7, 1)}) }()
	select {
	case <-done:
		t.Error("relay recycled credit around a stalled direct reservation")
	case <-time.After(50 * time.Millisecond):
	}
	require.Equal(t, start+16, ci.messageCounter.Load())
	release.Do(func() { close(unblock) })
	<-done
	p.drain()
	require.Zero(t, ci.txBudget.state.Load())
}
