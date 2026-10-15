//go:build linux && !android && !e2e_testing

package nebula

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestFlowStagedRXOrderAndReplay feeds every packet behind a forgery of it, from another address, and a replay of
// it, then a test packet that jumps the window and the whole stream again, with shuffled workers and a slow tun,
// through small and large batches: the tun sees each segment once, in order, the window marks them all, the forgeries
// neither consume a counter nor roam, and the jump does not get the earlier data packets of its batch rejected.
func TestFlowStagedRXOrderAndReplay(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, cipher := range []noise.CipherFunc{noiseutil.CipherAESGCM, noise.CipherChaChaPoly} {
		for _, batchLen := range []int{8, 1000} {
			t.Run(fmt.Sprintf("%s/batch=%d", cipher.CipherName(), batchLen), func(t *testing.T) {
				sender, receiver := newFlowTestPair(t, cipher, stagedOn(4))
				delayCrypto(receiver, func(n uint64) {
					if n%32 == 0 {
						time.Sleep(time.Millisecond)
					}
				})
				receiver.tun.delay = 100 * time.Microsecond
				batches, want := flowTestBatches(30, 4, 1, 10)
				wire := wireFor(t, sender, batches)
				var feed [][]byte
				for i, p := range wire {
					// Corrupt the tag or the payload
					bad := append([]byte(nil), p...)
					bad[[]int{len(p) - 1, header.Len + 3}[i%2]] ^= 1
					feed = append(feed, bad, p, p)
				}
				// The jump lands in a batch with fresh data before it, at batch=1000
				sender.hostinfo.ConnectionState.messageCounter.Add(2 * ReplayWindow)
				feed = append(append(feed, sendControl(sender, header.Test, header.TestReply)), wire...)
				forged := func(i int) netip.AddrPort {
					if i < 3*len(wire) && i%3 == 0 {
						return netip.MustParseAddrPort("198.51.100.9:4242")
					}
					return flowTestUnder
				}
				rx0 := rxBatches.Count()
				conn := &rxConn{wire: feed, batchLen: batchLen, from: forged}
				receiver.receive(conn)
				require.Positive(t, rxBatches.Count()-rx0)
				require.Equal(t, (len(feed)+batchLen-1)/batchLen, conn.swaps, "every batch is handed off")
				require.Equal(t, want, receiver.tun.segments(t), "every packet exactly once, in order")
				require.Equal(t, flowTestUnder, receiver.hostinfo.GetRemote())
				for _, p := range wire {
					h := &header.H{}
					require.NoError(t, h.Parse(p))
					require.False(t, receiver.hostinfo.ConnectionState.window.Check(receiver.f.l, h.MessageCounter), "counter %d must be marked seen", h.MessageCounter)
				}
			})
		}
	}
}

// TestFlowStagedRXClose: a CloseTunnel in the middle of a batch is handled in its place, by the writer. The data after
// it in the batch is still delivered from the batch's hostmap cache, as inline receive does.
func TestFlowStagedRXClose(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(2))
	batches, want := flowTestBatches(4, 4, 1, 8)
	wire := wireFor(t, sender, batches)
	half := len(wire) / 2
	feed := append(append(append([][]byte{}, wire[:half]...), sendControl(sender, header.CloseTunnel, 0)), wire[half:]...)
	receiver.receive(&rxConn{wire: feed, batchLen: len(feed)})
	require.Equal(t, want, receiver.tun.segments(t))
	require.Nil(t, receiver.f.hostMap.QueryIndex(receiver.hostinfo.localIndexId))
}

// sendControl returns the wire packet of a control message from sender.
func sendControl(sender *flowTestPeer, typ header.MessageType, st header.MessageSubType) []byte {
	sender.f.sendNoMetrics(typ, st, sender.hostinfo.ConnectionState, sender.hostinfo, flowTestUnder, nil, make([]byte, 12), make([]byte, mtu), 0)
	wire := sender.conn.captured()
	sender.conn.pkts, sender.conn.addrs = nil, nil
	return wire[len(wire)-1]
}

// receivePaths is inline, staged and, with the threshold, adaptive receive.
func receivePaths() []stagedConfig {
	return []stagedConfig{{}, stagedOn(2), adaptive(2)}
}

// TestFlowStagedRXRecvError feeds a RecvError that deletes the tunnel, then a known replay and new data for it, in one
// batch. Every receive path must drop the data through its own view of the hostmap, without touching the replay window,
// and answer each packet with a RecvError, as inline receive does, without decrypting the replay again.
func TestFlowStagedRXRecvError(t *testing.T) {
	for _, sc := range receivePaths() {
		t.Run(stagedName(sc), func(t *testing.T) {
			sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, sc)
			receiver.f.messageMetrics = newMessageMetrics()
			receiver.f.acceptRecvErrorConfig = recvErrorAlways
			receiver.f.sendRecvErrorConfig = recvErrorAlways
			batches, want := flowTestBatches(1, 1, 1, 33)
			wire := wireFor(t, sender, batches)
			rxc := newRxContext(receiver.f, 0)
			receiver.f.readOutsidePackets(ViaSender{UdpAddr: flowTestUnder}, append([]byte(nil), wire[0]...), rxc)
			receiver.f.flushOutside(rxc)
			h := &header.H{}
			require.NoError(t, h.Parse(wire[0]))
			replay := h.MessageCounter
			var decrypts atomic.Int64
			delayCrypto(receiver, func(n uint64) {
				if n == replay {
					decrypts.Add(1)
				}
			})
			ctl := header.Encode(make([]byte, header.Len), header.Version, header.RecvError, 0, receiver.hostinfo.remoteIndexId, 0)
			conn := &rxConn{wire: append([][]byte{ctl}, wire...), batchLen: len(wire) + 1}
			receiver.receive(conn)
			require.Nil(t, receiver.f.hostMap.QueryIndex(receiver.hostinfo.localIndexId))
			require.Equal(t, want[:1], receiver.tun.segments(t))
			require.Zero(t, decrypts.Load(), "known replays must not be decrypted again")
			replies := conn.captured()
			require.Len(t, replies, len(wire))
			for i, reply := range replies {
				require.NoError(t, h.Parse(reply))
				require.Equal(t, header.RecvError, h.Type)
				require.NoError(t, h.Parse(wire[i]))
				require.True(t, i == 0 || receiver.hostinfo.ConnectionState.window.Check(nil, h.MessageCounter), "dropped data must not update replay state")
			}
		})
	}
}

// TestFlowStagedRXReplacedTunnel classifies a data packet, then a close and a new handshake replace its tunnel at the
// same index before the writer commits it, as when the listener runs ahead: it must be dropped untouched.
func TestFlowStagedRXReplacedTunnel(t *testing.T) {
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(2))
	receiver.f.messageMetrics = newMessageMetrics()
	batches, _ := flowTestBatches(1, 1, 1, 1)
	wire := wireFor(t, sender, batches)
	closePacket := sendControl(sender, header.CloseTunnel, 0)
	p := &stagedRx{f: receiver.f, h: &header.H{}, hostmapCache: map[uint32]*HostInfo{}}
	item := rxItem{packet: wire[0], via: flowTestUnder}
	p.classify(&item)
	require.NotNil(t, item.ci)
	rxc := newRxContext(receiver.f, 0)
	p.process(&rxBatch{items: []rxItem{{packet: closePacket, via: flowTestUnder}}}, rxc)
	require.Nil(t, receiver.f.hostMap.QueryIndex(receiver.hostinfo.localIndexId))
	_, replacement := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(2))
	receiver.f.hostMap.Lock()
	receiver.f.hostMap.unlockedAddHostInfo(replacement.hostinfo, receiver.f)
	receiver.f.hostMap.Unlock()
	p.process(&rxBatch{items: []rxItem{item}}, rxc)
	require.Empty(t, receiver.tun.writes)
	require.True(t, item.ci.window.Check(nil, item.counter))
	require.True(t, replacement.hostinfo.ConnectionState.window.Check(nil, item.counter))
}

// TestFlowStagedRXRealSocket exercises buffer handoff through the real Linux UDP receive loop.
func TestFlowStagedRXRealSocket(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(3))
	batches, want := flowTestBatches(60, 4, 1, 8)
	wire := wireFor(t, sender, batches)

	l := receiver.f.l
	conn, err := udp.NewListener(l, udp.Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Batch: 16, Offloads: true})
	require.NoError(t, err)
	addr, err := conn.LocalAddr()
	require.NoError(t, err)
	out, err := udp.NewListener(l, udp.Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Batch: 16, Offloads: true})
	require.NoError(t, err)
	defer out.Close()
	// The sender's address is the tunnel's remote, so no roaming
	from, err := out.LocalAddr()
	require.NoError(t, err)
	receiver.hostinfo.remote.Store(&from)

	done := make(chan struct{})
	go func() { receiver.receive(conn); close(done) }()
	// Send in bursts small enough for the default socket buffer
	for off := 0; off < len(wire); off += 32 {
		end := min(off+32, len(wire))
		addrs := make([]netip.AddrPort, end-off)
		for i := range addrs {
			addrs[i] = addr
		}
		_, err := out.WriteBatch(wire[off:end], addrs)
		require.NoError(t, err)
		require.Eventually(t, func() bool { return len(receiver.tun.segments(t)) >= end }, 5*time.Second, 100*time.Microsecond)
	}
	receiver.f.closed.Store(true)
	require.NoError(t, conn.Close())
	<-done
	require.Equal(t, want, receiver.tun.segments(t))
}

// TestFlowStagedRXCloseFlushesPartial: packets the listener holds in a batch it never got to end when the conn fails
// are still committed, in order, on a live interface.
func TestFlowStagedRXCloseFlushesPartial(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, stagedOn(2))
	batches, want := flowTestBatches(11, 4, 1, 8)
	wire := wireFor(t, sender, batches)
	p := newStagedRx(receiver.f, 0, newRxContext(receiver.f, 0))
	for i, packet := range wire {
		p.deliver(flowTestUnder, packet)
		if (i+1)%64 == 0 {
			p.endBatch()
		}
	}
	p.close()
	require.Equal(t, want, receiver.tun.segments(t))
}

// TestFlowStagedRXInlineBelow: small idle batches stay on the listener, larger batches still use the ordered writer.
func TestFlowStagedRXInlineBelow(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	sc := adaptive(3)
	sc.inlineBelow = 16
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, sc)
	batches, want := flowTestBatches(40, 4, 1, 16)
	wire := wireFor(t, sender, batches)
	inline := metrics.GetOrRegisterCounter("flow.rx.inline", nil)
	inline0, rx0 := inline.Count(), rxBatches.Count()
	receiver.receive(&rxConn{wire: wire, sizes: []int{8, 8, 8, 128, 128, 8, 8, 128, 4, 128}})
	require.Equal(t, want, receiver.tun.segments(t))
	require.Positive(t, inline.Count()-inline0)
	require.Positive(t, rxBatches.Count()-rx0)
}
