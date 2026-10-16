//go:build linux && !android && !e2e_testing

package nebula

import (
	"fmt"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// gated is staging with an inline threshold of 4 segments and the given gate hold.
func gated(hold int) stagedConfig {
	sc := adaptive(2)
	sc.inlineBelow, sc.gateHold = 4, hold
	return sc
}

// gateCounters snapshots the transmit counters a gate test checks.
type gateCounters struct{ inline, batches, switches int64 }

func readGateCounters() gateCounters {
	return gateCounters{
		inline:   metrics.GetOrRegisterCounter("flow.tx.inline", nil).Count(),
		batches:  metrics.GetOrRegisterCounter("flow.tx.batches", nil).Count(),
		switches: metrics.GetOrRegisterCounter("flow.tx.gate_switches", nil).Count(),
	}
}

func (c gateCounters) since(c0 gateCounters) gateCounters {
	return gateCounters{c.inline - c0.inline, c.batches - c0.batches, c.switches - c0.switches}
}

// gateReads builds reads of small (3 segments, below the threshold) or large (2 superpackets of 9) shape, in order,
// for one flow, and the segments they carry.
func gateReads(large ...bool) ([][]tio.Packet, []decodedSeg) {
	var reads [][]tio.Packet
	var want []decodedSeg
	seq := uint32(0)
	for _, l := range large {
		per, segs := 1, 3
		if l {
			per, segs = 2, 9
		}
		var b []tio.Packet
		for range per {
			b = append(b, flowTCPSuperpacket(0, seq, segs))
			for s := range segs {
				want = append(want, decodedSeg{seq: seq, idx: uint16(s)})
			}
			seq++
		}
		reads = append(reads, b)
	}
	return reads, want
}

func repeatBool(v bool, n int) []bool {
	out := make([]bool, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// TestFlowStagedTXGateSwitch forces the gate from inline to fanout and back, with a slow socket and slow
// workers so the fanout batches are still in flight when the small reads arrive: wire order is read order, counters
// are contiguous, and each switch happens on exactly the gate_hold-th read that wants it.
func TestFlowStagedTXGateSwitch(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	const hold = 3
	for _, routines := range []int{1, 2} {
		t.Run(fmt.Sprintf("routines=%d", routines), func(t *testing.T) {
			sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, gated(hold))
			sender.f.routines = routines
			sender.f.writers = []udp.Conn{sender.conn, sender.conn}
			delayCrypto(sender, func(n uint64) {
				if n%7 == 0 {
					time.Sleep(time.Millisecond)
				}
			})
			sender.conn.delay = 4 * time.Millisecond
			// 4 small inline, 2 large held inline, 6 large fanout from the switch on, 2 small held in fanout, then
			// the switch back drains and 3 small go inline
			shape := append(repeatBool(false, 4), repeatBool(true, 8)...)
			shape = append(shape, repeatBool(false, 5)...)
			reads, want := gateReads(shape...)
			ci := sender.hostinfo.ConnectionState
			start := ci.messageCounter.Load()
			c0 := readGateCounters()
			p := newStagedTx(sender.f, newFlowBatchQueue(nil), 0)
			for i, r := range reads {
				p.send(r)
				if i == 13 {
					require.Positive(t, p.inFlight, "fanout batches must still be in flight when the small reads start")
				}
				if i == 14 {
					require.Zero(t, p.inFlight, "switching to inline drains the pipeline")
				}
			}
			p.close()
			require.Equal(t, want, decryptWire(t, receiver, sender.conn.captured()), "wire order must match read order")
			require.Equal(t, start+uint64(len(want)), ci.messageCounter.Load(), "every reserved counter is used once")
			require.Equal(t, gateCounters{inline: 4 + 2 + 3, batches: 6 + 2, switches: 2}, readGateCounters().since(c0))
			require.Zero(t, ci.txBudget.state.Load())
		})
	}
}

// TestFlowStagedTXGateHold: the gate never switches before gate_hold consecutive reads want the other mode, and
// a read that wants the current mode restarts the count.
func TestFlowStagedTXGateHold(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	const hold = 5
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly, gated(hold))
	shape := append(repeatBool(true, hold-1), false)
	shape = append(shape, repeatBool(true, hold-1)...)
	reads, want := gateReads(append(shape, true)...)
	c0 := readGateCounters()
	p := newStagedTx(sender.f, newFlowBatchQueue(nil), 0)
	for _, r := range reads[:len(reads)-1] {
		p.send(r)
	}
	require.Equal(t, gateCounters{inline: 2*hold - 1}, readGateCounters().since(c0), "no switch before gate_hold")
	p.send(reads[len(reads)-1])
	require.Equal(t, gateCounters{inline: 2*hold - 1, batches: 1, switches: 1}, readGateCounters().since(c0))
	p.close()
	require.Equal(t, want, decryptWire(t, receiver, sender.conn.captured()))
}
