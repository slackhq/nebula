package batch

import (
	"testing"

	"github.com/slackhq/nebula/test"
)

// stagePackets builds the stagedPacket entries Commit would have produced, so dispatch benchmarks
// bypass staging and the sort entirely.
func stagePackets(pkts [][]byte) []stagedPacket {
	staged := make([]stagedPacket, len(pkts))
	for i, p := range pkts {
		pp := testPP(p)
		staged[i] = stagedPacket{
			pkt:      p,
			key:      SortKey{Epoch: 1, Counter: uint64(i + 1)},
			proto:    pp.Protocol,
			fragAny:  pp.FragAny,
			ipHdrLen: uint16(pp.IPHdrLen),
		}
	}
	return staged
}

func flushLanes(b *testing.B, m *MultiCoalescer) {
	b.Helper()
	if m.tcp != nil {
		if err := m.tcp.Flush(); err != nil {
			b.Fatal(err)
		}
	}
	if m.udp != nil {
		if err := m.udp.Flush(); err != nil {
			b.Fatal(err)
		}
	}
	if err := m.pt.Flush(); err != nil {
		b.Fatal(err)
	}
}

// runDispatchBench measures dispatch plus the per-batch lane flush: the post-sort half of the
// batcher, which is where the production profile concentrates.
func runDispatchBench(b *testing.B, pkts [][]byte, batchSize int) {
	b.Helper()
	m := NewMultiCoalescer(nopTunWriter{}, test.NewLogger())
	staged := stagePackets(pkts)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkts[0])))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := m.dispatch(staged[i%len(staged)]); err != nil {
			b.Fatal(err)
		}
		if (i+1)%batchSize == 0 {
			flushLanes(b, m)
		}
	}
	b.StopTimer()
	flushLanes(b, m)
}

// BenchmarkDispatchSingleFlow is the bulk steady state: every packet past the seed appends.
func BenchmarkDispatchSingleFlow(b *testing.B) {
	runDispatchBench(b, buildTCPv4BulkFlow(tcpCoalesceMaxSegs, 1200), tcpCoalesceMaxSegs)
}

// BenchmarkDispatchInterleaved16 stresses the openSlots map: 16 flows round-robined defeats the
// lastSlot cache on every packet.
func BenchmarkDispatchInterleaved16(b *testing.B) {
	pkts := buildTCPv4Interleaved(16, tcpCoalesceMaxSegs, 1200)
	runDispatchBench(b, pkts, len(pkts))
}

// BenchmarkDispatchAckHeavy alternates MSS data with pure ACKs on one flow — the RX shape of a
// bidirectional transfer (the peer's data and its ACKs of our data share the tunnel direction).
func BenchmarkDispatchAckHeavy(b *testing.B) {
	pay := make([]byte, 1200)
	var pkts [][]byte
	seq := uint32(1000)
	for range tcpCoalesceMaxSegs / 2 {
		pkts = append(pkts, buildTCPv4(seq, tcpAck, pay))
		seq += uint32(len(pay))
		pkts = append(pkts, buildTCPv4(seq, tcpAck, nil))
	}
	runDispatchBench(b, pkts, len(pkts))
}

// BenchmarkDispatchUDPFlow is the QUIC-ish bulk UDP shape.
func BenchmarkDispatchUDPFlow(b *testing.B) {
	pay := make([]byte, 1200)
	pkts := make([][]byte, udpCoalesceMaxSegs)
	for i := range pkts {
		pkts[i] = buildUDPv4(2000, 443, pay)
	}
	runDispatchBench(b, pkts, len(pkts))
}

// BenchmarkDispatchSeedHeavy sets PSH on every packet so each one seeds and immediately closes
// its own slot — the small-write RPC shape, and the upper bound on what the seed path (including
// the parsedTCP-to-slot field transfer) can cost.
func BenchmarkDispatchSeedHeavy(b *testing.B) {
	pay := make([]byte, 1200)
	pkts := make([][]byte, tcpCoalesceMaxSegs)
	seq := uint32(1000)
	for i := range pkts {
		pkts[i] = buildTCPv4(seq, tcpAckPsh, pay)
		seq += uint32(len(pay))
	}
	runDispatchBench(b, pkts, len(pkts))
}

// TestFlowKeyDigestDistinct pins digest quality: distinct flows must produce distinct keys across
// a large sample, and the v4/v6 domains must not alias. Collisions are tolerated by construction
// (headersMatch gates every merge), so this is a quality canary, not a correctness requirement.
func TestFlowKeyDigestDistinct(t *testing.T) {
	seen := make(map[flowKey]struct{}, 1<<17)
	v4 := make([]byte, 40)
	v4[0] = 0x45
	v4[3] = 40 // total length
	add := func(fk flowKey) {
		if _, dup := seen[fk]; dup {
			t.Fatal("flow digest collision in small sample")
		}
		seen[fk] = struct{}{}
	}
	var fk flowKey
	for a := range 256 {
		for b := range 128 {
			v4[15] = byte(a) // src low byte
			v4[19] = byte(b) // dst low byte
			v4[21] = byte(a)
			v4[23] = byte(b)
			trimmed, ok := fk.parseIPv4Prologue(v4)
			if !ok {
				t.Fatal("v4 prologue rejected synthetic packet")
			}
			_ = trimmed
			add(fk.withPorts(uint32(a)<<16 | uint32(b)))
		}
	}
	v6 := make([]byte, 60)
	v6[0] = 0x60
	for a := range 256 {
		for b := range 128 {
			v6[23] = byte(a)
			v6[39] = byte(b)
			trimmed, ok := fk.parseIPv6Prologue(v6)
			if !ok {
				t.Fatal("v6 prologue rejected synthetic packet")
			}
			_ = trimmed
			add(fk.withPorts(uint32(a)<<16 | uint32(b)))
		}
	}
}
