package batch

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/slackhq/nebula/overlay/tio"
)

// nopTunWriter is a zero-alloc tio.GSOWriter for benchmarks. Discards
// everything but satisfies the interface the coalescer detects.
type nopTunWriter struct{}

func (nopTunWriter) Write(p []byte) (int, error) { return len(p), nil }
func (nopTunWriter) WriteGSO(hdr []byte, transportHdr []byte, pays [][]byte, _ tio.GSOProto) error {
	return nil
}
func (nopTunWriter) Capabilities() tio.Capabilities {
	return tio.Capabilities{TSO: true, USO: true}
}

// buildTCPv4BulkFlow returns a slice of N adjacent ACK-only TCP segments
// on a single 5-tuple, each carrying payloadLen bytes. Seq numbers are
// contiguous so every packet is coalesceable onto the previous one.
func buildTCPv4BulkFlow(n, payloadLen int) [][]byte {
	pkts := make([][]byte, n)
	pay := make([]byte, payloadLen)
	seq := uint32(1000)
	for i := range n {
		pkts[i] = buildTCPv4(seq, tcpAck, pay)
		seq += uint32(payloadLen)
	}
	return pkts
}

// buildTCPv4Interleaved returns nFlows * perFlow packets with per-flow
// seq continuity but round-robin across flows — worst case for any
// "last-slot" cache.
func buildTCPv4Interleaved(nFlows, perFlow, payloadLen int) [][]byte {
	pay := make([]byte, payloadLen)
	seqs := make([]uint32, nFlows)
	for i := range seqs {
		seqs[i] = uint32(1000 + i*1000000)
	}
	pkts := make([][]byte, 0, nFlows*perFlow)
	for range perFlow {
		for f := range nFlows {
			sport := uint16(10000 + f)
			pkts = append(pkts, buildTCPv4Ports(sport, 2000, seqs[f], tcpAck, pay))
			seqs[f] += uint32(payloadLen)
		}
	}
	return pkts
}

// buildICMPv4 returns a minimal non-TCP packet that takes the passthrough
// branch in Commit.
func buildICMPv4() []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[9] = 1 // ICMP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	return pkt
}

// runCommitBench drives Commit over pkts batchSize at a time, flushing
// between batches, and reports per-packet cost.
func runCommitBench(b *testing.B, pkts [][]byte, batchSize int) {
	b.Helper()
	c := NewTCPCoalescer(nopTunWriter{})
	b.ReportAllocs()
	b.SetBytes(int64(len(pkts[0])))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := pkts[i%len(pkts)]
		if err := c.Commit(pkt); err != nil {
			b.Fatal(err)
		}
		if (i+1)%batchSize == 0 {
			if err := c.Flush(); err != nil {
				b.Fatal(err)
			}
		}
	}
	// Drain any trailing partial batch so slot state doesn't leak across runs.
	_ = c.Flush()
}

// BenchmarkCommitSingleFlow is the bulk-TCP steady state: one flow,
// contiguous seq, 1200-byte payloads. Every packet past the seed should
// append onto the open slot. This is the case we most care about.
func BenchmarkCommitSingleFlow(b *testing.B) {
	pkts := buildTCPv4BulkFlow(tcpCoalesceMaxSegs, 1200)
	runCommitBench(b, pkts, tcpCoalesceMaxSegs)
}

// BenchmarkCommitInterleaved4 has 4 concurrent bulk flows round-robined.
// A single-entry fast-path cache will miss on every packet; an N-way
// cache or map lookup carries the weight.
func BenchmarkCommitInterleaved4(b *testing.B) {
	pkts := buildTCPv4Interleaved(4, tcpCoalesceMaxSegs, 1200)
	runCommitBench(b, pkts, len(pkts))
}

// BenchmarkCommitInterleaved16 stresses the map at higher flow counts.
func BenchmarkCommitInterleaved16(b *testing.B) {
	pkts := buildTCPv4Interleaved(16, tcpCoalesceMaxSegs, 1200)
	runCommitBench(b, pkts, len(pkts))
}

// BenchmarkCommitPassthrough exercises the non-TCP branch: parseTCPBase
// bails early and addPassthrough is the only work.
func BenchmarkCommitPassthrough(b *testing.B) {
	pkt := buildICMPv4()
	pkts := make([][]byte, 64)
	for i := range pkts {
		pkts[i] = pkt
	}
	runCommitBench(b, pkts, 64)
}

// BenchmarkCommitNonCoalesceableTCP sends SYN|ACK packets on one flow.
// Each packet takes the "TCP but not admissible" branch which does a
// map delete + passthrough. Measures the seal-without-slot cost.
func BenchmarkCommitNonCoalesceableTCP(b *testing.B) {
	pay := make([]byte, 0)
	pkts := make([][]byte, 64)
	for i := range pkts {
		pkts[i] = buildTCPv4(uint32(1000+i), tcpSyn|tcpAck, pay)
	}
	runCommitBench(b, pkts, 64)
}

// runMultiCommitBench drives MultiCoalescer.Commit. The dispatcher does
// the IP/L4 parse once and passes the parsed struct to the lane, so this
// is the bench that shows the savings of skipping the lane's re-parse.
func runMultiCommitBench(b *testing.B, pkts [][]byte, batchSize int) {
	b.Helper()
	m := NewMultiCoalescer(nopTunWriter{}, true, true)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkts[0])))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := pkts[i%len(pkts)]
		if err := m.Commit(pkt); err != nil {
			b.Fatal(err)
		}
		if (i+1)%batchSize == 0 {
			if err := m.Flush(); err != nil {
				b.Fatal(err)
			}
		}
	}
	_ = m.Flush()
}

// BenchmarkMultiCommitSingleFlow is the multi-lane analogue of
// BenchmarkCommitSingleFlow — same workload but routed through the
// dispatcher. The delta vs the single-lane bench measures dispatcher
// overhead.
func BenchmarkMultiCommitSingleFlow(b *testing.B) {
	pkts := buildTCPv4BulkFlow(tcpCoalesceMaxSegs, 1200)
	runMultiCommitBench(b, pkts, tcpCoalesceMaxSegs)
}

// BenchmarkMultiCommitInterleaved4 mirrors BenchmarkCommitInterleaved4
// through the dispatcher.
func BenchmarkMultiCommitInterleaved4(b *testing.B) {
	pkts := buildTCPv4Interleaved(4, tcpCoalesceMaxSegs, 1200)
	runMultiCommitBench(b, pkts, len(pkts))
}

// flowKeyPair is one comparison input for the flowKeyCompare bench.
type flowKeyPair struct{ a, b flowKey }

// makeFlowKey builds an IPv4 flowKey from compact inputs.
func makeFlowKey(srcLow, dstLow uint32, sport, dport uint16) flowKey {
	var fk flowKey
	binary.BigEndian.PutUint32(fk.src[12:16], srcLow)
	binary.BigEndian.PutUint32(fk.dst[12:16], dstLow)
	fk.sport = sport
	fk.dport = dport
	return fk
}

// flowKeyCases are the workload mixes flowKeyCompare sees in practice.
//   - sameFlow: equal keys; tests the equal-path cost (sort runs hit this
//     repeatedly when many segments share a flow).
//   - sportDiffers: same src/dst/dport, different sport — the typical
//     "sibling flows from one host to one server" pattern.
//   - dstDiffers: same src/sport/dport, different dst — outbound to many
//     servers from a fixed local port.
//   - allDiffer: every field differs; worst case for short-circuiting.
func flowKeyCases() map[string][]flowKeyPair {
	const n = 64
	cases := map[string][]flowKeyPair{
		"sameFlow":     make([]flowKeyPair, n),
		"sportDiffers": make([]flowKeyPair, n),
		"dstDiffers":   make([]flowKeyPair, n),
		"allDiffer":    make([]flowKeyPair, n),
	}
	for i := range n {
		base := makeFlowKey(0x0a000001, 0x0a000002, 40000, 443)
		cases["sameFlow"][i] = flowKeyPair{a: base, b: base}
		cases["sportDiffers"][i] = flowKeyPair{
			a: base,
			b: makeFlowKey(0x0a000001, 0x0a000002, uint16(40001+i), 443),
		}
		cases["dstDiffers"][i] = flowKeyPair{
			a: base,
			b: makeFlowKey(0x0a000001, uint32(0x0a000002+i+1), 40000, 443),
		}
		cases["allDiffer"][i] = flowKeyPair{
			a: makeFlowKey(uint32(0x0a000001+i), uint32(0x0a000002+i), uint16(40000+i), uint16(80+i)),
			b: makeFlowKey(uint32(0x0b000001+i), uint32(0x0b000002+i), uint16(50000+i), uint16(443+i)),
		}
	}
	return cases
}

// BenchmarkFlowKeyCompare measures flowKeyCompare across the workloads
// the sort step actually sees. Use this to compare reorderings.
func BenchmarkFlowKeyCompare(b *testing.B) {
	for name, pairs := range flowKeyCases() {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			var sink int
			for i := 0; i < b.N; i++ {
				p := pairs[i&(len(pairs)-1)]
				sink += flowKeyCompare(p.a, p.b)
			}
			runtime.KeepAlive(sink)
		})
	}
}
