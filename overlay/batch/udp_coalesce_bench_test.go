package batch

import (
	"testing"
)

// buildUDPv4BulkFlow returns n equal-size datagrams on one flow — the
// steady state for single-flow QUIC bulk, the workload USO exists for.
func buildUDPv4BulkFlow(n, payloadLen int) [][]byte {
	pay := make([]byte, payloadLen)
	pkts := make([][]byte, n)
	for i := range pkts {
		pkts[i] = buildUDPv4(40000, 443, pay)
	}
	return pkts
}

// buildUDPv4RunInterleaved mirrors buildTCPv4RunInterleaved: nFlows*perFlow
// datagrams arriving in GRO-burst runs of runLen per flow.
func buildUDPv4RunInterleaved(nFlows, perFlow, runLen, payloadLen int) [][]byte {
	pay := make([]byte, payloadLen)
	pkts := make([][]byte, 0, nFlows*perFlow)
	for done := 0; done < perFlow; done += runLen {
		for f := range nFlows {
			sport := uint16(40000 + f)
			for range runLen {
				pkts = append(pkts, buildUDPv4(sport, 443, pay))
			}
		}
	}
	return pkts
}

// runUDPCommitBench drives UDPCoalescer.Commit over pkts batchSize at a
// time, flushing between batches, and reports per-packet cost.
func runUDPCommitBench(b *testing.B, pkts [][]byte, batchSize int) {
	b.Helper()
	c := newTestUDPCoalescer(b, nopTunWriter{})
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
	_ = c.Flush()
}

// BenchmarkUDPCommitSingleFlow is the single-flow bulk steady state.
func BenchmarkUDPCommitSingleFlow(b *testing.B) {
	pkts := buildUDPv4BulkFlow(udpCoalesceMaxSegs, 1200)
	runUDPCommitBench(b, pkts, udpCoalesceMaxSegs)
}

// BenchmarkUDPCommitInterleaved4 is the adversarial per-packet round-robin.
func BenchmarkUDPCommitInterleaved4(b *testing.B) {
	pkts := buildUDPv4RunInterleaved(4, udpCoalesceMaxSegs, 1, 1200)
	runUDPCommitBench(b, pkts, len(pkts))
}

// BenchmarkUDPCommitRunInterleaved4 is 4 flows in GRO-burst runs of 16.
func BenchmarkUDPCommitRunInterleaved4(b *testing.B) {
	pkts := buildUDPv4RunInterleaved(4, udpCoalesceMaxSegs, 16, 1200)
	runUDPCommitBench(b, pkts, len(pkts))
}
