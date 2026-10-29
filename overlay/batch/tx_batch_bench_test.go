package batch

import (
	"net/netip"
	"testing"
)

// benchSendBatch fills a full batch with ports from portOf and flushes it, per iteration.
func benchSendBatch(b *testing.B, multiport bool, portOf func(i int) uint16) {
	w := noopBatchWriter{}
	sb := NewSendBatch(w, SendBatchCap, 0)
	if multiport {
		sb.SetPortWriter(func(uint16) BatchWriter { return w })
	}
	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	pkt := make([]byte, 1400)

	b.ReportAllocs()
	for b.Loop() {
		for i := range SendBatchCap {
			if multiport {
				sb.CommitPort(pkt, ap, portOf(i))
			} else {
				sb.Commit(pkt, ap)
			}
		}
		_, _ = sb.Flush()
	}
}

func BenchmarkSendBatch(b *testing.B) {
	b.Run("plain", func(b *testing.B) {
		benchSendBatch(b, false, nil)
	})
	b.Run("multiport/one_port", func(b *testing.B) {
		benchSendBatch(b, true, func(int) uint16 { return 7 })
	})
	// Superpacket segments of a few flows, committed back to back
	b.Run("multiport/grouped", func(b *testing.B) {
		benchSendBatch(b, true, func(i int) uint16 { return uint16(i / 32) })
	})
	// Many small flows interleaved across the ports
	b.Run("multiport/interleaved", func(b *testing.B) {
		benchSendBatch(b, true, func(i int) uint16 { return uint16(i % 100) })
	})
}
