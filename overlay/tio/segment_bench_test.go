//go:build linux && !android && !e2e_testing

package tio

import (
	"testing"

	"github.com/slackhq/nebula/wire"
)

// fakeBatch stands in for batch.TxBatcher inside the bench — same shape
// of pointer-capturing closure that sendInsideMessage builds.
type fakeBatch struct{ buf [65536]byte }

func (b *fakeBatch) Reserve(sz int) []byte { return b.buf[:sz] }
func (b *fakeBatch) Commit([]byte)         {}

type fakeHostInfo struct {
	remoteIndexId uint32
	counter       uint64
}
type fakeIface struct {
	rebindCount uint8
	hi          *fakeHostInfo
}

// BenchmarkSegmentSuperpacketAllocsTSO measures allocation per
// PerSegment call when a closure captures pointer-bearing receivers — the
// realistic shape of sendInsideMessage's closure.
func BenchmarkSegmentSuperpacketAllocsTSO(b *testing.B) {
	const mss = 1400
	const numSeg = 32
	pkt := buildTSOv6(mss*numSeg, mss)
	gso := wire.GSOInfo{
		Size:      mss,
		HdrLen:    60, // 40 (IPv6) + 20 (TCP)
		CsumStart: 40,
		Proto:     wire.GSOProtoTCP,
	}
	p := wire.TunPacket{Bytes: pkt, Meta: gso}

	hi := &fakeHostInfo{remoteIndexId: 0xdeadbeef}
	f := &fakeIface{rebindCount: 7, hi: hi}
	fb := &fakeBatch{}

	// PerSegment consumes pkt destructively; refresh from a master copy
	// each iter (matches the production pattern where every TUN read hands
	// the segmenter a fresh kernel-supplied buffer).
	master := append([]byte(nil), pkt...)
	work := make([]byte, len(pkt))
	p.Bytes = work

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(work, master)
		err := p.PerSegment(func(seg []byte) error {
			out := fb.Reserve(16 + len(seg) + 16)
			out[0] = byte(f.rebindCount)
			out[1] = byte(hi.counter)
			hi.counter++
			fb.Commit(out)
			return nil
		})
		if err != nil {
			b.Fatalf("PerSegment: %v", err)
		}
	}
}
