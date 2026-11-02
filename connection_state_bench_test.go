package nebula

import (
	"sync/atomic"
	"testing"

	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/test"
)

// BenchmarkSendInsideEncrypt encrypts 1400 byte segments for a tunnel, uncontended from one goroutine, and from 8
// goroutines on their own queues of one tunnel or each on its own tunnel. Run with GODEBUG=fips140=on for the
// ciphers that need a lock.
func BenchmarkSendInsideEncrypt(b *testing.B) {
	f := &Interface{l: test.NewLogger()}
	hi := &HostInfo{remoteIndexId: 1}
	seg := make([]byte, 1400)

	newCI := func(b *testing.B, queues int) *ConnectionState {
		initR, _ := runTestHandshakeCipher(&testing.T{}, noiseutil.CipherAESGCM)
		ci, err := newConnectionStateFromResult(initR, ReplayWindow, queues)
		if err != nil {
			b.Fatal(err)
		}
		return ci
	}

	for _, queues := range []int{0, 8} {
		name := map[int]string{0: "one_cipher", 8: "8_queues"}[queues]

		b.Run(name+"/uncontended", func(b *testing.B) {
			ci := newCI(b, queues)
			nb := make([]byte, 12)
			scratch := make([]byte, header.Len+len(seg)+16)
			b.SetBytes(int64(len(seg)))
			for b.Loop() {
				if f.sendInsideEncrypt(hi, ci, seg, scratch, nb, 0) == nil {
					b.Fatal("encrypt failed")
				}
			}
		})

		b.Run(name+"/parallel_one_tunnel", func(b *testing.B) {
			ci := newCI(b, queues)
			var next atomic.Int32
			b.SetBytes(int64(len(seg)))
			b.SetParallelism(1)
			b.RunParallel(func(pb *testing.PB) {
				q := int(next.Add(1) - 1)
				nb := make([]byte, 12)
				scratch := make([]byte, header.Len+len(seg)+16)
				for pb.Next() {
					if f.sendInsideEncrypt(hi, ci, seg, scratch, nb, q) == nil {
						panic("encrypt failed")
					}
				}
			})
		})

		b.Run(name+"/parallel_own_tunnels", func(b *testing.B) {
			cis := make([]*ConnectionState, 64)
			for i := range cis {
				cis[i] = newCI(b, queues)
			}
			var next atomic.Int32
			b.SetBytes(int64(len(seg)))
			b.SetParallelism(1)
			b.RunParallel(func(pb *testing.PB) {
				q := int(next.Add(1) - 1)
				ci := cis[q%len(cis)]
				nb := make([]byte, 12)
				scratch := make([]byte, header.Len+len(seg)+16)
				for pb.Next() {
					if f.sendInsideEncrypt(hi, ci, seg, scratch, nb, q) == nil {
						panic("encrypt failed")
					}
				}
			})
		})
	}
}
