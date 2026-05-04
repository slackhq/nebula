package checksum

import (
	"fmt"
	"math/rand/v2"
	"testing"

	gvisorchecksum "gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// TestChecksumMatchesGvisor walks lengths from 0 to 4096, with several initial
// seeds and a handful of starting alignments, asserting that our local
// Checksum matches gvisor's reference bit-for-bit.
func TestChecksumMatchesGvisor(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	const padFront = 16

	// Random pool large enough for the longest case + alignment slop.
	pool := make([]byte, 4096+padFront)
	for i := range pool {
		pool[i] = byte(rng.Uint32())
	}

	seeds := []uint16{0, 0x0001, 0xabcd, 0xffff, 0x1234, 0xfedc}
	offsets := []int{0, 1, 2, 3, 4, 5, 7, 8, 15, 16}

	for length := 0; length <= 4096; length++ {
		for _, seed := range seeds {
			for _, off := range offsets {
				if off+length > len(pool) {
					continue
				}
				buf := pool[off : off+length]
				want := gvisorchecksum.Checksum(buf, seed)
				got := Checksum(buf, seed)
				if got != want {
					t.Fatalf("len=%d off=%d seed=%#x: got %#04x want %#04x",
						length, off, seed, got, want)
				}
			}
		}
	}
}

// TestChecksumPatternedBuffers exercises specific byte patterns that have
// historically tripped up checksum implementations: all-zero, all-0xff,
// alternating, and ascending sequences.
func TestChecksumPatternedBuffers(t *testing.T) {
	for length := 0; length <= 256; length++ {
		patterns := map[string][]byte{
			"zeros":       make([]byte, length),
			"ones":        bytes(length, 0xff),
			"alternating": pattern(length, []byte{0xa5, 0x5a}),
			"ascending":   ascending(length),
		}
		for name, buf := range patterns {
			for _, seed := range []uint16{0, 0xffff, 0x8000} {
				want := gvisorchecksum.Checksum(buf, seed)
				got := Checksum(buf, seed)
				if got != want {
					t.Fatalf("%s len=%d seed=%#x: got %#04x want %#04x",
						name, length, seed, got, want)
				}
			}
		}
	}
}

func bytes(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func pattern(n int, p []byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = p[i%len(p)]
	}
	return b
}

func ascending(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// TestChecksumTailPaths targets every combination of (SIMD body iterations,
// trailing tail bytes) the asm handlers walk through. The tail handlers
// peel off 8 → 4 → 2 → 1 byte chunks in turn; this test exercises each by
// constructing lengths of the form 64*k + tail for tail ∈ [0, 63] and a
// representative spread of k values, including k=0 (no main loop, all tail)
// and k=1 (one main loop iter, then tail). It's explicit coverage for
// payload sizes that are odd, not divisible by 4, by 8, or by 32.
func TestChecksumTailPaths(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 17))
	const padFront = 16
	const maxK = 8

	pool := make([]byte, 64*maxK+padFront+64)
	for i := range pool {
		pool[i] = byte(rng.Uint32())
	}

	seeds := []uint16{0, 0xffff, 0xabcd}
	offsets := []int{0, 1, 3, 7, 15} // mix of aligned and odd starts

	for k := 0; k <= maxK; k++ {
		for tail := 0; tail < 64; tail++ {
			length := 64*k + tail
			for _, seed := range seeds {
				for _, off := range offsets {
					if off+length > len(pool) {
						continue
					}
					buf := pool[off : off+length]
					want := gvisorchecksum.Checksum(buf, seed)
					got := Checksum(buf, seed)
					if got != want {
						t.Fatalf("k=%d tail=%d (len=%d) off=%d seed=%#x: got %#04x want %#04x",
							k, tail, length, off, seed, got, want)
					}
				}
			}
		}
	}
}

// BenchmarkChecksumTailSizes covers payload sizes that aren't clean multiples
// of the SIMD body's 32-byte (amd64) or 16-byte (arm64) chunks, so the tail
// handler is meaningfully on the hot path. Sizes are picked to either exercise
// every tail branch (tiny lengths) or sit slightly off realistic packet
// boundaries (e.g. 1499 = MTU − 1).
func BenchmarkChecksumTailSizes(b *testing.B) {
	sizes := []int{
		1, 3, 7, 15, 31, // sub-SIMD; entire work is scalar tail
		33, 35, 47, 63, // one loop32 + assorted tails
		65, 95, 127, // one loop64 + assorted tails
		1447, 1471, 1499, 1501, // around MTU
		8191, 8193, // around USO
		65531, 65533, // near the kernel max
	}
	for _, size := range sizes {
		buf := make([]byte, size)
		for i := range buf {
			buf[i] = byte(i)
		}
		b.Run(fmt.Sprintf("size=%d/local", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_ = Checksum(buf, 0)
			}
		})
		b.Run(fmt.Sprintf("size=%d/gvisor", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_ = gvisorchecksum.Checksum(buf, 0)
			}
		})
	}
}

// BenchmarkChecksum compares the local Checksum to gvisor's at sizes that
// match real traffic: a TCP/IP header (60), a typical MSS (1448), a typical
// USO size (8192), and the kernel's max GSO superpacket (65535).
func BenchmarkChecksum(b *testing.B) {
	for _, size := range []int{60, 1448, 8192, 65535} {
		buf := make([]byte, size)
		for i := range buf {
			buf[i] = byte(i)
		}
		b.Run(fmt.Sprintf("size=%d/local", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_ = Checksum(buf, 0)
			}
		})
		b.Run(fmt.Sprintf("size=%d/gvisor", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_ = gvisorchecksum.Checksum(buf, 0)
			}
		})
	}
}
