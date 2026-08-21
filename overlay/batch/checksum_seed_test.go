package batch

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// The checksum-seeding helpers feed the virtio NEEDS_CSUM contract: the L4
// checksum field is pre-loaded with the folded (not inverted) pseudo-header
// sum, and the kernel later adds the L4 byte sum and inverts. A wrong seed
// produces packets every receiver silently drops, with nothing failing on
// our side — so these tests check the helpers against an independent
// RFC 1071 reference built from explicit pseudo-header bytes, never against
// the production checksum code.

// refSum accumulates big-endian 16-bit words of b (odd tail zero-padded)
// into a wide one's-complement accumulator.
func refSum(b []byte) uint64 {
	var s uint64
	for i := 0; i+1 < len(b); i += 2 {
		s += uint64(b[i])<<8 | uint64(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint64(b[len(b)-1]) << 8
	}
	return s
}

// refFold folds a wide one's-complement accumulator to 16 bits.
func refFold(s uint64) uint16 {
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}

func TestFoldOnceNoInvertEdgeCases(t *testing.T) {
	cases := []uint32{
		0, 1, 0xffff,
		0x10000,    // single carry
		0x1fffe,    // 0xffff + 0xffff: carry produces another 0xffff
		0xffff0000, // high half only
		0xfffeffff, // fold yields 0x1fffd: needs a second fold
		0xffffffff, // worst case
		0x00010001, // simple two-word
	}
	for _, c := range cases {
		want := refFold(uint64(c))
		if got := foldOnceNoInvert(c); got != want {
			t.Errorf("foldOnceNoInvert(%#x) = %#x, want %#x", c, got, want)
		}
		// Folding a folded value must be a no-op.
		if got := foldOnceNoInvert(uint32(foldOnceNoInvert(c))); got != foldOnceNoInvert(c) {
			t.Errorf("foldOnceNoInvert not idempotent at %#x", c)
		}
	}
}

func TestPseudoSumIPv4MatchesReference(t *testing.T) {
	cases := []struct {
		name     string
		src, dst [4]byte
		proto    byte
		l4Len    int
	}{
		{"simple", [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 6, 20},
		{"zero-len", [4]byte{192, 168, 1, 1}, [4]byte{192, 168, 1, 2}, 17, 0},
		{"max-len", [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 6, 65535},
		{"carry-heavy", [4]byte{255, 255, 255, 255}, [4]byte{255, 255, 255, 254}, 17, 65535},
		{"broadcastish", [4]byte{255, 255, 255, 255}, [4]byte{255, 255, 255, 255}, 255, 65535},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// RFC 793 pseudo-header: src(4) dst(4) zero(1) proto(1) len(2).
			ph := make([]byte, 12)
			copy(ph[0:4], c.src[:])
			copy(ph[4:8], c.dst[:])
			ph[9] = c.proto
			binary.BigEndian.PutUint16(ph[10:12], uint16(c.l4Len))
			want := refFold(refSum(ph))

			got := foldOnceNoInvert(pseudoSumIPv4(c.src[:], c.dst[:], c.proto, c.l4Len))
			if got != want {
				t.Errorf("fold(pseudoSumIPv4) = %#x, want %#x", got, want)
			}
		})
	}
}

func TestPseudoSumIPv6MatchesReference(t *testing.T) {
	ones := func(b byte) (a [16]byte) {
		for i := range a {
			a[i] = b
		}
		return
	}
	cases := []struct {
		name     string
		src, dst [16]byte
		proto    byte
		l4Len    int
	}{
		{"simple", [16]byte{0xfe, 0x80, 15: 1}, [16]byte{0xfe, 0x80, 15: 2}, 6, 20},
		{"zero-len", [16]byte{0x20, 0x01, 15: 9}, [16]byte{0x20, 0x01, 15: 8}, 17, 0},
		{"max-u16-len", ones(0xff), ones(0xfe), 6, 65535},
		{"len-past-u16", ones(0xff), ones(0xff), 17, 0x12345}, // exercises the 32-bit split
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// RFC 8200 pseudo-header: src(16) dst(16) len(4) zero(3) next(1).
			ph := make([]byte, 40)
			copy(ph[0:16], c.src[:])
			copy(ph[16:32], c.dst[:])
			binary.BigEndian.PutUint32(ph[32:36], uint32(c.l4Len))
			ph[39] = c.proto
			want := refFold(refSum(ph))

			got := foldOnceNoInvert(pseudoSumIPv6(c.src[:], c.dst[:], c.proto, c.l4Len))
			if got != want {
				t.Errorf("fold(pseudoSumIPv6) = %#x, want %#x", got, want)
			}
		})
	}
}

func TestIPv4HdrChecksumMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1791))
	for _, hdrLen := range []int{20, 24, 40, 60} {
		for trial := 0; trial < 200; trial++ {
			hdr := make([]byte, hdrLen)
			rng.Read(hdr)
			hdr[0] = 0x40 | byte(hdrLen/4)
			hdr[10], hdr[11] = 0, 0 // checksum field zeroed, as the contract requires

			want := ^refFold(refSum(hdr))
			got := ipv4HdrChecksum(hdr)
			if got != want {
				t.Fatalf("ipv4HdrChecksum(len=%d trial=%d) = %#x, want %#x", hdrLen, trial, got, want)
			}

			// Receiver-side property: with the checksum stored, the full
			// header must sum to all-ones.
			binary.BigEndian.PutUint16(hdr[10:12], got)
			if v := refFold(refSum(hdr)); v != 0xffff {
				t.Fatalf("stored checksum does not validate: full-header fold = %#x", v)
			}
		}
	}
}

// TestChecksumSeedReceiverAcceptance is the end-to-end property the helpers
// exist for: seed the TCP checksum field with fold(pseudoSum), do what the
// kernel's NEEDS_CSUM completion does (one's-complement sum over the L4
// bytes including the seed, then invert, then store), and verify the result
// the way a receiver does (pseudo-header + L4 must sum to all-ones).
func TestChecksumSeedReceiverAcceptance(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1826))
	for trial := 0; trial < 200; trial++ {
		src := [4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		dst := [4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		payLen := rng.Intn(1500)
		l4 := make([]byte, 20+payLen)
		rng.Read(l4)

		// Seed exactly as flushSlot does.
		seed := foldOnceNoInvert(pseudoSumIPv4(src[:], dst[:], 6, len(l4)))
		binary.BigEndian.PutUint16(l4[16:18], seed)

		// Kernel NEEDS_CSUM completion: sum the L4 region (seed included,
		// which is equivalent to summing with the field zeroed and folding
		// the seed in), invert, store.
		final := ^refFold(refSum(l4[:16]) + uint64(seed) + refSum(l4[18:]))
		binary.BigEndian.PutUint16(l4[16:18], final)

		// Receiver validation.
		ph := make([]byte, 12)
		copy(ph[0:4], src[:])
		copy(ph[4:8], dst[:])
		ph[9] = 6
		binary.BigEndian.PutUint16(ph[10:12], uint16(len(l4)))
		if v := refFold(refSum(ph) + refSum(l4)); v != 0xffff {
			t.Fatalf("trial %d: receiver rejects packet: fold = %#x (seed=%#x final=%#x payLen=%d)",
				trial, v, seed, final, payLen)
		}
	}
}
