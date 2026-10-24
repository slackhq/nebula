package fec

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// slowMul is carry-less multiplication reduced by gfPoly, used to check the tables.
func slowMul(a, b byte) byte {
	var p int
	x, y := int(a), int(b)
	for y > 0 {
		if y&1 != 0 {
			p ^= x
		}
		x <<= 1
		if x&0x100 != 0 {
			x ^= gfPoly
		}
		y >>= 1
	}
	return byte(p)
}

func TestGF(t *testing.T) {
	for a := range 256 {
		for b := range 256 {
			require.Equal(t, slowMul(byte(a), byte(b)), gfMul(byte(a), byte(b)), "%d*%d", a, b)
		}
		if a != 0 {
			require.Equal(t, byte(1), gfMul(byte(a), gfInv(byte(a))), "inv(%d)", a)
		}
	}

	src := make([]byte, 256)
	for i := range src {
		src[i] = byte(i)
	}
	for c := range 256 {
		dst := make([]byte, 256)
		mulAdd(dst, src, byte(c))
		for i := range src {
			require.Equal(t, gfMul(byte(c), src[i]), dst[i])
		}
	}
}

func TestLayout(t *testing.T) {
	for msgLen := 1; msgLen <= 20000; msgLen++ {
		l, err := NewLayout(msgLen, 1176)
		require.NoError(t, err)
		require.Equal(t, (msgLen+1175)/1176, l.K)
		require.LessOrEqual(t, l.SymbolSize, 1176)
		require.GreaterOrEqual(t, l.K*l.SymbolSize, msgLen)
		require.Less(t, l.K*l.SymbolSize-msgLen, l.K, "padding must be less than one byte per symbol")
	}

	l, err := NewLayout(65535, 1176)
	require.NoError(t, err)
	assert.Equal(t, 56, l.K)

	_, err = NewLayout(0, 1176)
	require.ErrorIs(t, err, ErrInvalidLayout)
	_, err = NewLayout(100, 0)
	require.ErrorIs(t, err, ErrInvalidLayout)
	_, err = NewLayout(256, 1)
	require.ErrorIs(t, err, ErrInvalidLayout)
	_, err = NewLayout(255, 1)
	require.NoError(t, err)
}

func randMsg(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func decodeWith(t *testing.T, enc *Encoder, msgLen, maxSym int, indexes []int) []byte {
	t.Helper()
	dec, err := NewDecoder(msgLen, maxSym)
	require.NoError(t, err)
	for _, idx := range indexes {
		sym, err := enc.Symbol(nil, idx)
		require.NoError(t, err)
		_, err = dec.Add(idx, sym)
		require.NoError(t, err)
	}
	require.True(t, dec.Ready())
	// Decode after a prefix, into capacity holding garbage, which must neither
	// disturb the prefix nor leak into the message.
	dst := make([]byte, 3, 3+dec.Layout().K*dec.Layout().SymbolSize)
	for i := range dst[:cap(dst)] {
		dst[:cap(dst)][i] = 0xa5
	}
	out, err := dec.Decode(dst)
	require.NoError(t, err)
	require.Equal(t, []byte{0xa5, 0xa5, 0xa5}, out[:3])
	require.Equal(t, &dst[:1][0], &out[:1][0], "decoded in place")
	return out[3:]
}

// TestExhaustiveSubsets decodes every k-subset of the first k+m symbols for
// small codes, which checks the MDS property directly.
func TestExhaustiveSubsets(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	const maxSym = 16
	for k := 1; k <= 10; k++ {
		for m := 1; m <= 5; m++ {
			msgLen := (k-1)*maxSym + 1 + r.IntN(maxSym)
			msg := randMsg(r, msgLen)
			enc, err := NewEncoder(msg, maxSym)
			require.NoError(t, err)
			require.Equal(t, k, enc.Layout().K)

			n := k + m
			for mask := 0; mask < 1<<n; mask++ {
				var idx []int
				for i := range n {
					if mask&(1<<i) != 0 {
						idx = append(idx, i)
					}
				}
				if len(idx) != k {
					continue
				}
				require.Equal(t, msg, decodeWith(t, enc, msgLen, maxSym, idx), "k=%d m=%d idx=%v", k, m, idx)
			}
		}
	}
}

// TestRandomHighIndexes draws symbols from the whole index space, the shape
// retransmits produce once fresh repair symbols are in play.
func TestRandomHighIndexes(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for range 2000 {
		msgLen := 1 + r.IntN(65535)
		msg := randMsg(r, msgLen)
		enc, err := NewEncoder(msg, 1176)
		require.NoError(t, err)
		k := enc.Layout().K

		idx := r.Perm(MaxSymbols)[:k]
		require.Equal(t, msg, decodeWith(t, enc, msgLen, 1176, idx), "k=%d idx=%v", k, idx)
	}
}

func TestDecoderBounds(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	msg := randMsg(r, 3000)
	enc, err := NewEncoder(msg, 1176)
	require.NoError(t, err)
	l := enc.Layout()
	require.Equal(t, 3, l.K)
	require.Equal(t, 1000, l.SymbolSize)

	dec, err := NewDecoder(3000, 1176)
	require.NoError(t, err)

	_, err = dec.Decode(nil)
	require.ErrorIs(t, err, ErrNotEnough)

	_, err = dec.Add(-1, make([]byte, 1000))
	require.ErrorIs(t, err, ErrIndexRange)
	_, err = dec.Add(MaxSymbols, make([]byte, 1000))
	require.ErrorIs(t, err, ErrIndexRange)
	_, err = dec.Add(0, make([]byte, 999))
	require.ErrorIs(t, err, ErrSymbolSize)

	s5, _ := enc.Symbol(nil, 5)
	ready, err := dec.Add(5, s5)
	require.NoError(t, err)
	require.False(t, ready)

	// A duplicate index is ignored, even with different contents.
	ready, err = dec.Add(5, make([]byte, 1000))
	require.NoError(t, err)
	require.False(t, ready)

	s0, _ := enc.Symbol(nil, 0)
	s9, _ := enc.Symbol(nil, 9)
	_, err = dec.Add(0, s0)
	require.NoError(t, err)
	ready, err = dec.Add(9, s9)
	require.NoError(t, err)
	require.True(t, ready)

	// Symbols beyond K are not stored.
	ready, err = dec.Add(1, make([]byte, 1000))
	require.NoError(t, err)
	require.True(t, ready)
	require.Len(t, dec.syms, 3)

	out, err := dec.Decode(nil)
	require.NoError(t, err)
	require.Equal(t, msg, out)
}

func TestCorruptPadding(t *testing.T) {
	// 3001 bytes in 3 symbols of 1001 leaves 2 bytes of padding in the last one.
	dec, err := NewDecoder(3001, 1176)
	require.NoError(t, err)
	require.Equal(t, 1001, dec.Layout().SymbolSize)

	last := make([]byte, 1001)
	last[1000] = 1
	for i, s := range [][]byte{make([]byte, 1001), make([]byte, 1001), last} {
		_, err = dec.Add(i, s)
		require.NoError(t, err)
	}
	_, err = dec.Decode(nil)
	require.ErrorIs(t, err, ErrCorrupt)
}

// TestKnownAnswer pins the encoding. Both ends of a handshake must produce
// identical repair symbols, so any change here is a wire format change.
func TestKnownAnswer(t *testing.T) {
	msg := make([]byte, 3000)
	for i := range msg {
		msg[i] = byte(i*7 + 3)
	}
	enc, err := NewEncoder(msg, 1176)
	require.NoError(t, err)

	// Cross-checked against an independent bit-serial GF(2^8) implementation.
	want := map[int]string{
		3:   "52124f58276ec6338d3b3f4eed273bc7cabfe4f0f467928962b046ad1b348f50",
		4:   "a50928b04738981985a7d4a17ffaf8d7e30014ca64fc53c99800ffb61aec4aa7",
		5:   "ada4c95a7facbc542aaef584e6f0d081b7b0d0eed69ded03b57d0753a119cfc9",
		255: "839066cdf94f963b223fb1c1c1360f698c14f6349b25653ff5b521791a4021b1",
	}
	for idx, h := range want {
		sym, err := enc.Symbol(nil, idx)
		require.NoError(t, err)
		sum := sha256.Sum256(sym)
		assert.Equal(t, h, hex.EncodeToString(sum[:]), "symbol %d", idx)
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("hello"), uint16(2), uint64(0))
	f.Add(make([]byte, 9000), uint16(1176), uint64(7))
	f.Fuzz(func(t *testing.T, msg []byte, maxSym uint16, seed uint64) {
		if len(msg) == 0 || maxSym == 0 {
			return
		}
		enc, err := NewEncoder(msg, int(maxSym))
		if err != nil {
			return
		}
		r := rand.New(rand.NewPCG(seed, seed))
		idx := r.Perm(MaxSymbols)[:enc.Layout().K]
		require.Equal(t, msg, decodeWith(t, enc, len(msg), int(maxSym), idx))
	})
}

// FuzzDecoder feeds arbitrary symbols to a decoder; it must never panic and
// must either fail or return a message of the declared length.
func FuzzDecoder(f *testing.F) {
	f.Add(uint16(3000), []byte{0, 5, 9, 200}, []byte("some symbol bytes"))
	f.Fuzz(func(t *testing.T, msgLen uint16, indexes []byte, fill []byte) {
		dec, err := NewDecoder(int(msgLen), 1176)
		if err != nil {
			return
		}
		size := dec.Layout().SymbolSize
		for i, idx := range indexes {
			sym := make([]byte, size)
			for j := range sym {
				if len(fill) > 0 {
					sym[j] = fill[(i+j)%len(fill)]
				}
			}
			if _, err := dec.Add(int(idx), sym); err != nil {
				t.Fatal(err)
			}
		}
		out, err := dec.Decode(nil)
		if err == nil {
			require.Len(t, out, int(msgLen))
		}
	})
}

// BenchmarkRepair and BenchmarkDecode use a v3-sized msg2 (~9.8KB, k=9) with
// three repair symbols, decoding with three data symbols missing.
func BenchmarkRepair(b *testing.B) {
	msg := randMsg(rand.New(rand.NewPCG(7, 8)), 9800)
	enc, err := NewEncoder(msg, 1176)
	require.NoError(b, err)
	buf := make([]byte, 0, 1176)
	b.SetBytes(int64(len(msg)))
	for b.Loop() {
		for idx := 9; idx < 12; idx++ {
			buf, _ = enc.Symbol(buf[:0], idx)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	msg := randMsg(rand.New(rand.NewPCG(7, 8)), 9800)
	enc, err := NewEncoder(msg, 1176)
	require.NoError(b, err)
	idx := []int{0, 1, 2, 3, 5, 6, 9, 10, 11}
	syms := make([][]byte, len(idx))
	for i, x := range idx {
		syms[i], _ = enc.Symbol(nil, x)
	}
	b.SetBytes(int64(len(msg)))
	for b.Loop() {
		dec, _ := NewDecoder(len(msg), 1176)
		for i, x := range idx {
			_, _ = dec.Add(x, syms[i])
		}
		if _, err := dec.Decode(nil); err != nil {
			b.Fatal(err)
		}
	}
}
