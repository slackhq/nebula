#include "textflag.h"

// func checksumAVX2(buf []byte, initial uint16) uint16
//
// Computes the RFC 1071 ones-complement sum of buf, seeded with initial.
//
// Algorithm: sum the buffer treating it as a stream of uint32s in machine
// (little-endian) byte order, accumulating into 64-bit lanes (top 32 bits
// hold cross-add carries — at 1 byte / lane / iter we have 32 bits of
// headroom which is far more than the 16 KB/64 KB max practical inputs).
// At the end we fold to 16 bits and byte-swap once to recover the on-wire
// (big-endian) result. RFC 1071 §1.2.B byte-order independence makes this
// equivalent to summing as 16-bit big-endian words.
//
// The ymm accumulators (Y4..Y7) hold 4 uint64 lanes each = 16 parallel
// partial sums. The main loop loads 64 bytes per iter as four 16-byte
// chunks, zero-extending each chunk's four uint32s into a ymm via
// VPMOVZXDQ-from-memory, then VPADDQ into a separate accumulator per
// chunk to break the dep chain. After the vector loop the lane sums are
// horizontally reduced and merged with a scalar accumulator that handles
// the trailing 0..63 bytes plus the (byte-swapped) initial seed.
TEXT ·checksumAVX2(SB), NOSPLIT, $0-34
	MOVQ    buf_base+0(FP), SI
	MOVQ    buf_len+8(FP), CX
	MOVWQZX initial+24(FP), AX

	// Pre-byteswap initial into the LE-summing space so it merges directly
	// with the rest of the accumulator. The final fold's bswap16 will undo
	// this and convert the whole result back to BE.
	XCHGB AH, AL

	CMPQ CX, $32
	JLT  scalar_tail

	VPXOR Y4, Y4, Y4
	VPXOR Y5, Y5, Y5
	VPXOR Y6, Y6, Y6
	VPXOR Y7, Y7, Y7

	CMPQ CX, $64
	JLT  loop32

loop64:
	VPMOVZXDQ (SI), Y0
	VPMOVZXDQ 16(SI), Y1
	VPMOVZXDQ 32(SI), Y2
	VPMOVZXDQ 48(SI), Y3
	VPADDQ    Y0, Y4, Y4
	VPADDQ    Y1, Y5, Y5
	VPADDQ    Y2, Y6, Y6
	VPADDQ    Y3, Y7, Y7
	ADDQ      $64, SI
	SUBQ      $64, CX
	CMPQ      CX, $64
	JGE       loop64

loop32:
	CMPQ      CX, $32
	JLT       reduce_vec
	VPMOVZXDQ (SI), Y0
	VPMOVZXDQ 16(SI), Y1
	VPADDQ    Y0, Y4, Y4
	VPADDQ    Y1, Y5, Y5
	ADDQ      $32, SI
	SUBQ      $32, CX
	JMP       loop32

reduce_vec:
	// Combine the four ymm accumulators into Y4.
	VPADDQ Y5, Y4, Y4
	VPADDQ Y7, Y6, Y6
	VPADDQ Y6, Y4, Y4

	// Horizontally reduce Y4's four uint64 lanes to a single scalar.
	VEXTRACTI128 $1, Y4, X5
	VPADDQ       X5, X4, X4
	VPSHUFD      $0x4e, X4, X5
	VPADDQ       X5, X4, X4
	VMOVQ        X4, R8
	VZEROUPPER

	ADDQ R8, AX
	ADCQ $0, AX

scalar_tail:
	// Handle remaining 0..63 bytes (or the entire buffer if it was < 32).
	CMPQ CX, $8
	JLT  tail4

loop8:
	ADDQ (SI), AX
	ADCQ $0, AX
	ADDQ $8, SI
	SUBQ $8, CX
	CMPQ CX, $8
	JGE  loop8

tail4:
	CMPQ CX, $4
	JLT  tail2
	MOVL (SI), R8
	ADDQ R8, AX
	ADCQ $0, AX
	ADDQ $4, SI
	SUBQ $4, CX

tail2:
	CMPQ    CX, $2
	JLT     tail1
	MOVWQZX (SI), R8
	ADDQ    R8, AX
	ADCQ    $0, AX
	ADDQ    $2, SI
	SUBQ    $2, CX

tail1:
	TESTQ   CX, CX
	JZ      fold
	MOVBQZX (SI), R8
	ADDQ    R8, AX
	ADCQ    $0, AX

fold:
	// Fold the 64-bit accumulator to 16 bits via four rounds, mirroring
	// gvisor's reduce(). Each pair (split, add) halves the live width;
	// the truncation steps absorb the single bit that may be left over
	// after each add so the next round's bound holds.

	// 64 → 33 bits.
	MOVQ AX, R8
	SHRQ $32, R8
	MOVL AX, AX
	ADDQ R8, AX

	// 33 → 32 bits. AX += (AX>>32); truncate to 32. AX is now ≤ 0xFFFF_FFFF.
	MOVQ AX, R8
	SHRQ $32, R8
	ADDQ R8, AX
	MOVL AX, AX

	// 32 → 17 bits.
	MOVQ    AX, R8
	SHRQ    $16, R8
	MOVWQZX AX, AX
	ADDQ    R8, AX

	// 17 → 16 bits. AX += (AX>>16); the trailing MOVW truncates bit 16.
	MOVQ AX, R8
	SHRQ $16, R8
	ADDQ R8, AX

	// AX low 16 bits hold the 16-bit sum in machine (LE) byte order; flip
	// to big-endian to match the gvisor API contract.
	XCHGB AH, AL

	MOVW AX, ret+32(FP)
	RET
