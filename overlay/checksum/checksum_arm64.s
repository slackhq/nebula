#include "textflag.h"

// func checksumNEON(buf []byte, initial uint16) uint16
//
// Mirrors the algorithm in checksum_amd64.s: sum the buffer treating it as
// a stream of uint32s in machine (little-endian) byte order, accumulating
// into 64-bit lanes that have ample carry headroom; fold and byte-swap once
// at the very end to recover the on-wire (big-endian) result.
//
// Each loop iteration loads 64 bytes via VLD1.P into V0..V3 (4 Q regs).
// VUADDW takes the low two uint32 lanes of a Q reg, zero-extends them to
// uint64, and adds them into a 2×uint64 accumulator; VUADDW2 does the same
// for the high two lanes. Four ymm-equivalent accumulators (V8..V11) get
// updated twice per iter to break the dep chain. Tail bytes go through a
// scalar ADCS chain seeded with the byte-swapped initial.
TEXT ·checksumNEON(SB), NOSPLIT, $0-34
	MOVD  buf_base+0(FP), R0
	MOVD  buf_len+8(FP), R1
	MOVHU initial+24(FP), R2

	// Pre-byteswap initial into the LE-summing space so it merges directly
	// with the rest of the accumulator.
	REV16W R2, R2

	MOVD ZR, R3 // scalar accumulator

	CMP $32, R1
	BLT scalar_tail

	VEOR V8.B16, V8.B16, V8.B16
	VEOR V9.B16, V9.B16, V9.B16
	VEOR V10.B16, V10.B16, V10.B16
	VEOR V11.B16, V11.B16, V11.B16

	CMP $64, R1
	BLT loop16_init

loop64:
	VLD1.P  64(R0), [V0.B16, V1.B16, V2.B16, V3.B16]
	VUADDW  V0.S2, V8.D2, V8.D2
	VUADDW2 V0.S4, V9.D2, V9.D2
	VUADDW  V1.S2, V10.D2, V10.D2
	VUADDW2 V1.S4, V11.D2, V11.D2
	VUADDW  V2.S2, V8.D2, V8.D2
	VUADDW2 V2.S4, V9.D2, V9.D2
	VUADDW  V3.S2, V10.D2, V10.D2
	VUADDW2 V3.S4, V11.D2, V11.D2
	SUB     $64, R1, R1
	CMP     $64, R1
	BGE     loop64

loop16_init:
	CMP $16, R1
	BLT reduce_vec

loop16:
	VLD1.P  16(R0), [V0.B16]
	VUADDW  V0.S2, V8.D2, V8.D2
	VUADDW2 V0.S4, V9.D2, V9.D2
	SUB     $16, R1, R1
	CMP     $16, R1
	BGE     loop16

reduce_vec:
	// Combine the four accumulators into V8.
	VADD V9.D2, V8.D2, V8.D2
	VADD V11.D2, V10.D2, V10.D2
	VADD V10.D2, V8.D2, V8.D2

	// Horizontal-add the two lanes of V8.D2 into a single uint64.
	VADDP V8.D2, V8.D2, V8.D2
	VMOV  V8.D[0], R8

	ADDS R8, R3, R3
	ADC  ZR, R3, R3

scalar_tail:
	CMP $8, R1
	BLT tail4

loop8:
	MOVD.P 8(R0), R8
	ADDS   R8, R3, R3
	ADC    ZR, R3, R3
	SUB    $8, R1, R1
	CMP    $8, R1
	BGE    loop8

tail4:
	CMP    $4, R1
	BLT    tail2
	MOVWU.P 4(R0), R8
	ADDS   R8, R3, R3
	ADC    ZR, R3, R3
	SUB    $4, R1, R1

tail2:
	CMP    $2, R1
	BLT    tail1
	MOVHU.P 2(R0), R8
	ADDS   R8, R3, R3
	ADC    ZR, R3, R3
	SUB    $2, R1, R1

tail1:
	CBZ R1, fold
	MOVBU (R0), R8
	ADDS  R8, R3, R3
	ADC   ZR, R3, R3

fold:
	// Merge the byte-swapped initial into our LE-form accumulator.
	ADDS R2, R3, R3
	ADC  ZR, R3, R3

	// 64 → 33 bits.
	LSR $32, R3, R8
	AND $0xffffffff, R3, R3
	ADD R8, R3, R3

	// 33 → 32 (truncate after adding bit 32 back).
	LSR $32, R3, R8
	ADD R8, R3, R3
	AND $0xffffffff, R3, R3

	// 32 → 17.
	LSR $16, R3, R8
	AND $0xffff, R3, R3
	ADD R8, R3, R3

	// 17 → 16 (truncation absorbs bit 16 below).
	LSR $16, R3, R8
	ADD R8, R3, R3

	// AX low 16 bits hold the 16-bit sum in machine (LE) byte order; flip
	// to big-endian to match the gvisor API contract. REV16W swaps bytes
	// within each 16-bit halfword of the low 32 bits, so it acts as a
	// 16-bit byte-swap on the live low 16.
	REV16W R3, R3
	AND    $0xffff, R3, R3

	MOVH R3, ret+32(FP)
	RET
