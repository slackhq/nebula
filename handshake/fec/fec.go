// Package fec implements the systematic Reed-Solomon erasure code used to carry
// handshake messages that do not fit in a single UDP packet.
//
// A message is split into K equally sized data symbols (the last one zero
// padded). Symbol indexes 0..K-1 are the data symbols themselves; indexes
// K..MaxSymbols-1 are repair symbols. Any K distinct symbols reconstruct the
// message. Repair symbols are generated on demand, so a sender can emit fresh
// ones on every retransmit and a receiver can merge everything it has seen.
package fec

import (
	"errors"
	"fmt"
	"slices"
)

// MaxSymbols is the number of distinct symbols, data and repair together, one
// message can be encoded into. It is bounded by the size of GF(2^8).
const MaxSymbols = 256

var (
	ErrInvalidLayout = errors.New("invalid fec layout")
	ErrIndexRange    = errors.New("symbol index out of range")
	ErrSymbolSize    = errors.New("symbol has the wrong size")
	ErrNotEnough     = errors.New("not enough symbols to decode")
	ErrCorrupt       = errors.New("decoded message has non-zero padding")
)

// Layout describes how a message is split into symbols. Both ends derive it
// from the message length alone, so it never has to be sent.
type Layout struct {
	MsgLen     int // length of the message in bytes
	K          int // number of data symbols
	SymbolSize int // size of every symbol, data and repair
}

// NewLayout returns the layout for a message of msgLen bytes carried in symbols
// of at most maxSymbolSize bytes. Symbols are balanced, so padding is always
// less than K bytes.
func NewLayout(msgLen, maxSymbolSize int) (Layout, error) {
	if msgLen <= 0 || maxSymbolSize <= 0 {
		return Layout{}, ErrInvalidLayout
	}
	k := (msgLen + maxSymbolSize - 1) / maxSymbolSize
	if k >= MaxSymbols {
		return Layout{}, fmt.Errorf("%w: %d data symbols", ErrInvalidLayout, k)
	}
	return Layout{
		MsgLen:     msgLen,
		K:          k,
		SymbolSize: (msgLen + k - 1) / k,
	}, nil
}

// Encoder produces symbols for one message.
type Encoder struct {
	layout Layout
	data   [][]byte
}

// NewEncoder splits msg into data symbols. They alias msg, all but a padded
// last symbol, so msg must not change while the Encoder is in use.
func NewEncoder(msg []byte, maxSymbolSize int) (*Encoder, error) {
	l, err := NewLayout(len(msg), maxSymbolSize)
	if err != nil {
		return nil, err
	}

	data := make([][]byte, l.K)
	for i := range data {
		data[i] = msg[i*l.SymbolSize : min((i+1)*l.SymbolSize, len(msg))]
	}
	if last := data[l.K-1]; len(last) < l.SymbolSize {
		data[l.K-1] = append(make([]byte, 0, l.SymbolSize), last...)[:l.SymbolSize]
	}
	return &Encoder{layout: l, data: data}, nil
}

func (e *Encoder) Layout() Layout {
	return e.layout
}

// Symbol appends the symbol with the given index to dst and returns the result.
func (e *Encoder) Symbol(dst []byte, index int) ([]byte, error) {
	if index < 0 || index >= MaxSymbols {
		return nil, ErrIndexRange
	}
	if index < e.layout.K {
		return append(dst, e.data[index]...), nil
	}

	start := len(dst)
	dst = append(dst, make([]byte, e.layout.SymbolSize)...)
	out := dst[start:]
	for col, d := range e.data {
		mulAdd(out, d, coefficient(index, col))
	}
	return dst, nil
}

// Decoder collects symbols for one message until it can reconstruct it.
// It stores at most K symbols, so its memory is bounded by the layout no matter
// how many symbols arrive.
//
// TODO(in-place decode): for receivers that already hold state for the message,
// the initiator's msg2 slots and a pending responder's msg3, store into one
// buffer of K*SymbolSize (plus room for the Nebula header) allocated from the
// layout: data symbol i at offset i*SymbolSize, repair symbols parked in the
// slots of data symbols not seen yet (moved to another empty slot if that data
// symbol arrives; one always exists while fewer than K are held). Decode then
// folds the known columns into each parked repair symbol in place and runs
// Gauss-Jordan across those rows in place; a Cauchy submatrix needs no
// pivoting, so each solution lands in the slot of its own column and the
// buffer is the packet. That removes the per-symbol copies, about 10KB and a
// dozen allocations per msg2, at the
// cost of holding K*SymbolSize from the first fragment and destroying the
// input on a failed decode. It is not for the responder's msg1 table, which
// must never allocate from a claimed size.
type Decoder struct {
	layout Layout
	have   [MaxSymbols]bool
	syms   map[int][]byte
}

// NewDecoder returns a decoder for a message of msgLen bytes that was encoded
// with the same maxSymbolSize.
func NewDecoder(msgLen, maxSymbolSize int) (*Decoder, error) {
	l, err := NewLayout(msgLen, maxSymbolSize)
	if err != nil {
		return nil, err
	}
	return &Decoder{layout: l, syms: make(map[int][]byte, l.K)}, nil
}

func (d *Decoder) Layout() Layout {
	return d.layout
}

// Stored returns the number of symbols held.
func (d *Decoder) Stored() int {
	return len(d.syms)
}

// Has reports whether the symbol with the given index is held.
func (d *Decoder) Has(index int) bool {
	return index >= 0 && index < MaxSymbols && d.have[index]
}

// Seen returns which symbol indexes are held.
func (d *Decoder) Seen() [MaxSymbols]bool {
	return d.have
}

// Ready reports whether enough symbols have arrived to decode.
func (d *Decoder) Ready() bool {
	return len(d.syms) >= d.layout.K
}

// Add stores a copy of the symbol. Duplicates, and anything beyond the first K
// distinct symbols, are ignored. It returns whether the decoder is ready.
func (d *Decoder) Add(index int, sym []byte) (bool, error) {
	if index < 0 || index >= MaxSymbols {
		return d.Ready(), ErrIndexRange
	}
	if len(sym) != d.layout.SymbolSize {
		return d.Ready(), ErrSymbolSize
	}
	if d.have[index] || d.Ready() {
		return d.Ready(), nil
	}
	d.have[index] = true
	d.syms[index] = append([]byte(nil), sym...)
	return d.Ready(), nil
}

// Decode reconstructs the message from the stored symbols and appends it to
// dst. Decoding needs the padding of the last symbol too, so dst has to have
// room for K*SymbolSize bytes or it is grown to.
func (d *Decoder) Decode(dst []byte) ([]byte, error) {
	if !d.Ready() {
		return nil, ErrNotEnough
	}
	l := d.layout

	start := len(dst)
	dst = slices.Grow(dst, l.K*l.SymbolSize)[:start+l.K*l.SymbolSize]
	out := dst[start:]
	var missing, repair []int
	for i := range l.K {
		if s, ok := d.syms[i]; ok {
			copy(out[i*l.SymbolSize:], s)
		} else {
			clear(out[i*l.SymbolSize : (i+1)*l.SymbolSize])
			missing = append(missing, i)
		}
	}

	if len(missing) > 0 {
		for i := l.K; i < MaxSymbols && len(repair) < len(missing); i++ {
			if d.have[i] {
				repair = append(repair, i)
			}
		}
		if len(repair) < len(missing) {
			return nil, ErrNotEnough
		}

		// Each repair symbol r satisfies r = sum_col coefficient(r, col) * data[col].
		// Move the known data columns to the left hand side, leaving a square
		// Cauchy system in the missing columns.
		rhs := make([][]byte, len(repair))
		m := make([][]byte, len(repair))
		for ri, row := range repair {
			rhs[ri] = append([]byte(nil), d.syms[row]...)
			m[ri] = make([]byte, len(missing))
			mi := 0
			for col := range l.K {
				if mi < len(missing) && missing[mi] == col {
					m[ri][mi] = coefficient(row, col)
					mi++
					continue
				}
				mulAdd(rhs[ri], out[col*l.SymbolSize:(col+1)*l.SymbolSize], coefficient(row, col))
			}
		}
		if !invert(m) {
			// Unreachable for a Cauchy matrix; kept so a broken invariant fails loudly.
			return nil, errors.New("fec: singular decode matrix")
		}
		for mi, col := range missing {
			dst := out[col*l.SymbolSize : (col+1)*l.SymbolSize]
			for ri := range repair {
				mulAdd(dst, rhs[ri], m[mi][ri])
			}
		}
	}

	for _, b := range out[l.MsgLen:] {
		if b != 0 {
			return nil, ErrCorrupt
		}
	}
	return dst[:start+l.MsgLen], nil
}
