package batch

import (
	"io"

	"github.com/slackhq/nebula/udp"
)

// Passthrough is a RxBatcher that doesn't batch anything, it just accumulates and then sends packets.
type Passthrough struct {
	out     io.Writer
	slots   [][]byte
	backing []byte
	cursor  int
}

func NewPassthrough(w io.Writer) *Passthrough {
	const baseNumSlots = 128
	return &Passthrough{
		out:     w,
		slots:   make([][]byte, 0, baseNumSlots),
		backing: make([]byte, 0, baseNumSlots*udp.MTU),
	}
}

func (p *Passthrough) Reserve(sz int) []byte {
	if len(p.backing)+sz > cap(p.backing) {
		// Grow: allocate a fresh backing. Already-committed slices still
		// reference the old array and remain valid until Flush drops them.
		newCap := max(cap(p.backing)*2, sz)
		p.backing = make([]byte, 0, newCap)
	}
	start := len(p.backing)
	p.backing = p.backing[:start+sz]
	return p.backing[start : start+sz : start+sz] //return zero length, sz-cap slice
}

func (p *Passthrough) Commit(pkt []byte) error {
	p.slots = append(p.slots, pkt)
	return nil
}

func (p *Passthrough) Flush() error {
	var firstErr error
	for _, s := range p.slots {
		_, err := p.out.Write(s)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for i := range p.slots {
		p.slots[i] = nil
	}
	p.slots = p.slots[:0]
	p.backing = p.backing[:0]
	return firstErr
}
