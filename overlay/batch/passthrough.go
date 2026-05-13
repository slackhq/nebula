package batch

import (
	"io"

	"github.com/slackhq/nebula/udp"
)

// Passthrough is a RxBatcher that doesn't batch anything, it just accumulates and then sends packets.
type Passthrough struct {
	out    io.Writer
	slots  [][]byte
	arena  *Arena
	cursor int
}

const passthroughBaseNumSlots = 128

// DefaultPassthroughArenaCap is the recommended arena capacity for a
// standalone Passthrough batcher: 128 slots × udp.MTU ≈ 1.1 MiB.
const DefaultPassthroughArenaCap = passthroughBaseNumSlots * udp.MTU

func NewPassthrough(w io.Writer, slots int, arena *Arena) *Passthrough {
	return &Passthrough{
		out:   w,
		slots: make([][]byte, 0, slots),
		arena: arena,
	}
}

func (p *Passthrough) Reserve(sz int) []byte {
	return p.arena.Reserve(sz)
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
	clear(p.slots)
	p.slots = p.slots[:0]
	p.arena.Reset()
	return firstErr
}
