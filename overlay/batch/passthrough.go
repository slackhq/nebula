package batch

import (
	"io"

	"github.com/slackhq/nebula/udp"
)

// Passthrough is a RxBatcher that doesn't batch anything, it just accumulates and then sends packets.
type Passthrough struct {
	out      io.Writer
	slots    [][]byte
	reserver Reserver
	resetter Resetter
	cursor   int
}

const passthroughBaseNumSlots = 128

// DefaultPassthroughArenaCap is the recommended arena capacity for a
// standalone Passthrough batcher: 128 slots × udp.MTU ≈ 1.1 MiB.
const DefaultPassthroughArenaCap = passthroughBaseNumSlots * udp.MTU

func NewPassthrough(w io.Writer, reserver Reserver, resetter Resetter) *Passthrough {
	return &Passthrough{
		out:      w,
		slots:    make([][]byte, 0, passthroughBaseNumSlots),
		reserver: reserver,
		resetter: resetter,
	}
}

func (p *Passthrough) Reserve(sz int) []byte {
	return p.reserver(sz)
}

func (p *Passthrough) Commit(pkt []byte) error {
	p.slots = append(p.slots, pkt)
	return nil
}

// Flush drains every queued packet and calls the configured Resetter
func (p *Passthrough) Flush() error {
	firstErr := p.drain()
	if p.resetter != nil {
		p.resetter()
	}
	return firstErr
}

// drain writes out every queued packet and clears the slot list.
func (p *Passthrough) drain() error {
	var firstErr error
	for _, s := range p.slots {
		_, err := p.out.Write(s)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	clear(p.slots)
	p.slots = p.slots[:0]
	return firstErr
}
