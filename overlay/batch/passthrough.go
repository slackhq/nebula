package batch

import (
	"io"

	"github.com/slackhq/nebula/firewall"
)

// Passthrough is a RxBatcher that doesn't batch anything, it just accumulates and then sends packets.
type Passthrough struct {
	out   io.Writer
	slots [][]byte
}

func NewPassthrough(w io.Writer) *Passthrough {
	return &Passthrough{
		out:   w,
		slots: make([][]byte, 0, 128),
	}
}

func (p *Passthrough) Commit(pkt []byte, _ SortKey, _ *firewall.ParsedPacket) error {
	return p.enqueue(pkt)
}

// enqueue is the lane-facing half of Commit: MultiCoalescer.dispatch hands
// packets here already sorted into transmission order.
func (p *Passthrough) enqueue(pkt []byte) error {
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
	return firstErr
}
