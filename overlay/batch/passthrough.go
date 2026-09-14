package batch

import (
	"io"
)

// Passthrough is MultiCoalescer's verbatim lane: no batching, packets are written at Flush in the
// order enqueued.
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

// enqueue accepts one packet, already sorted into transmission order by dispatch.
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
