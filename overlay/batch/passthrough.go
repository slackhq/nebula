package batch

import (
	"io"

	"github.com/slackhq/nebula/overlay/tio"
)

// Passthrough is MultiCoalescer's verbatim lane: no coalescing, packets are written at Flush in the
// order enqueued, in one WriteBatch when out implements tio.BatchWriter.
type Passthrough struct {
	out   io.Writer
	bw    tio.BatchWriter // nil: Flush writes one packet per Write
	slots [][]byte
}

func NewPassthrough(w io.Writer) *Passthrough {
	bw, _ := w.(tio.BatchWriter)
	return &Passthrough{
		out:   w,
		bw:    bw,
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
	if p.bw != nil {
		if len(p.slots) > 0 {
			firstErr = p.bw.WriteBatch(p.slots)
		}
	} else {
		for _, s := range p.slots {
			_, err := p.out.Write(s)
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	clear(p.slots)
	p.slots = p.slots[:0]
	return firstErr
}
