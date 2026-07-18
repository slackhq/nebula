package batch

import (
	"io"
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
	return firstErr
}
