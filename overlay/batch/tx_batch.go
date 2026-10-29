package batch

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
)

const SendBatchCap = 128

// BatchWriter is the minimal subset of udp.Conn needed by SendBatch to flush.
type BatchWriter interface {
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error)
}

// SendBatch accumulates encrypted UDP packets and flushes them via WriteBatch.
// Each reader goroutine owns its own SendBatch; no locking is needed.
// Slots can borrow receive buffers or be backed by an Arena (see its docs).
type SendBatch struct {
	out   BatchWriter
	bufs  [][]byte
	dsts  []netip.AddrPort
	arena *Arena

	// ports holds the multiport send port of each slot, mixed is set once any of them is nonzero
	ports []uint16
	mixed bool
	// portOut picks the writer for a nonzero send port, see SetPortWriter
	portOut func(port uint16) BatchWriter
	// scratch for flushPorts: slot indices sorted by port, and the slots laid out in that order
	order   []int
	runBufs [][]byte
	runDsts []netip.AddrPort
}

// NewSendBatch makes a SendBatch with batchCap slots and an arenaSize byte buffer for slices to back those slots
func NewSendBatch(out BatchWriter, batchCap, arenaSize int) *SendBatch {
	return &SendBatch{
		out:   out,
		bufs:  make([][]byte, 0, batchCap),
		dsts:  make([]netip.AddrPort, 0, batchCap),
		ports: make([]uint16, 0, batchCap),
		arena: NewArena(arenaSize),
	}
}

func (b *SendBatch) Reserve(sz int) []byte {
	return b.arena.Reserve(sz)
}

// Len reports how many packets are queued for the next Flush. Callers use
// it to flush incrementally once a full sendmmsg batch has accumulated,
// bounding how long the first packet of a large read batch waits.
func (b *SendBatch) Len() int { return len(b.bufs) }

func (b *SendBatch) Commit(pkt []byte, dst netip.AddrPort) {
	b.bufs = append(b.bufs, pkt)
	b.dsts = append(b.dsts, dst)
	b.ports = append(b.ports, 0)
}

// SetPortWriter sets how CommitPort's nonzero send ports map to writers. Port 0 always uses the batch's own writer.
func (b *SendBatch) SetPortWriter(fn func(port uint16) BatchWriter) {
	b.portOut = fn
}

// CommitPort queues pkt for dst to leave from the multiport send port port, 0 is the batch's own writer.
// A nonzero port needs SetPortWriter, otherwise it is sent from the batch's own writer.
func (b *SendBatch) CommitPort(pkt []byte, dst netip.AddrPort, port uint16) {
	if port == 0 || b.portOut == nil {
		b.Commit(pkt, dst)
		return
	}
	b.mixed = true
	b.bufs = append(b.bufs, pkt)
	b.dsts = append(b.dsts, dst)
	b.ports = append(b.ports, port)
}

// Flush writes every queued packet and reports how many actually went out. A short count means some destinations
// were undeliverable; the batch is drained either way.
func (b *SendBatch) Flush() (int, error) {
	var err error
	written := 0
	if b.mixed {
		written, err = b.flushPorts()
	} else if len(b.bufs) > 0 {
		written, err = b.out.WriteBatch(b.bufs, b.dsts)
	}
	clear(b.bufs)
	b.bufs = b.bufs[:0]
	b.dsts = b.dsts[:0]
	b.ports = b.ports[:0]
	b.mixed = false
	b.arena.Reset()
	return written, err
}

// flushPorts writes one WriteBatch per distinct send port, keeping each port's packets in commit order.
func (b *SendBatch) flushPorts() (int, error) {
	// Stable sort the slots by port, then lay them out in that order so each port's run is one contiguous WriteBatch
	b.order = b.order[:0]
	for i := range b.bufs {
		b.order = append(b.order, i)
	}
	ports := b.ports
	slices.SortStableFunc(b.order, func(x, y int) int { return cmp.Compare(ports[x], ports[y]) })

	b.runBufs = b.runBufs[:0]
	b.runDsts = b.runDsts[:0]
	for _, i := range b.order {
		b.runBufs = append(b.runBufs, b.bufs[i])
		b.runDsts = append(b.runDsts, b.dsts[i])
	}

	var errs []error
	written := 0
	for start := 0; start < len(b.order); {
		port := ports[b.order[start]]
		end := start + 1
		for end < len(b.order) && ports[b.order[end]] == port {
			end++
		}

		out := b.out
		if port != 0 {
			out = b.portOut(port)
		}
		n, err := out.WriteBatch(b.runBufs[start:end], b.runDsts[start:end])
		written += n
		if err != nil {
			errs = append(errs, err)
		}
		start = end
	}
	clear(b.runBufs)
	return written, errors.Join(errs...)
}
