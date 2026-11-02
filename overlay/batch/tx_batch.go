package batch

import (
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

	// mixed is set by the first nonzero CommitPort, a batch without multiport packets pays nothing for runs
	mixed bool
	// runs marks each change of send port in commit order, only kept once mixed is set
	runs []portRun
	// seen is a bitset over ports, flushPorts uses it to find a port with more than one run
	seen *[65536 / 64]uint64
	// portOut picks the writer for a nonzero send port, see SetPortWriter
	portOut func(port uint16) BatchWriter
	// scratch for flushPorts when a port has more than one run: run indices sorted by port, and the slots laid
	// out in that order
	order    []int
	orderTmp []int
	runBufs  [][]byte
	runDsts  []netip.AddrPort
}

// portRun is a run of consecutive slots committed for one port, starting at slot start
type portRun struct {
	start int
	port  uint16
}

// NewSendBatch makes a SendBatch with batchCap slots and an arenaSize byte buffer for slices to back those slots
func NewSendBatch(out BatchWriter, batchCap, arenaSize int) *SendBatch {
	return &SendBatch{
		out:   out,
		bufs:  make([][]byte, 0, batchCap),
		dsts:  make([]netip.AddrPort, 0, batchCap),
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
	if b.mixed {
		b.addRun(0)
	}
}

// addRun records the slot just committed for port, call it after appending the slot
func (b *SendBatch) addRun(port uint16) {
	if n := len(b.runs); n == 0 || b.runs[n-1].port != port {
		b.runs = append(b.runs, portRun{start: len(b.bufs) - 1, port: port})
	}
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
	if !b.mixed {
		// The slots committed before this one are a run on port 0
		b.runs = b.runs[:0]
		if len(b.bufs) > 0 {
			b.runs = append(b.runs, portRun{start: 0, port: 0})
		}
		b.mixed = true
	}
	b.bufs = append(b.bufs, pkt)
	b.dsts = append(b.dsts, dst)
	b.addRun(port)
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
	b.runs = b.runs[:0]
	b.mixed = false
	b.arena.Reset()
	return written, err
}

// flushPorts writes one WriteBatch per distinct send port, keeping each port's packets in commit order.
func (b *SendBatch) flushPorts() (int, error) {
	if b.seen == nil {
		b.seen = new([65536 / 64]uint64)
	}

	// The common case is every port in one run, the segments of a flow are committed back to back, and each run
	// can go out straight from bufs
	grouped := true
	var maxPort uint16
	for _, r := range b.runs {
		maxPort = max(maxPort, r.port)
		w, bit := r.port/64, uint64(1)<<(r.port%64)
		if b.seen[w]&bit != 0 {
			grouped = false
		}
		b.seen[w] |= bit
	}
	for _, r := range b.runs {
		b.seen[r.port/64] = 0
	}

	var errs []error
	written := 0
	write := func(port uint16, bufs [][]byte, dsts []netip.AddrPort) {
		out := b.out
		if port != 0 {
			out = b.portOut(port)
		}
		n, err := out.WriteBatch(bufs, dsts)
		written += n
		if err != nil {
			errs = append(errs, err)
		}
	}

	if grouped {
		for i, r := range b.runs {
			start, end := b.runBounds(i)
			write(r.port, b.bufs[start:end], b.dsts[start:end])
		}
		return written, errors.Join(errs...)
	}

	// A port has several runs. Stable sort the runs by port and lay the slots out in that order, so each port is
	// one contiguous WriteBatch
	b.sortRuns(maxPort)
	runs := b.runs

	b.runBufs = b.runBufs[:0]
	b.runDsts = b.runDsts[:0]
	for _, i := range b.order {
		// Runs are often a single slot, a plain loop beats a slice append's bulk copy for those
		start, end := b.runBounds(i)
		for j := start; j < end; j++ {
			b.runBufs = append(b.runBufs, b.bufs[j])
			b.runDsts = append(b.runDsts, b.dsts[j])
		}
	}

	pos := 0
	for k := 0; k < len(b.order); {
		port, begin := runs[b.order[k]].port, pos
		for ; k < len(b.order) && runs[b.order[k]].port == port; k++ {
			start, end := b.runBounds(b.order[k])
			pos += end - start
		}
		write(port, b.runBufs[begin:pos], b.runDsts[begin:pos])
	}
	clear(b.runBufs)
	return written, errors.Join(errs...)
}

// sortRuns fills order with the run indices stably sorted by port, an LSD radix sort on the port bytes that skips
// the high byte when every port is below 256
func (b *SendBatch) sortRuns(maxPort uint16) {
	n := len(b.runs)
	b.order = slices.Grow(b.order[:0], n)[:n]
	b.orderTmp = slices.Grow(b.orderTmp[:0], n)[:n]
	for i := range b.order {
		b.order[i] = i
	}

	for shift := uint(0); shift < 16 && maxPort>>shift > 0; shift += 8 {
		var counts [257]int32
		for _, i := range b.order {
			counts[uint8(b.runs[i].port>>shift)+1]++
		}
		for d := 1; d < len(counts); d++ {
			counts[d] += counts[d-1]
		}
		for _, i := range b.order {
			d := uint8(b.runs[i].port >> shift)
			b.orderTmp[counts[d]] = i
			counts[d]++
		}
		b.order, b.orderTmp = b.orderTmp, b.order
	}
}

// runBounds returns the slots [start, end) of run i
func (b *SendBatch) runBounds(i int) (int, int) {
	end := len(b.bufs)
	if i+1 < len(b.runs) {
		end = b.runs[i+1].start
	}
	return b.runs[i].start, end
}
