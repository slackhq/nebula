package batch

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// BatchWriter is batchWriter for the port writers SetPortWriter returns
type BatchWriter = batchWriter

// sendPorts is SendBatch's state for packets committed with CommitPort
type sendPorts struct {
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

func (p *sendPorts) reset() {
	p.runs = p.runs[:0]
	p.mixed = false
}

// portRun is a run of consecutive slots committed for one port, starting at slot start
type portRun struct {
	start int
	port  uint16
}

// addRun records the slot just committed for port, call it after appending the slot
func (b *SendBatch) addRun(port uint16) {
	if n := len(b.ports.runs); n == 0 || b.ports.runs[n-1].port != port {
		b.ports.runs = append(b.ports.runs, portRun{start: len(b.bufs) - 1, port: port})
	}
}

// SetPortWriter sets how CommitPort's nonzero send ports map to writers. Port 0 always uses the batch's own writer.
func (b *SendBatch) SetPortWriter(fn func(port uint16) BatchWriter) {
	b.ports.portOut = fn
}

// CommitPort queues pkt for dst to leave from the multiport send port port, 0 is the batch's own writer.
// A nonzero port needs SetPortWriter, otherwise it is sent from the batch's own writer.
func (b *SendBatch) CommitPort(pkt []byte, dst netip.AddrPort, port uint16) {
	if port == 0 || b.ports.portOut == nil {
		b.Commit(pkt, dst)
		return
	}
	if !b.ports.mixed {
		// The slots committed before this one are a run on port 0
		b.ports.runs = b.ports.runs[:0]
		if len(b.bufs) > 0 {
			b.ports.runs = append(b.ports.runs, portRun{start: 0, port: 0})
		}
		b.ports.mixed = true
	}
	b.bufs = append(b.bufs, pkt)
	b.dsts = append(b.dsts, dst)
	b.addRun(port)
}

// flushPorts writes one WriteBatch per distinct send port, keeping each port's packets in commit order.
func (b *SendBatch) flushPorts() (int, error) {
	if b.ports.seen == nil {
		b.ports.seen = new([65536 / 64]uint64)
	}

	// The common case is every port in one run, the segments of a flow are committed back to back, and each run
	// can go out straight from bufs
	grouped := true
	var maxPort uint16
	for _, r := range b.ports.runs {
		maxPort = max(maxPort, r.port)
		w, bit := r.port/64, uint64(1)<<(r.port%64)
		if b.ports.seen[w]&bit != 0 {
			grouped = false
		}
		b.ports.seen[w] |= bit
	}
	for _, r := range b.ports.runs {
		b.ports.seen[r.port/64] = 0
	}

	var errs []error
	written := 0
	write := func(port uint16, bufs [][]byte, dsts []netip.AddrPort) {
		out := b.out
		if port != 0 {
			out = b.ports.portOut(port)
		}
		n, err := out.WriteBatch(bufs, dsts)
		written += n
		if err != nil {
			errs = append(errs, fmt.Errorf("multiport send port %d: %w", port, err))
		}
	}

	if grouped {
		for i, r := range b.ports.runs {
			start, end := b.runBounds(i)
			write(r.port, b.bufs[start:end], b.dsts[start:end])
		}
		return written, errors.Join(errs...)
	}

	// A port has several runs. Stable sort the runs by port and lay the slots out in that order, so each port is
	// one contiguous WriteBatch
	b.sortRuns(maxPort)
	runs := b.ports.runs

	b.ports.runBufs = b.ports.runBufs[:0]
	b.ports.runDsts = b.ports.runDsts[:0]
	for _, i := range b.ports.order {
		// Runs are often a single slot, a plain loop beats a slice append's bulk copy for those
		start, end := b.runBounds(i)
		for j := start; j < end; j++ {
			b.ports.runBufs = append(b.ports.runBufs, b.bufs[j])
			b.ports.runDsts = append(b.ports.runDsts, b.dsts[j])
		}
	}

	pos := 0
	for k := 0; k < len(b.ports.order); {
		port, begin := runs[b.ports.order[k]].port, pos
		for ; k < len(b.ports.order) && runs[b.ports.order[k]].port == port; k++ {
			start, end := b.runBounds(b.ports.order[k])
			pos += end - start
		}
		write(port, b.ports.runBufs[begin:pos], b.ports.runDsts[begin:pos])
	}
	clear(b.ports.runBufs)
	return written, errors.Join(errs...)
}

// sortRuns fills order with the run indices stably sorted by port, an LSD radix sort on the port bytes that skips
// the high byte when every port is below 256
func (b *SendBatch) sortRuns(maxPort uint16) {
	n := len(b.ports.runs)
	b.ports.order = slices.Grow(b.ports.order[:0], n)[:n]
	b.ports.orderTmp = slices.Grow(b.ports.orderTmp[:0], n)[:n]
	for i := range b.ports.order {
		b.ports.order[i] = i
	}

	for shift := uint(0); shift < 16 && maxPort>>shift > 0; shift += 8 {
		var counts [257]int32
		for _, i := range b.ports.order {
			counts[uint8(b.ports.runs[i].port>>shift)+1]++
		}
		for d := 1; d < len(counts); d++ {
			counts[d] += counts[d-1]
		}
		for _, i := range b.ports.order {
			d := uint8(b.ports.runs[i].port >> shift)
			b.ports.orderTmp[counts[d]] = i
			counts[d]++
		}
		b.ports.order, b.ports.orderTmp = b.ports.orderTmp, b.ports.order
	}
}

// runBounds returns the slots [start, end) of run i
func (b *SendBatch) runBounds(i int) (int, int) {
	end := len(b.bufs)
	if i+1 < len(b.ports.runs) {
		end = b.ports.runs[i+1].start
	}
	return b.ports.runs[i].start, end
}
