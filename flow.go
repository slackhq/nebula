package nebula

import (
	"log/slog"
	"runtime"
	"sync"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/noiseutil"
)

// Staged processing (tun.staged.workers) moves crypto off each tun reader and udp listener onto worker goroutines,
// behind which an ordered stage sends or writes every batch in read order. It reuses the inline packet handlers:
// staging changes ownership and scheduling, not policy. Each routine has its own workers and ordered stages, so order
// is per routine. Full queues block the reader. A read error drains the batches in flight, while shutdown waits for
// the crypto and then drops packets whose destination has closed. A TX slot holds one tun read and its ciphertext,
// about 1.1 MiB; there are eight, or two more than the workers. An RX slot holds one recvmmsg batch, listen.batch
// times 64 KiB with GRO, and the count keeps up to 384 entries in flight in four to six slots: six and 24 MiB at
// listen.batch=64.
// tun.staged.tx_slots and rx_slots override the counts. Small-MSS TX arenas can grow.
//
// Metrics are registered only for active pipelines. flow.{tx,rx}.batches counts reads handed to the ordered stage and
// flow.{tx,rx}.inline those the reader handled itself (TX inline also counts oversized reads); their rates show
// whether staging is used. flow.tx.gate_switches counts transmit switches between inline and fanout mode.

// stagedConfig is tun.staged. workers is per routine and direction; zero keeps processing inline.
type stagedConfig struct {
	workers int
	tx      bool
	rx      bool
	// inlineBelow is the TX segment or RX packet count below which a read may skip the worker handoff, 0 never: a TX
	// read in inline mode, an RX read with nothing in flight
	inlineBelow int
	// txSlots and rxSlots are how many batches each routine can have in flight per direction
	txSlots, rxSlots int
	// gateHold is how many TX reads in a row must want the other mode before a routine switches between inline and
	// fanout transmit
	gateHold int
}

// stagedGateHold is the default tun.staged.gate_hold
const stagedGateHold = 64

const (
	// stagedTxSlots is the default TX slot count, unless the workers need more
	stagedTxSlots = 8
	// stagedRxEntries is how many recvmmsg entries the RX slots hold in flight by default
	stagedRxEntries = 6 * 64
	// stagedMinSlots lets the reader fill one batch while another is in flight
	stagedMinSlots = 2
	// stagedMinRxSlots keeps the default RX pipeline deep enough for large listen.batch values
	stagedMinRxSlots = 4
	// stagedMaxRxSlots is the measured default, a smaller listen.batch does not take more slots
	stagedMaxRxSlots = 6
)

// stagedSlots sizes the TX and RX slots. TX reads are bounded by the tun queue, so one slot per worker plus the one
// being read and the one being sent, and at least the eight measured. RX slots keep stagedRxEntries in flight, four
// to six, so a larger listen.batch means fewer slots and RX memory never exceeds the six measured. A positive override replaces either, down to stagedMinSlots.
func stagedSlots(workers, batch, txOverride, rxOverride int) (tx, rx int) {
	tx = max(stagedTxSlots, workers+2)
	rx = min(max(stagedMinRxSlots, (stagedRxEntries+batch-1)/max(batch, 1)), stagedMaxRxSlots)
	if txOverride > 0 {
		tx = max(txOverride, stagedMinSlots)
	}
	if rxOverride > 0 {
		rx = max(rxOverride, stagedMinSlots)
	}
	return tx, rx
}

// parseStagedConfig enables staging on Linux only; queues and conns that cannot hand off batches also stay inline.
func parseStagedConfig(c *config.C, l *slog.Logger) stagedConfig {
	sc := stagedConfig{workers: c.GetInt("tun.staged.workers", 0)}
	if sc.workers <= 0 {
		return stagedConfig{}
	}
	if runtime.GOOS != "linux" {
		l.Warn("tun.staged is only supported on Linux; packet processing stays inline")
		return stagedConfig{}
	}
	sc.tx, sc.rx = c.GetBool("tun.staged.tx", true), true
	// 256 is the measured crossover, 0 hands every batch to the workers
	sc.inlineBelow = max(c.GetInt("tun.staged.inline_below", 256), 0)
	if sc.tx && noiseutil.EncryptLockNeeded {
		l.Warn("tun.staged cannot encrypt in parallel with boringcrypto or fips140; transmit stays inline")
		sc.tx = false
	}
	sc.gateHold = max(c.GetInt("tun.staged.gate_hold", stagedGateHold), 1)
	sc.txSlots, sc.rxSlots = stagedSlots(sc.workers, c.GetInt("listen.batch", 64),
		c.GetInt("tun.staged.tx_slots", 0), c.GetInt("tun.staged.rx_slots", 0))
	l.Info("Staged packet processing enabled", "workers", sc.workers, "tx", sc.tx, "rx", sc.rx,
		"inlineBelow", sc.inlineBelow, "gateHold", sc.gateHold,
		"txSlots", sc.txSlots, "rxSlots", sc.rxSlots)
	return sc
}

// flowJob is one batch of crypto work. It owns its packet buffers until run returns; jobs and queues are reused.
type flowJob interface{ run(nb []byte) }

// flowPool runs one reader's crypto jobs. The reader is the only producer and closes the pool once its ordered stage
// has drained.
type flowPool struct {
	jobs chan flowJob
	wg   sync.WaitGroup
}

func newFlowPool(workers, queueLen int) *flowPool {
	p := &flowPool{jobs: make(chan flowJob, queueLen)}
	for range workers {
		p.wg.Go(func() {
			nb := make([]byte, 12)
			for job := range p.jobs {
				job.run(nb)
			}
		})
	}
	return p
}

func (p *flowPool) close() { close(p.jobs); p.wg.Wait() }
