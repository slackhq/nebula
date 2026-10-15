package nebula

import (
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/noiseutil"
)

// Staged processing (tun.staged.workers) moves crypto off each tun reader and udp listener onto worker goroutines,
// behind which an ordered stage sends or writes every batch in read order. It reuses the inline packet handlers:
// staging changes ownership and scheduling, not policy. Each routine has its own workers and ordered stages, so order
// is per routine. Full queues block the reader. A read error drains the batches in flight, while shutdown waits for
// the crypto and then drops packets whose destination has closed. TX uses eight slots and RX six; at listen.batch=64
// with GRO their buffers take about 9 MiB and 24 MiB per routine. Small-MSS TX arenas can grow.
//
// Metrics are registered only for active pipelines. flow.{tx,rx}.batches counts reads handed to the ordered stage and
// flow.{tx,rx}.inline those an idle reader handled itself (TX inline also counts oversized reads); their rates show
// whether staging is used. flow.stage.<stage>.q<queue>.busy_ns locates the limiting stage: tx_read, tx_encrypt,
// tx_send, rx_read, rx_decrypt or rx_write. Take rates; 1e9 ns/s fills a serial stage. These are elapsed times that
// exclude read syscalls and downstream waits; descheduling inflates them and worker times add up across the pool.
// Inline work counts at the reader; small RX batches sent to the writer include decryption in writer time.

// stagedConfig is tun.staged. workers is per routine and direction; zero keeps processing inline.
type stagedConfig struct {
	workers int
	tx      bool
	rx      bool
	// inlineBelow is the TX segment or RX packet count below which an idle reader skips the worker handoff
	inlineBelow int
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
	sc.tx, sc.rx = true, true
	// 256 is the measured crossover
	sc.inlineBelow = 256
	if noiseutil.EncryptLockNeeded {
		l.Warn("tun.staged cannot encrypt in parallel with boringcrypto or fips140; transmit stays inline")
		sc.tx = false
	}
	l.Info("Staged packet processing enabled", "workers", sc.workers, "tx", sc.tx, "rx", sc.rx)
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

func newFlowPool(workers, queueLen int, busy metrics.Counter) *flowPool {
	p := &flowPool{jobs: make(chan flowJob, queueLen)}
	for range workers {
		p.wg.Go(func() {
			nb := make([]byte, 12)
			for job := range p.jobs {
				t := time.Now()
				job.run(nb)
				busy.Inc(int64(time.Since(t)))
			}
		})
	}
	return p
}

func (p *flowPool) close() { close(p.jobs); p.wg.Wait() }

// stageBusy is the busy time counter of one stage of routine q.
func stageBusy(stage string, q int) metrics.Counter {
	return metrics.GetOrRegisterCounter(fmt.Sprintf("flow.stage.%s.q%d.busy_ns", stage, q), nil)
}
