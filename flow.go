package nebula

import (
	"log/slog"
	"runtime"
	"sync"

	"github.com/slackhq/nebula/config"
)

// Staged receive (tun.staged.workers) moves decryption off each udp listener onto worker goroutines, behind which an
// ordered writer commits every batch in arrival order. It reuses the inline packet handlers: staging changes ownership
// and scheduling, not policy. Each routine has its own workers and writer, so order is per routine. Full queues block
// the listener. A read error drains the batches in flight, while shutdown waits for the workers and then drops what
// is left. Each routine keeps six batches; at listen.batch=64 with GRO their buffers take about 24 MiB per routine.
//
// Metrics are registered only for active pipelines. flow.rx.batches counts batches handed to the writer and
// flow.rx.inline those an idle listener handled itself; their rates show whether staging is used.

// stagedConfig is tun.staged. workers is per routine; zero keeps receive inline.
type stagedConfig struct {
	workers int
	// inlineBelow is the packet count below which an idle listener skips the worker handoff
	inlineBelow int
}

// parseStagedConfig enables staging on Linux only; conns that cannot hand off batches also stay inline.
func parseStagedConfig(c *config.C, l *slog.Logger) stagedConfig {
	sc := stagedConfig{workers: c.GetInt("tun.staged.workers", 0)}
	if sc.workers <= 0 {
		return stagedConfig{}
	}
	if runtime.GOOS != "linux" {
		l.Warn("tun.staged is only supported on Linux; packet processing stays inline")
		return stagedConfig{}
	}
	// 256 is the measured crossover
	sc.inlineBelow = 256
	l.Info("Staged receive processing enabled", "workers", sc.workers)
	return sc
}

// flowJob is one batch of crypto work. It owns its packet buffers until run returns; jobs and queues are reused.
type flowJob interface{ run(nb []byte) }

// flowPool runs one listener's crypto jobs. The listener is the only producer and closes the pool once its ordered
// stage has drained.
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
