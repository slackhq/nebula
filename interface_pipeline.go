//go:build darwin || send_pipeline

package nebula

import (
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/udp"
)

// sendPipelinePlatform lets listenIn take the pipelined send path. It is on for darwin, and for any platform built
// with -tags send_pipeline so the pipeline's tests (and the e2e suite through it) run on linux too.
const sendPipelinePlatform = true

// listenInPipelined is f.listenIn with the underlay writes moved to a sender goroutine (batch.SendPipeline). This
// goroutine still reads the tun, runs the firewall and encrypts, straight into the pipeline's batch. The sender
// writes whatever has built up each time its previous write returns, so under load the packets read while one
// write is in the kernel leave together in the next one, and the next tun read overlaps the write.
func listenInPipelined(f *Interface, queue tio.Queue, i int) {
	if f.pinThreads {
		f.pinThisThread(i)
	}

	rejectBuf := make([]byte, mtu)
	arenaSize := batch.SendBatchCap * (udp.MTU + 32)
	onWrite := func(queued, written int, err error) {
		f.accountSendBatch(queued, written, err, i)
	}
	p := batch.NewSendPipeline(f.writers[i], batch.SendBatchCap, arenaSize, udp.MaxWriteBatch, onWrite)
	defer p.Close()
	fwPacket := &firewall.ParsedPacket{}
	nb := make([]byte, 12, 12)

	conntrackCache := firewall.NewConntrackCacheTicker(f.ctx, f.l, f.conntrackCacheTimeout)

	for {
		pkts, err := queue.Read()
		if err != nil {
			// Same shutdown noise handling as listenOut
			if !f.closed.Load() && f.ctx.Err() == nil {
				f.l.Error("Error while reading outbound packet, closing", "error", err, "reader", i)
				f.onFatal(err)
			}
			break
		}

		for j, pkt := range pkts {
			// One Begin/End per packet holds the batch only briefly, so a sender that finishes a write mid-read
			// takes what is ready then. An idle sender is woken once, at the end of the read, to take it whole.
			sb := p.Begin()
			f.consumeInsidePacket(pkt, fwPacket, nb, sb, rejectBuf, i, conntrackCache.Get())
			p.End(j == len(pkts)-1)
		}
	}

	f.l.Debug("overlay reader is done", "reader", i)
}
