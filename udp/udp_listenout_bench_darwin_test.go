//go:build !e2e_testing

package udp

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

// BenchmarkListenOut measures the receive path on loopback: senders flood datagrams sized like a full tunnel
// packet, and each op is one datagram delivered to the reader. There are enough senders that the reader, not the
// senders, sets the pace. flushes/pkt is 1 when every receive is its own syscall and falls as receives batch. The
// senders share the machine, so ns/op is only comparable between runs on the same host.
func BenchmarkListenOut(b *testing.B) {
	for _, tc := range []struct{ name, listen string }{
		{"v4", "127.0.0.1"},
		{"v6", "::1"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			c, err := NewListener(slog.New(slog.DiscardHandler), Settings{Listen: netip.AddrPortFrom(netip.MustParseAddr(tc.listen), 0)})
			if err != nil {
				b.Fatal(err)
			}
			la, err := c.LocalAddr()
			if err != nil {
				b.Fatal(err)
			}
			const size, senders = 1300, 4
			txs := make([]net.Conn, senders)
			for i := range txs {
				if txs[i], err = net.Dial("udp", la.String()); err != nil {
					b.Fatal(err)
				}
				defer txs[i].Close()
			}

			target := int64(b.N)
			var got, flushes atomic.Int64
			reached := make(chan struct{})
			done := make(chan struct{})
			go func() {
				_ = c.ListenOut(func(netip.AddrPort, []byte) {
					if got.Add(1) == target {
						close(reached)
					}
				}, func() { flushes.Add(1) })
				close(done)
			}()

			// Writes fail with ENOBUFS while the send queue is full; the flood only has to keep the receiver busy.
			stop := make(chan struct{})
			var sent sync.WaitGroup
			for _, tx := range txs {
				sent.Go(func() {
					payload := make([]byte, size)
					for {
						select {
						case <-stop:
							return
						default:
							_, _ = tx.Write(payload)
						}
					}
				})
			}

			b.SetBytes(size)
			b.ResetTimer()
			<-reached
			b.StopTimer()

			close(stop)
			sent.Wait()
			if err := c.Close(); err != nil {
				b.Fatal(err)
			}
			<-done
			b.ReportMetric(float64(flushes.Load())/float64(got.Load()), "flushes/pkt")
		})
	}
}
