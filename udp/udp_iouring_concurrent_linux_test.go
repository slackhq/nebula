//go:build linux && !android && !e2e_testing && iouring

package udp

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIoUringConn_concurrent_WriteTo_race exercises the send ring from many
// goroutines at once. Without sendMu, concurrent GetSQE / Submit / WaitCQE
// calls would race on the ring's head/tail pointers and `go test -race`
// would detect the data race. With the mutex in place this passes cleanly.
//
// Gated by !testing.Short so `nix flake check` (which runs -short) doesn't
// try to open io_uring rings, and by IoUringAvailable so machines without
// the right kernel quietly skip.
func TestIoUringConn_concurrent_WriteTo_race(t *testing.T) {
	if testing.Short() {
		t.Skip("io_uring integration test; needs real kernel socket")
	}
	if !IoUringAvailable() {
		t.Skip("kernel does not support io_uring required ops")
	}

	l := slog.New(slog.DiscardHandler)

	// Sink: a plain UDP socket on a free port. We send everything to it,
	// drain it periodically so kernel rx buffers don't overflow, and don't
	// care about packet content — the test is about racing the sender.
	lc := &net.ListenConfig{}
	sink, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	sinkAddr := netip.MustParseAddrPort(sink.LocalAddr().String())

	opts := DefaultIoUringOptions()
	opts.Enabled = true

	conn, err := NewIoUringListener(l, netip.MustParseAddr("127.0.0.1"), 0, false, 64, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	// Background drain so the sink's rx buffer doesn't fill up and start
	// dropping. We don't assert on packet count — race detection is the
	// goal, not delivery.
	var drained atomic.Int64
	drainStop := make(chan struct{})
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		buf := make([]byte, 2048)
		for {
			select {
			case <-drainStop:
				return
			default:
			}
			_ = sink.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			_, _, rerr := sink.ReadFrom(buf)
			if rerr == nil {
				drained.Add(1)
			}
		}
	}()

	const goroutines = 8
	const perGoroutine = 1000
	payload := []byte("hello race detector — io_uring concurrent send")

	var wg sync.WaitGroup
	var firstErr atomic.Pointer[error]
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perGoroutine {
				if err := conn.WriteTo(payload, sinkAddr); err != nil {
					firstErr.CompareAndSwap(nil, &err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(drainStop)
	<-drainDone

	if e := firstErr.Load(); e != nil {
		t.Fatalf("concurrent WriteTo errored: %v", *e)
	}
	t.Logf("sent %d packets across %d goroutines; sink drained %d",
		goroutines*perGoroutine, goroutines, drained.Load())
}

// TestIoUringConn_concurrent_mixed_race mixes WriteTo and WriteBatch from
// different goroutines. WriteBatch grabs the send mutex per chunk and
// WriteTo grabs it for one packet; with the mutex these serialize
// correctly. Without it the CQE drain in WriteBatch could pick up a
// WriteTo's completion and free the wrong slot.
func TestIoUringConn_concurrent_mixed_race(t *testing.T) {
	if testing.Short() {
		t.Skip("io_uring integration test; needs real kernel socket")
	}
	if !IoUringAvailable() {
		t.Skip("kernel does not support io_uring required ops")
	}

	l := slog.New(slog.DiscardHandler)

	lc := &net.ListenConfig{}
	sink, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	sinkAddr := netip.MustParseAddrPort(sink.LocalAddr().String())

	opts := DefaultIoUringOptions()
	opts.Enabled = true

	conn, err := NewIoUringListener(l, netip.MustParseAddr("127.0.0.1"), 0, false, 64, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	// Drain in the background to keep kernel buffers happy.
	drainStop := make(chan struct{})
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		buf := make([]byte, 2048)
		for {
			select {
			case <-drainStop:
				return
			default:
			}
			_ = sink.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			_, _, _ = sink.ReadFrom(buf)
		}
	}()

	const writerGoroutines = 4
	const batcherGoroutines = 4
	const iterations = 250
	const batchSize = 16
	payload := []byte("mixed concurrent test payload")

	var wg sync.WaitGroup
	var firstErr atomic.Pointer[error]

	for range writerGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				if err := conn.WriteTo(payload, sinkAddr); err != nil {
					firstErr.CompareAndSwap(nil, &err)
					return
				}
			}
		}()
	}

	bufs := make([][]byte, batchSize)
	addrs := make([]netip.AddrPort, batchSize)
	for i := range bufs {
		bufs[i] = payload
		addrs[i] = sinkAddr
	}
	for range batcherGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localBufs := make([][]byte, batchSize)
			localAddrs := make([]netip.AddrPort, batchSize)
			copy(localBufs, bufs)
			copy(localAddrs, addrs)
			for range iterations {
				if err := conn.WriteBatch(localBufs, localAddrs, nil); err != nil {
					firstErr.CompareAndSwap(nil, &err)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(drainStop)
	<-drainDone

	if e := firstErr.Load(); e != nil {
		t.Fatalf("concurrent mixed send errored: %v", *e)
	}
}

// BenchmarkIoUringConn_concurrent_WriteTo_rings measures the per-op cost of
// WriteTo with G concurrent goroutines hitting a Conn sized with R send
// rings. The contention curve makes the value of io_uring_send_rings
// observable: with R=1 all G goroutines queue on a single mutex; with R=G
// they're effectively independent.
//
// Run with: go test -tags iouring -bench=BenchmarkIoUringConn_concurrent ./udp/
//
// Each sub-benchmark also serves as a smoke test under -race for that
// particular (rings, goroutines) configuration.
func BenchmarkIoUringConn_concurrent_WriteTo_rings(b *testing.B) {
	if !IoUringAvailable() {
		b.Skip("kernel does not support io_uring required ops")
	}
	l := slog.New(slog.DiscardHandler)

	for _, cfg := range []struct {
		name       string
		rings      int
		goroutines int
	}{
		{"R1_G1", 1, 1},
		{"R1_G4", 1, 4},
		{"R1_G8", 1, 8},
		{"R4_G4", 4, 4},
		{"R4_G8", 4, 8},
		{"R8_G8", 8, 8},
		{"R16_G16", 16, 16},
	} {
		b.Run(cfg.name, func(b *testing.B) {
			lc := &net.ListenConfig{}
			sink, err := lc.ListenPacket(b.Context(), "udp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = sink.Close() }()
			sinkAddr := netip.MustParseAddrPort(sink.LocalAddr().String())

			opts := DefaultIoUringOptions()
			opts.Enabled = true
			opts.SendRings = cfg.rings

			conn, err := NewIoUringListener(l, netip.MustParseAddr("127.0.0.1"), 0, false, 64, opts)
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = conn.Close() }()

			// Background sink drain so kernel rx buffers don't overflow.
			drainStop := make(chan struct{})
			drainDone := make(chan struct{})
			go func() {
				defer close(drainDone)
				buf := make([]byte, 2048)
				for {
					select {
					case <-drainStop:
						return
					default:
					}
					_ = sink.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					_, _, _ = sink.ReadFrom(buf)
				}
			}()
			defer func() {
				close(drainStop)
				<-drainDone
			}()

			payload := []byte("benchmark payload")
			b.ResetTimer()
			b.SetParallelism(cfg.goroutines)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := conn.WriteTo(payload, sinkAddr); err != nil {
						b.Errorf("WriteTo: %v", err)
						return
					}
				}
			})
		})
	}
}
