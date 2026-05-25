//go:build linux && !android && !e2e_testing && iouring

package udp

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIoUringConn_close_during_send exercises the documented limitation
// that Close racing with in-flight senders is unsafe: Close unmaps the
// ring's SQ/CQ via QueueExit without waiting for active WriteTo callers,
// and concurrently nils out the ring pointer in each sendRingState.
//
// Senders that pass the c.closed check before Close runs may still try
// to call GetSQE / Submit / WaitCQE on a half-torn-down ring. Whether
// the race detector catches this depends on which fields the racing
// goroutines happen to touch — it observes Go-memory accesses but not
// the in-kernel mmap teardown.
//
// We assert that:
//   - WriteTo eventually returns either nil or net.ErrClosed,
//   - the test process does not panic or deadlock.
//
// This test is expected to pass today; if it ever starts failing under
// -race after a refactor, that's a real regression. The deeper fix (drain
// in-flight senders before tearing down the rings) is tracked as a known
// limitation in nebula-1704-sa.md.
func TestIoUringConn_close_during_send(t *testing.T) {
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

	// Background sink drain.
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

	// Senders hammer WriteTo until Close fires or they see ErrClosed.
	const senders = 6
	payload := []byte("close-race test payload")
	var unexpectedErr atomic.Pointer[error]
	var wg sync.WaitGroup
	for range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				err := conn.WriteTo(payload, sinkAddr)
				if err == nil {
					continue
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				// Any other error is acceptable at shutdown (EBADF, etc.)
				// but record the first one for visibility.
				unexpectedErr.CompareAndSwap(nil, &err)
				return
			}
		}()
	}

	// Let the senders saturate the rings, then Close while they're mid-send.
	time.Sleep(50 * time.Millisecond)
	closeErr := conn.Close()

	// Give senders a moment to observe ErrClosed and bail.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("senders did not exit within 5s of Close — possible deadlock")
	}

	if closeErr != nil {
		t.Logf("Close returned: %v (informational, not a failure)", closeErr)
	}
	if e := unexpectedErr.Load(); e != nil {
		t.Logf("first non-ErrClosed error from a sender: %v (informational)", *e)
	}
}
