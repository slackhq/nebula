//go:build linux && !android && !e2e_testing

package udp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestShutdownWakesAfterRx_Mechanism exercises the kernel quirk our teardown
// relies on: once a socket has received a packet, shutdown(2) wakes a blocked
// recvmmsg with n>=1/Len==0 (not n==0). recvmmsg must turn that into net.ErrClosed
// once Close set closed, so a parked reader exits instead of spinning.
func TestShutdownWakesAfterRx_Mechanism(t *testing.T) {
	c, err := NewListener(testLogger(), netip.MustParseAddr("127.0.0.1"), 0, true, 64)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	sc := c.(*StdConn)
	addr, err := sc.LocalAddr()
	if err != nil {
		t.Fatalf("LocalAddr: %v", err)
	}
	msgs, _, _, _ := prepareRawMessages(sc.batch, 0xffff, 16)

	// Receive a real packet so the socket has carried data.
	send, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := send.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	n, err := sc.recvmmsg(msgs)
	t.Logf("drain of real packet: n=%d err=%v msgs[0].Len=%d", n, err, msgs[0].Len)
	_ = send.Close()

	// Block a reader on the now-empty queue, then tear down as Close() does.
	// recvmmsg must return net.ErrClosed (not hang, not spin) even post-rx.
	done := make(chan error, 1)
	go func() {
		_, err := sc.recvmmsg(msgs)
		done <- err
	}()
	time.Sleep(150 * time.Millisecond) // let it park in recvmmsg

	sc.closed.Store(true)
	if serr := unix.Shutdown(sc.sysFd, unix.SHUT_RDWR); serr != nil {
		t.Logf("shutdown returned %v (expected ENOTCONN on unconnected UDP)", serr)
	}

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("recvmmsg after post-rx shutdown returned %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("HANG: recvmmsg did not return after shutdown following a received packet")
	}
	_ = unix.Close(sc.sysFd)
}

// TestListenOutTeardown_TrafficPatterns reproduces the field report: a blocking
// reader must tear down cleanly on Close() regardless of what the socket has
// carried. The three cases the report called out:
//
//	no traffic ever      -> works (shutdown wakes recvmmsg with n==0)
//	ping once, then idle -> historically HUNG: once the socket has received a
//	                        packet, shutdown(2) wakes recvmmsg with n>=1/Len==0,
//	                        which an n==0-only teardown check misses
//	continuous traffic   -> works (a real packet is always arriving)
//
// All three must return within the deadline; a hang dumps goroutines so the
// stuck reader is visible.
func TestListenOutTeardown_TrafficPatterns(t *testing.T) {
	cases := []struct {
		name    string
		traffic func(send net.Conn, stop <-chan struct{})
	}{
		{"no_traffic_ever", func(net.Conn, <-chan struct{}) {}},
		{"ping_once_then_idle", func(send net.Conn, _ <-chan struct{}) {
			_, _ = send.Write([]byte("hello"))
		}},
		{"continuous", func(send net.Conn, stop <-chan struct{}) {
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = send.Write([]byte("hello"))
					time.Sleep(2 * time.Millisecond)
				}
			}
		}},
	}

	// batch 1 exercises single-message reads, batch 64 a full recvmmsg batch;
	// both must tear down cleanly.
	for _, batch := range []int{1, 64} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("batch%d/%s", batch, tc.name), func(t *testing.T) {
				runTeardownCase(t, batch, tc.name, tc.traffic)
			})
		}
	}
}

func runTeardownCase(t *testing.T, batch int, name string, traffic func(send net.Conn, stop <-chan struct{})) {
	c, err := NewListener(testLogger(), netip.MustParseAddr("127.0.0.1"), 0, true, batch)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	sc := c.(*StdConn)
	addr, err := sc.LocalAddr()
	if err != nil {
		t.Fatalf("LocalAddr: %v", err)
	}

	var received atomic.Int64
	loopDone := make(chan error, 1)
	go func() {
		loopDone <- sc.ListenOut(func(netip.AddrPort, []byte, RxMeta) {
			received.Add(1)
		}, func() {})
	}()

	send, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer send.Close()

	stop := make(chan struct{})
	trafficDone := make(chan struct{})
	go func() {
		traffic(send, stop)
		close(trafficDone)
	}()

	// Let the pattern run and, for the idle case, the reader park again on an
	// empty queue with the socket already having received a packet.
	time.Sleep(500 * time.Millisecond)

	start := time.Now()
	if err := sc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(stop)

	select {
	case err := <-loopDone:
		// Clean teardown surfaces as net.ErrClosed (propagated like the other
		// platforms); the caller absorbs it via its closed flag.
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("%s: ListenOut returned unexpected error on teardown: %v", name, err)
		}
		t.Logf("%s: closed in %v (received %d packets)", name, time.Since(start), received.Load())
	case <-time.After(3 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("%s: HANG, ListenOut did not return within 3s of Close\n%s", name, buf[:n])
	}
	<-trafficDone
}
