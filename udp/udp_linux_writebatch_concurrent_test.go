//go:build linux && !android && !e2e_testing

package udp

import (
	"net/netip"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// The TUN reader and relay forwarding share a socket. Exercise their concurrent
// batches against the actual GSO planner and scratch, without relying on a NIC.
func TestWriteBatchConcurrent(t *testing.T) {
	const batches = 64
	w := newRewindTestWriter()
	sent := make(chan [][]byte, 2*batches)
	w.sendFn = func(start, n int) (int, error) {
		runtime.Gosched()
		sent <- capturePrepared(w, start, n)
		return n, nil
	}
	conn := &StdConn{bw: w}
	remote := netip.MustParseAddrPort("192.0.2.1:4242")
	var wg sync.WaitGroup
	start := make(chan struct{})
	for producer := range 2 {
		wg.Go(func() {
			<-start
			for i := range batches {
				var bufs [][]byte
				var addrs []netip.AddrPort
				for j := range 4 {
					bufs = append(bufs, []byte{byte(producer), byte(i), byte(j), 0})
					addrs = append(addrs, remote)
				}
				n, err := conn.WriteBatch(bufs, addrs)
				if err != nil || n != len(bufs) {
					t.Errorf("WriteBatch = %d, %v; want %d, nil", n, err, len(bufs))
					return
				}
			}
		})
	}
	close(start)
	wg.Wait()
	close(sent)
	var counts [2]int
	for packets := range sent {
		require.Len(t, packets, 4)
		producer := packets[0][0]
		require.Less(t, int(producer), len(counts))
		for j, packet := range packets {
			require.Equal(t, []byte{producer, byte(counts[producer]), byte(j), 0}, packet)
		}
		counts[producer]++
	}
	require.Equal(t, [2]int{batches, batches}, counts)
}
