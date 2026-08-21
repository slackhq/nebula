//go:build linux && !android && !e2e_testing

package udp

import (
	"net/netip"
	"testing"
)

// TestWriteBatchNoAllocs verifies the sendmmsg/UDP-GSO transmit path performs
// no per-packet heap allocations on the happy path: all mmsghdr/iovec/cmsg
// scratch is preallocated in newBatchWriter and WriteBatch may only rewrite
// it. The batch deliberately mixes a GSO-eligible run, a short tail segment,
// destination changes, so the planner, sockaddr,
// and cmsg paths are all exercised.
func TestWriteBatchNoAllocs(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
	}{
		{"v4", "127.0.0.1"},
		{"v6", "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tc.addr)
			newConn := func() Conn {
				udpSettings := Settings{
					Listen:   netip.AddrPortFrom(ip, 0),
					Multi:    false,
					Batch:    8,
					Offloads: true,
				}
				c, err := NewListener(testLogger(), udpSettings)
				if err != nil {
					t.Fatalf("NewListener: %v", err)
				}
				t.Cleanup(func() { _ = c.Close() })
				return c
			}
			tx := newConn()
			rxA := newConn()
			rxB := newConn()
			if sc, ok := tx.(*StdConn); ok {
				// Records which planner path the measurement covered; GSO
				// support depends on the running kernel.
				t.Logf("gsoSupported=%v maxGSOSegments=%d", sc.bw.gsoSupported, sc.bw.maxGSOSegments)
			}
			dstA, err := rxA.LocalAddr()
			if err != nil {
				t.Fatalf("LocalAddr: %v", err)
			}
			dstB, err := rxB.LocalAddr()
			if err != nil {
				t.Fatalf("LocalAddr: %v", err)
			}

			payload := make([]byte, 1200)
			short := make([]byte, 900)

			var bufs [][]byte
			var addrs []netip.AddrPort
			add := func(b []byte, dst netip.AddrPort) {
				bufs = append(bufs, b)
				addrs = append(addrs, dst)
			}
			// GSO-eligible run with a short tail.
			for k := 0; k < 8; k++ {
				add(payload, dstA)
			}
			add(short, dstA)
			add(payload, dstA)
			// Alternating destinations defeat coalescing entirely.
			for k := 0; k < 4; k++ {
				dst := dstA
				if k%2 == 0 {
					dst = dstB
				}
				add(payload, dst)
			}

			var werr error
			// Warm-up outside the measured runs.
			if _, err := tx.WriteBatch(bufs, addrs); err != nil {
				t.Fatalf("WriteBatch warm-up: %v", err)
			}
			allocs := testing.AllocsPerRun(100, func() {
				if _, err := tx.WriteBatch(bufs, addrs); err != nil {
					werr = err
				}
			})
			if werr != nil {
				t.Fatalf("WriteBatch: %v", werr)
			}
			if allocs != 0 {
				t.Fatalf("WriteBatch allocated %.1f times per call, want 0", allocs)
			}
		})
	}
}
