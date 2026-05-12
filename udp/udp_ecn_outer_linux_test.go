//go:build linux && !android && !e2e_testing

package udp

import (
	"net/netip"
	"testing"
)

// TestPlanRunBreaksOnECNChange confirms that two same-destination, same-size
// packets with different outer ECN end up in separate sendmmsg entries (the
// kernel stamps one outer codepoint per entry, so a run that straddled the
// boundary would silently lose information).
func TestPlanRunBreaksOnECNChange(t *testing.T) {
	u := &StdConn{gsoSupported: true, maxGSOSegments: 63}
	dst := netip.MustParseAddrPort("10.0.0.1:4242")

	bufs := [][]byte{
		make([]byte, 1200),
		make([]byte, 1200),
		make([]byte, 1200),
	}
	addrs := []netip.AddrPort{dst, dst, dst}

	t.Run("uniform_ecn_runs_together", func(t *testing.T) {
		ecns := []byte{0x02, 0x02, 0x02}
		runLen, segSize := u.planRun(bufs, addrs, ecns, 0, 64)
		if runLen != 3 {
			t.Errorf("runLen=%d want 3 (uniform ECT(0))", runLen)
		}
		if segSize != 1200 {
			t.Errorf("segSize=%d want 1200", segSize)
		}
	})

	t.Run("ecn_change_truncates_run", func(t *testing.T) {
		// 0,0,3: first two run together, CE seeds a fresh entry.
		ecns := []byte{0x00, 0x00, 0x03}
		runLen, _ := u.planRun(bufs, addrs, ecns, 0, 64)
		if runLen != 2 {
			t.Errorf("runLen=%d want 2 (ECN changes at index 2)", runLen)
		}
	})

	t.Run("nil_ecns_runs_full", func(t *testing.T) {
		runLen, _ := u.planRun(bufs, addrs, nil, 0, 64)
		if runLen != 3 {
			t.Errorf("runLen=%d want 3 (nil ecns means no break)", runLen)
		}
	})

	t.Run("first_ecn_is_singleton", func(t *testing.T) {
		// Second packet has different ECN from the first → run halts at 1
		// (the first packet alone forms the run).
		ecns := []byte{0x00, 0x03, 0x03}
		runLen, _ := u.planRun(bufs, addrs, ecns, 0, 64)
		if runLen != 1 {
			t.Errorf("runLen=%d want 1 (different ECN immediately)", runLen)
		}
	})
}
