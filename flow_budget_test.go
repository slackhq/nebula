package nebula

import (
	"fmt"
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/require"
)

var budgetWindows = []uint64{8192, 65536}

// TestTXBudgetOvertaking: a fast sender must not recycle credit around a stalled older reservation. A pure in-flight
// count passes the cap assertion but fails this replay test.
func TestTXBudgetOvertaking(t *testing.T) {
	for _, window := range budgetWindows {
		t.Run(fmt.Sprint(window), func(t *testing.T) {
			var b txBudget
			limit := window / 2
			w := NewBits(window)
			l := test.NewLogger()
			require.True(t, b.acquire(1, limit, 1)) // counter 1 stalls
			for counter := uint64(2); counter <= limit; counter++ {
				require.True(t, b.acquire(1, limit, 2))
				require.True(t, w.Update(l, counter))
				b.release(1, false)
			}
			require.Equal(t, uint64(1), b.state.Load()&txBudgetMask)
			require.False(t, b.acquire(1, limit, 2), "spent credit cannot be recycled while the oldest sender stalls")
			// The other half of the window allows this many unreserved sends.
			for counter := limit + 1; counter <= window; counter++ {
				require.True(t, w.Update(l, counter))
			}
			require.True(t, w.Update(l, 1), "oldest reservation must still fit after using the whole margin")
			b.release(1, false)
			require.Zero(t, b.state.Load())
			require.True(t, b.acquire(limit, limit, 2))
			require.False(t, b.acquire(1, limit, 2))
			b.release(limit, false)
		})
	}
}

// TestTXBudgetBlockedReader models eight 512-segment reads of a busy owner and a 568-segment waiter, without socket
// timing. Alone, the owner gets each completion refunded, so it keeps eight batches in flight forever, even across its
// own failed acquisitions. But even when the owner always retries first, its completions must stop refunding credit
// once the waiter is blocked, and let the budget drain. Waiter 0 is the conservative ID of readers beyond the owner
// field's range.
func TestTXBudgetBlockedReader(t *testing.T) {
	for _, waiter := range []uint64{1, 0} {
		t.Run(fmt.Sprintf("waiter=%d", waiter), func(t *testing.T) {
			var b txBudget
			const limit, n, want = uint64(4096), uint64(512), uint64(568)
			for range 8 {
				require.True(t, b.acquire(n, limit, 2))
			}
			for range 100 {
				require.False(t, b.acquire(n, limit, 2))
				b.release(n, false) // the sole sender flushes its oldest batch
				require.True(t, b.acquire(n, limit, 2))
				require.Equal(t, 8*n, b.state.Load()&txBudgetMask)
			}
			require.False(t, b.acquire(want, limit, waiter))
			for range 7 {
				b.release(n, false)
				require.False(t, b.acquire(n, limit, 2), "blocked reader must stop the owner's credit recycling")
				require.False(t, b.acquire(want, limit, waiter))
			}
			b.release(n, false)
			require.Zero(t, b.state.Load())
			// Even if the former owner wins the next acquisition, both now fit.
			require.True(t, b.acquire(n, limit, 2))
			require.True(t, b.acquire(want, limit, waiter))
			b.release(n, false)
			b.release(want, false)
			require.Zero(t, b.state.Load())
		})
	}
}

// TestTXBudgetRelayRollback: when a later tunnel of a batch cannot acquire, the earlier ones give their credit back,
// spent credit included.
func TestTXBudgetRelayRollback(t *testing.T) {
	for _, window := range budgetWindows {
		inner := &ConnectionState{window: NewBits(window)}
		outer := &ConnectionState{window: NewBits(window)}
		limit := inner.txBudgetLimit()
		require.True(t, inner.txBudget.acquire(10, limit, 1))
		require.True(t, outer.txBudget.acquire(limit, limit, 1))
		r := txReserver{owner: 2, tunnels: []txTunnel{{ci: inner, n: 20}, {ci: outer, n: 20}}}
		for range 100 {
			require.False(t, r.tryBudget())
			require.Equal(t, uint64(10), inner.txBudget.state.Load()&txBudgetMask)
			require.Equal(t, uint64(10), (inner.txBudget.state.Load()>>24)&txBudgetMask, "rollback must refund spent credit too")
		}
		outer.txBudget.release(limit, false)
		require.True(t, r.tryBudget())
		inner.txBudget.release(20, false)
		outer.txBudget.release(20, false)
		inner.txBudget.release(10, false)
		require.Zero(t, inner.txBudget.state.Load())
		require.Zero(t, outer.txBudget.state.Load())
	}
}
