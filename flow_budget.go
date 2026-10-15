package nebula

import (
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/overlay/tio"
)

// txBudget is the reservation credit of one tunnel, shared by every staged reader sending on it. The low 24 bits of
// state are outstanding counters, the next 24 spent credit, and the top 16 the sole ordered reader (q+1); owner zero
// means shared. Readers beyond the owner field's range always take the conservative shared path.
//
// A cap on outstanding counters alone is not enough: a fast reader could repeatedly send and reacquire credit,
// overtaking a paused reader by arbitrarily far. So once readers overlap, or another reader is blocked, spent credit
// is only recycled when ALL reservations have drained. A sole reader instead gets each ordered completion refunded,
// its later batches cannot overtake its earlier ones. All transitions are one CAS, without locks.
//
// The credit is half the peer's replay window. The other half is left for uncredited sends and transport reordering:
// inline and control traffic, and relay forwarding through SendVia, which takes counters on the relay tunnel without
// credit. Unlimited bypass traffic or network delay can still exceed it. The window is not negotiated, so
// ci.window.length, from the build-time ReplayWindow, is also the assumed peer window.
type txBudget struct{ state atomic.Uint64 }

const txBudgetMask = uint64(1<<24 - 1)

// Fail compilation for unsupported build-time windows: a power of two, at least 8192, fitting the credit fields (up
// to 16777216).
const (
	_ = uint64(txBudgetMask) - ReplayWindow/2
	_ = uint64(ReplayWindow) - 8192
	_ = uint64(0) - (ReplayWindow & (ReplayWindow - 1))
)

func txBudgetOwner(q int) uint64 {
	if q < 0 || q >= 65535 {
		return 0
	}
	return uint64(q + 1)
}

func (b *txBudget) acquire(n, limit, owner uint64) bool {
	for {
		old := b.state.Load()
		pending, spent, who := old&txBudgetMask, (old>>24)&txBudgetMask, old>>48
		if n > limit || spent > limit-n {
			// A blocked reader ends sole ownership so ordered completions stop refunding credit. Otherwise a busy
			// owner could keep a larger waiter blocked forever without ever sharing a reservation.
			if who != 0 && who != owner && !b.state.CompareAndSwap(old, old&^(uint64(0xffff)<<48)) {
				continue
			}
			return false
		}
		if pending == 0 {
			who = owner
		} else if who != owner {
			who = 0
		}
		next := who<<48 | (spent+n)<<24 | (pending + n)
		if b.state.CompareAndSwap(old, next) {
			return true
		}
	}
}

// release runs only after the socket flush or an explicit drop. A rollback returns credit before any message counter
// was allocated, as when a later tunnel of a relay or multi-tunnel batch could not acquire its own.
func (b *txBudget) release(n uint64, rollback bool) {
	for {
		old := b.state.Load()
		pending, spent, owner := old&txBudgetMask, (old>>24)&txBudgetMask, old>>48
		pending -= n
		if rollback || owner != 0 {
			spent -= n
		}
		next := owner<<48 | spent<<24 | pending
		if pending == 0 {
			next = 0
		}
		if b.state.CompareAndSwap(old, next) {
			return
		}
	}
}

func (ci *ConnectionState) txBudgetLimit() uint64 { return ci.window.length / 2 }

func (r *txReserver) oversized() bool {
	for _, t := range r.tunnels {
		if t.n > t.ci.txBudgetLimit() {
			return true
		}
	}
	return false
}

func (r *txReserver) tryBudget() bool {
	for i, t := range r.tunnels {
		if !t.ci.txBudget.acquire(t.n, t.ci.txBudgetLimit(), r.owner) {
			for _, acquired := range r.tunnels[:i] {
				acquired.ci.txBudget.release(acquired.n, true)
			}
			return false
		}
	}
	return true
}

// waitBudget acquires credit for every tunnel of the batch, never holding a partial acquisition while it waits. Each
// reader first flushes its own oldest batch, flushes need no credit; with none, another reader holds all outstanding
// work and can flush it independently. So there is no circular wait, even with relay tunnels acquired in opposite
// orders. The sleep is only for readers with no local work, not the uncontended hot path. Acquisition is
// all-or-nothing per read, so pressure on one tunnel also delays packets for idle tunnels in the read; splitting
// would need separate slot ownership and coupled inner/relay reservations. Reader fairness is not guaranteed.
func (p *stagedTx) waitBudget() (time.Duration, bool) {
	if p.tryBudget() {
		return 0, true
	}
	t := time.Now()
	for {
		if p.f.closed.Load() {
			return time.Since(t), false
		}
		if !p.flushOldest() {
			time.Sleep(50 * time.Microsecond)
		}
		if p.tryBudget() {
			return time.Since(t), true
		}
	}
}

func (s *txSlot) releaseBudget() {
	for _, t := range s.reservations {
		t.ci.txBudget.release(t.n, false)
	}
	clear(s.reservations)
	s.reservations = s.reservations[:0]
}

// sendLarge handles the unusual reads that exceed a whole tunnel's credit, such as tiny-MSS superpackets. It drains
// the pipeline, then segments and sends them synchronously with credit for each segment, never exceeding the cap and
// never filtering or running connection manager side effects twice. This deliberately slow path avoids a lone-batch
// exception to the shared invariant.
func (p *stagedTx) sendLarge(items []txItem) time.Duration {
	t := time.Now()
	for p.flushOldest() {
	}
	stall := time.Since(t)
	for _, it := range items {
		err := tio.SegmentSuperpacket(it.pkt, func(seg []byte) error {
			if p.f.closed.Load() {
				return nil
			}
			part := it
			part.pkt, part.segs = tio.Packet{Bytes: seg}, 1
			p.tunnels = p.tunnels[:0]
			part.counter = p.need(part.hostinfo, part.ci, 1)
			if part.relayHI != nil {
				part.relayCounter = p.need(part.relayHI, part.relayHI.ConnectionState, 1)
			}
			d, ok := p.waitBudget()
			stall += d
			if !ok {
				return nil
			}
			one := [1]txItem{part}
			if reserved := p.reserve(one[:]); len(reserved) != 0 {
				p.f.encryptTxItem(&reserved[0], p.nb, p.sb)
				p.f.flushSendBatch(p.sb, p.q)
			}
			for _, t := range p.tunnels {
				t.ci.txBudget.release(t.n, false)
			}
			return nil
		})
		if err != nil {
			it.hostinfo.logger(p.f.l).Error("Failed to segment superpacket for send", "error", err)
		}
	}
	clear(items)
	return stall
}
