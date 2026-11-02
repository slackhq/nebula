package nebula

import (
	"context"
	"log/slog"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/header"
)

// replayWindowGrowth is how much a replay window grows at once, and how far behind a packet may be to trigger it.
// Packets 1-4x the window behind are reordering, a multiport tunnel's packets cross every queue on both hosts.
const replayWindowGrowth = 4

var replayWindowGrown = metrics.GetOrRegisterCounter("network.replay_window.grown", nil)

// growReplayWindow grows the replay window when Check rejected counter c for arriving 1 to replayWindowGrowth
// windows behind, the packet is authentic, and the window is below replayWindowMax. It grows by replayWindowGrowth,
// capped at replayWindowMax, so the next packets that late are accepted.
//
// The packet itself is still dropped: once the window slid past c there is no record of whether c was already
// accepted, so it can't be told apart from a replay. Only an authentic packet grows the window, so forged counters
// can't, and a replayed one grows it at most to replayWindowMax.
func (cs *ConnectionState) growReplayWindow(l *slog.Logger, c uint64, packet, nb []byte) {
	if cs.replayWindowMax == 0 {
		return
	}

	cs.decryptLock.Lock()
	length, current := cs.window.length, cs.window.current
	cs.decryptLock.Unlock()
	if length >= cs.replayWindowMax || c > current || current-c < length || current-c > replayWindowGrowth*length {
		return
	}

	// Decrypts in place, the packet is dropped either way
	if _, err := cs.dKey.DecryptDanger(packet[header.Len:header.Len], packet[:header.Len], packet[header.Len:], c, nb); err != nil {
		return
	}

	newLength := min(length*replayWindowGrowth, cs.replayWindowMax)
	cs.decryptLock.Lock()
	grew := cs.window.length == length
	if grew {
		cs.window.grow(newLength)
	}
	cs.decryptLock.Unlock()

	if grew {
		replayWindowGrown.Inc(1)
		if l != nil && l.Enabled(context.Background(), slog.LevelDebug) {
			l.Debug("Grew the replay window for packets arriving out of order",
				"from", length, "to", newLength, "counter", c, "current", current)
		}
	}
}

// grow resizes the window to length, a larger power of two, keeping current. Counters the old window still covered
// keep their state. Everything older that the larger window now covers is marked seen: the old window already slid
// past it, so there is no record of whether those were accepted, and any already counted lost when it did.
func (b *Bits) grow(length uint64) {
	old := *b
	b.length = length
	b.lengthMask = length - 1
	b.bits = make([]uint64, max(length/bitsPerWord, 1))
	for i := range b.bits {
		b.bits[i] = ^uint64(0)
	}

	start := uint64(0)
	if old.current >= old.length {
		start = old.current - old.length + 1
	}
	for c := start; c <= old.current; c++ {
		if !old.get(c) {
			pos := c & b.lengthMask
			b.bits[pos>>6] &^= uint64(1) << (pos & 63)
		}
	}
}
