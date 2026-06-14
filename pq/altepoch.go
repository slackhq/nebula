package pq

import (
	"sync"
	"time"
)

// AltEpochHint remembers, per peer, that we recently answered an
// IXPSK2 msg1 with our CURRENT-epoch PSK. If the same peer sends a
// fresh msg1 shortly afterwards, the strong inference is that the
// initiator rejected our msg2 (it holds a different epoch) — so the
// responder should try its PREVIOUS epoch once. This is the
// responder half of epoch-skew healing; the initiator half is the
// same-packet SwapPSK retry. Never suggests downgrading to IXPSK0.
// An attacker replaying a captured msg1 can burn a peer's one suggestion
// per episode, suppressing this optimisation for that cycle — the
// initiator-side SwapPSK retry still heals, so the cost is one extra
// round-trip, never a failure or downgrade.
type AltEpochHint struct {
	mu sync.Mutex
	m  map[string]altEpochEntry
}

type altEpochEntry struct {
	lastMsg2  time.Time
	usedPrev  bool
	suggested bool
}

const (
	altEpochCap    = 512
	altEpochExpiry = 60 * time.Second
	// altEpochWindow is how soon after a current-epoch msg2 a fresh
	// msg1 from the same peer is read as "initiator rejected our
	// msg2". Outside the window a new msg1 is just a new handshake.
	altEpochWindow = 30 * time.Second
)

func NewAltEpochHint() *AltEpochHint {
	return &AltEpochHint{m: make(map[string]altEpochEntry)}
}

// ChoosePrev reports whether the responder should prefer its
// previous-epoch PSK for a fresh msg1 from this peer, firing at most
// once per noted msg2.
func (c *AltEpochHint) ChoosePrev(peerKey string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[peerKey]
	if !ok || e.usedPrev || e.suggested {
		return false
	}
	if now.Sub(e.lastMsg2) > altEpochWindow {
		return false
	}
	e.suggested = true
	c.m[peerKey] = e
	return true
}

// NoteMsg2 records that a msg2 was sent to the peer and which epoch
// was mixed into it.
func (c *AltEpochHint) NoteMsg2(peerKey string, now time.Time, usedPrev bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= altEpochCap {
		// Evict expired first; if nothing expired, drop an arbitrary
		// entry — diagnostics-grade bound, not a correctness surface.
		evicted := false
		for k, e := range c.m {
			if now.Sub(e.lastMsg2) > altEpochExpiry {
				delete(c.m, k)
				evicted = true
			}
		}
		if !evicted {
			for k := range c.m {
				delete(c.m, k)
				break
			}
		}
	}
	c.m[peerKey] = altEpochEntry{lastMsg2: now, usedPrev: usedPrev}
}

// Clear drops the peer's entry (tunnel established — episode over).
func (c *AltEpochHint) Clear(peerKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, peerKey)
}

// len is exposed for tests.
func (c *AltEpochHint) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
