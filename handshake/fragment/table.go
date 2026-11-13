package fragment

import (
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/slackhq/nebula/header"
)

var (
	ErrSourceQuota = errors.New("source has too many messages in progress")
	ErrNoRoom      = errors.New("no room for fragment")
)

// TableConfig bounds a Table.
type TableConfig struct {
	MaxBytes     int           // symbol bytes held across all entries
	MaxEntries   int           // messages in progress across all sources
	MaxPerSource int           // messages in progress per source
	TTL          time.Duration // an entry or repeat count idle this long is dropped
}

// Table reassembles messages from senders that have not authenticated yet, the
// responder's view of msg1. Every resource is capped. When a cap is hit a
// random entry is evicted; random eviction is harder to aim than LRU, which a
// flood can use to flush specific entries.
//
// K identifies one message, typically the source plus FragID. S identifies the
// source for quotas, typically the address masked to /32 or /64.
//
// A key is in one of three states:
//
//   - absent: nothing is held for it.
//   - assembling: Add is collecting its fragments, in entries. When the message
//     completes it is handed to the caller and the key is absent again.
//   - repeating: the caller recognised its fragments as a message it already
//     handled and counts them with Repeat, in repeats.
//
// Add takes a repeating key back to assembling, and Repeat takes an assembling
// one to repeating, so a key is never in both maps. Recognising a handled
// message is the caller's job: the table keeps nothing of a message once it
// completes. Keys include the path a message arrives by, so the same message
// arriving by two paths is two keys.
//
// A Table is safe for concurrent use.
type Table[K, S comparable] struct {
	mu        sync.Mutex
	cfg       TableConfig
	entries   map[K]*tableEntry[K, S]
	order     []K
	perSource map[S]int
	bytes     int
	repeats   map[K]repeat
}

// repeat counts the fragments of a handled message arriving by one path since
// it was last answered.
type repeat struct {
	fragments int
	received  int
	lastSeen  time.Time
}

type tableEntry[K, S comparable] struct {
	a        *Assembly
	source   S
	lastSeen time.Time
	pos      int
}

func NewTable[K, S comparable](cfg TableConfig) *Table[K, S] {
	return &Table[K, S]{
		cfg:       cfg,
		entries:   make(map[K]*tableEntry[K, S]),
		perSource: make(map[S]int),
		repeats:   make(map[K]repeat),
	}
}

// Result describes a completed message.
type Result struct {
	Packet   []byte // header.Len bytes for the caller's Nebula header, then the message
	Received int    // packet bytes received for it, for the amplification budget
}

// Add records a fragment parsed by Parse. When the message is complete its entry
// is removed and the result is returned; otherwise the result is nil. A decode
// error means the message is lost and must be retransmitted. A key that was
// repeating starts assembling again: its fragments no longer belong to a
// message the caller recognises.
func (t *Table[K, S]) Add(key K, source S, now time.Time, h Header, sym []byte) (*Result, error) {
	t.mu.Lock()
	delete(t.repeats, key)

	e, ok := t.entries[key]
	if ok && now.Sub(e.lastSeen) > t.cfg.TTL {
		t.remove(key, e)
		ok = false
	}
	if !ok {
		var err error
		e, err = t.insert(key, source, h)
		if err != nil {
			t.mu.Unlock()
			return nil, err
		}
	}
	e.lastSeen = now

	if !t.makeRoom(key, e.a.wouldStore(h, sym)) {
		if e.a.Stored() == 0 {
			t.remove(key, e)
		}
		t.mu.Unlock()
		return nil, ErrNoRoom
	}

	before := e.a.Stored()
	ready, err := e.a.Add(h, sym)
	t.bytes += e.a.Stored() - before
	if err != nil || !ready {
		if errors.Is(err, ErrMismatch) || (err != nil && e.a.Stored() == 0) {
			t.remove(key, e)
		}
		t.mu.Unlock()
		return nil, err
	}

	t.remove(key, e)
	t.mu.Unlock()

	pkt, err := e.a.Decode(make([]byte, header.Len))
	if err != nil {
		return nil, err
	}
	return &Result{Packet: pkt, Received: e.a.Received()}, nil
}

// Repeat counts a fragment of a message the caller already handled, n packet
// bytes arriving for key, which is repeating from now on. Every k of them, a
// whole copy's worth, it returns true and the bytes received since the last
// time, for the caller to answer the copy. A key that was assembling carries
// what its entry held into the count: those fragments were part of the copy.
//
// Counts live outside the entry, byte and source caps, at most MaxEntries of
// them. One dropped, idle for the TTL or evicted to make room, starts again at
// zero, which never holds back the answer to a copy of k fragments.
func (t *Table[K, S]) Repeat(key K, now time.Time, n, k int) (received int, answer bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	r, ok := t.repeats[key]
	if !ok {
		if e, ok := t.entries[key]; ok {
			r.fragments = e.a.dec.Stored()
			r.received = e.a.Received()
			t.remove(key, e)
		}
		if len(t.repeats) >= t.cfg.MaxEntries {
			for old := range t.repeats {
				delete(t.repeats, old)
				break
			}
		}
	}
	r.fragments++
	r.received += n
	r.lastSeen = now
	if r.fragments < k {
		t.repeats[key] = r
		return 0, false
	}
	t.repeats[key] = repeat{lastSeen: now}
	return r.received, true
}

// Expire drops every entry and repeat count idle for longer than the TTL.
func (t *Table[K, S]) Expire(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := 0; i < len(t.order); {
		key := t.order[i]
		e := t.entries[key]
		if now.Sub(e.lastSeen) > t.cfg.TTL {
			// remove swaps the last entry into position i, so look at i again.
			t.remove(key, e)
			continue
		}
		i++
	}
	for key, r := range t.repeats {
		if now.Sub(r.lastSeen) > t.cfg.TTL {
			delete(t.repeats, key)
		}
	}
}

// Len returns the number of messages in progress.
func (t *Table[K, S]) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// Load returns how full the table is, from 0 to 1, by whichever of its byte and
// entry limits is closer.
func (t *Table[K, S]) Load() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return max(float64(t.bytes)/float64(t.cfg.MaxBytes), float64(len(t.entries))/float64(t.cfg.MaxEntries))
}

func (t *Table[K, S]) insert(key K, source S, h Header) (*tableEntry[K, S], error) {
	if t.perSource[source] >= t.cfg.MaxPerSource {
		return nil, ErrSourceQuota
	}
	a, err := NewAssembly(h)
	if err != nil {
		return nil, err
	}
	for len(t.entries) >= t.cfg.MaxEntries {
		if !t.evictRandom(nil) {
			return nil, ErrNoRoom
		}
	}

	e := &tableEntry[K, S]{a: a, source: source, pos: len(t.order)}
	t.entries[key] = e
	t.order = append(t.order, key)
	t.perSource[source]++
	return e, nil
}

// makeRoom evicts random entries other than keep until n more bytes fit.
func (t *Table[K, S]) makeRoom(keep K, n int) bool {
	for t.bytes+n > t.cfg.MaxBytes {
		if !t.evictRandom(&keep) {
			return false
		}
	}
	return true
}

func (t *Table[K, S]) evictRandom(keep *K) bool {
	candidates := len(t.order)
	if keep != nil {
		if _, ok := t.entries[*keep]; ok {
			candidates--
		}
	}
	if candidates <= 0 {
		return false
	}
	for {
		key := t.order[rand.IntN(len(t.order))]
		if keep != nil && key == *keep {
			continue
		}
		t.remove(key, t.entries[key])
		return true
	}
}

func (t *Table[K, S]) remove(key K, e *tableEntry[K, S]) {
	last := len(t.order) - 1
	moved := t.order[last]
	t.order[e.pos] = moved
	t.entries[moved].pos = e.pos
	t.order = t.order[:last]
	delete(t.entries, key)

	t.bytes -= e.a.Stored()
	if t.perSource[e.source] <= 1 {
		delete(t.perSource, e.source)
	} else {
		t.perSource[e.source]--
	}
}
