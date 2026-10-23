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
	TTL          time.Duration // an entry idle this long is dropped

	// Quiet is how long a key drops every fragment once its message completes.
	Quiet time.Duration
}

// Table reassembles messages from senders that have not authenticated yet, the
// responder's view of msg1. Every resource is capped. When a cap is hit a
// random entry is evicted; random eviction is harder to aim than LRU, which a
// flood can use to flush specific entries.
//
// K identifies one message, typically the source plus FragID. S identifies the
// source for quotas, typically the address masked to /32 or /64.
//
// Once a message completes its key goes quiet: every fragment for it is dropped
// for the Quiet period. That takes care of the repair fragments trailing an
// attempt whose data fragments already completed the message, which would
// otherwise complete it again or, for K above the repair count, open an entry
// that never completes and holds a source's quota until it expires. A retry
// comes after the quiet period and is reassembled like the first attempt; a
// straggler that comes after it opens an entry the retry completes. Keys include
// the path a message arrives by, so the same message arriving by two paths is
// two keys, each quiet on its own.
//
// A Table is safe for concurrent use.
type Table[K, S comparable] struct {
	mu        sync.Mutex
	cfg       TableConfig
	entries   map[K]*tableEntry[K, S]
	order     []K
	perSource map[S]int
	bytes     int
	quiet     map[K]time.Time // when each quiet key takes fragments again
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
		quiet:     make(map[K]time.Time),
	}
}

// Result describes a completed message.
type Result struct {
	Packet   []byte // header.Len bytes for the caller's Nebula header, then the message
	Received int    // packet bytes received for it, for the amplification budget
}

// Add records a fragment parsed by Parse. When the message is complete its entry
// is removed, its key goes quiet and the result is returned; otherwise the result
// is nil, as it is for a fragment dropped because its key is quiet. A decode
// error means the message is lost and must be retransmitted.
func (t *Table[K, S]) Add(key K, source S, now time.Time, h Header, sym []byte) (*Result, error) {
	t.mu.Lock()
	if until, ok := t.quiet[key]; ok {
		if now.Before(until) {
			t.mu.Unlock()
			return nil, nil
		}
		delete(t.quiet, key)
	}

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
	t.quietKey(key, now)
	t.mu.Unlock()

	pkt, err := e.a.Decode(make([]byte, header.Len))
	if err != nil {
		return nil, err
	}
	return &Result{Packet: pkt, Received: e.a.Received()}, nil
}

// quietKey makes key drop fragments for the Quiet period. At most MaxEntries keys
// are quiet at once, outside the entry, byte and source caps.
func (t *Table[K, S]) quietKey(key K, now time.Time) {
	if t.cfg.Quiet <= 0 {
		return
	}
	if _, ok := t.quiet[key]; !ok && len(t.quiet) >= t.cfg.MaxEntries {
		for k := range t.quiet {
			delete(t.quiet, k)
			break
		}
	}
	t.quiet[key] = now.Add(t.cfg.Quiet)
}

// Reopen ends key's quiet period, so its fragments are reassembled again at once.
func (t *Table[K, S]) Reopen(key K) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.quiet, key)
}

// Expire drops every entry idle for longer than the TTL, and ends the quiet
// periods that are over.
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
	for key, until := range t.quiet {
		if !now.Before(until) {
			delete(t.quiet, key)
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
