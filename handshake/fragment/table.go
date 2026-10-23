package fragment

import (
	"crypto/sha256"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/slackhq/nebula/handshake/fec"
	"github.com/slackhq/nebula/header"
)

var (
	ErrTooLarge    = errors.New("fragmented message exceeds the size limit")
	ErrSourceQuota = errors.New("source has too many messages in progress")
	ErrNoRoom      = errors.New("no room for fragment")
)

// TableConfig bounds a Table.
type TableConfig struct {
	MaxBytes     int           // symbol bytes held across all entries
	MaxEntries   int           // messages in progress across all sources
	MaxPerSource int           // messages in progress per source
	MaxMsgLen    int           // largest message accepted
	TTL          time.Duration // an entry idle this long is dropped

	// RepeatInterval is how often, at most, an answered message is reported as a
	// repeat on one key. Zero reports every K fresh symbols.
	RepeatInterval time.Duration
}

// Table reassembles messages from senders that have not authenticated yet, the
// responder's view of msg1. Every resource is capped. When a cap is hit a
// random entry is evicted; random eviction is harder to aim than LRU, which a
// flood can use to flush specific entries.
//
// K identifies one message, typically the source plus FragID. S identifies the
// source for quotas, typically the address masked to /32 or /64.
//
// A message the caller answered is remembered, see Answered, so the fragments
// still arriving for it do not start it over. Without that, the repair
// fragments trailing a message whose data fragments already completed it would
// open a new entry that, for K above the repair count, never completes: it holds
// symbols and a source's quota until it expires. A retry of an answered message
// is reported as a repeat, at most once per RepeatInterval on that key. Keys
// include the path a message arrives by, so the same message arriving by two
// paths is two keys with two clocks.
//
// A Table is safe for concurrent use.
type Table[K, S comparable] struct {
	mu        sync.Mutex
	cfg       TableConfig
	entries   map[K]*tableEntry[K, S]
	order     []K
	perSource map[S]int
	bytes     int
	answered  map[K]*answeredEntry
}

// answeredEntry is what is kept of an answered message: no symbols, only which
// indexes have been seen, so a retry's fresh symbols can be told apart from
// stragglers of an attempt already decoded.
type answeredEntry struct {
	hash       [sha256.Size]byte
	msgLen     uint16
	k          int
	seen       [fec.MaxSymbols]bool
	fresh      int
	received   int
	lastSeen   time.Time
	lastRepeat time.Time // when it was answered, or last reported as a repeat
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
		answered:  make(map[K]*answeredEntry),
	}
}

// Result describes a completed message.
type Result struct {
	Msg      []byte            // the decoded message, nil for a repeat
	Packet   []byte            // header.Len bytes for the caller's Nebula header, then Msg
	Hash     [sha256.Size]byte // sha256 of the message
	Received int               // packet bytes received for it, for the amplification budget

	// Repeat means a message marked Answered was sent again: as many fresh
	// symbols as it has data symbols arrived, which a retry offers and stragglers
	// of an attempt already decoded do not.
	Repeat bool

	msgLen uint16
	k      int
	seen   [fec.MaxSymbols]bool
}

// Add records a fragment parsed by Parse. When the message is complete its entry
// is removed and the result returned; otherwise the result is nil. A decode
// error means the message is lost and must be retransmitted.
func (t *Table[K, S]) Add(key K, source S, now time.Time, h Header, sym []byte) (*Result, error) {
	if int(h.MsgLen) > t.cfg.MaxMsgLen {
		return nil, ErrTooLarge
	}

	t.mu.Lock()
	if a, ok := t.answered[key]; ok {
		if now.Sub(a.lastSeen) <= t.cfg.TTL {
			res := a.add(now, h, sym, t.cfg.RepeatInterval)
			t.mu.Unlock()
			return res, nil
		}
		delete(t.answered, key)
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
	t.mu.Unlock()

	pkt, err := e.a.Decode(make([]byte, header.Len))
	if err != nil {
		return nil, err
	}
	msg := pkt[header.Len:]
	return &Result{
		Msg:      msg,
		Packet:   pkt,
		Hash:     sha256.Sum256(msg),
		Received: e.a.Received(),
		msgLen:   e.a.msgLen,
		k:        e.a.dec.Layout().K,
		seen:     e.a.dec.Seen(),
	}, nil
}

func (a *answeredEntry) add(now time.Time, h Header, sym []byte, interval time.Duration) *Result {
	if h.MsgLen != a.msgLen {
		return nil
	}
	a.lastSeen = now
	a.received += header.Len + HeaderLen + len(sym)
	if a.seen[h.Index] {
		return nil
	}
	a.seen[h.Index] = true
	a.fresh++
	if a.fresh < a.k || now.Sub(a.lastRepeat) < interval {
		// Not enough fresh symbols yet, or this key was answered within the
		// interval. The fresh symbols keep counting, so the first one to arrive
		// once the interval is up reports the repeat.
		return nil
	}
	r := &Result{Hash: a.hash, Received: a.received, Repeat: true}
	a.fresh = 0
	a.received = 0
	a.lastRepeat = now
	return r
}

// Answered records that the caller answered res, the result of Add for key, so
// later fragments of it are counted rather than reassembled. A message is kept
// for the TTL after its last fragment, outside the entry, byte and source caps;
// at most MaxEntries are kept.
func (t *Table[K, S]) Answered(key K, res *Result, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// A straggler may have opened an entry while the caller worked.
	if e, ok := t.entries[key]; ok {
		t.remove(key, e)
	}
	if res.Repeat {
		return
	}
	if _, ok := t.answered[key]; !ok && len(t.answered) >= t.cfg.MaxEntries {
		for k := range t.answered {
			delete(t.answered, k)
			break
		}
	}
	t.answered[key] = &answeredEntry{hash: res.Hash, msgLen: res.msgLen, k: res.k, seen: res.seen, lastSeen: now, lastRepeat: now}
}

// Forget drops what Answered recorded for key, so its fragments are reassembled
// again.
func (t *Table[K, S]) Forget(key K) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.answered, key)
}

// Expire drops every entry idle for longer than the TTL.
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
	for key, a := range t.answered {
		if now.Sub(a.lastSeen) > t.cfg.TTL {
			delete(t.answered, key)
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

// Bytes returns the number of symbol bytes held.
func (t *Table[K, S]) Bytes() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bytes
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
