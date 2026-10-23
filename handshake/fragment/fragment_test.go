package fragment

import (
	"bytes"
	"crypto/sha256"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSubtype = header.MessageSubType(9)

type testKey struct {
	src    string
	fragID uint32
}

func randMsg(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func testConfig() TableConfig {
	return TableConfig{
		MaxBytes:     1 << 20,
		MaxEntries:   64,
		MaxPerSource: 4,
		MaxMsgLen:    16384,
		TTL:          2 * time.Second,
	}
}

// checkInvariants verifies the table's bookkeeping against its contents.
func checkInvariants[K, S comparable](t *testing.T, tb *Table[K, S]) {
	t.Helper()
	tb.mu.Lock()
	defer tb.mu.Unlock()

	require.Len(t, tb.order, len(tb.entries))
	require.LessOrEqual(t, len(tb.entries), tb.cfg.MaxEntries)
	bytes := 0
	perSource := map[S]int{}
	for i, key := range tb.order {
		e, ok := tb.entries[key]
		require.True(t, ok)
		require.Equal(t, i, e.pos)
		bytes += e.a.Stored()
		perSource[e.source]++
	}
	require.Equal(t, bytes, tb.bytes)
	require.LessOrEqual(t, tb.bytes, tb.cfg.MaxBytes)
	require.Equal(t, perSource, tb.perSource)
	for _, n := range perSource {
		require.LessOrEqual(t, n, tb.cfg.MaxPerSource)
	}
}

func parse(t *testing.T, p []byte) (header.H, Header, []byte) {
	t.Helper()
	var nh header.H
	require.NoError(t, nh.Parse(p))
	h, sym, err := Parse(p[header.Len:])
	require.NoError(t, err)
	return nh, h, sym
}

func TestParse(t *testing.T) {
	h := Header{FragID: 0xdeadbeef, MsgLen: 3000, Index: 7}
	b := h.Encode(nil)
	require.Len(t, b, HeaderLen)
	b = append(b, make([]byte, 1000)...)

	got, sym, err := Parse(b)
	require.NoError(t, err)
	assert.Equal(t, h, got)
	assert.Len(t, sym, 1000)

	_, _, err = Parse(b[:HeaderLen-1])
	require.ErrorIs(t, err, ErrShortFragment)
	_, _, err = Parse(b[:len(b)-1])
	require.ErrorIs(t, err, ErrSymbolSize)
	_, _, err = Parse(append(b, 0))
	require.ErrorIs(t, err, ErrSymbolSize)

	bad := Header{FragID: 0, MsgLen: 3000}.Encode(nil)
	_, _, err = Parse(append(bad, make([]byte, 1000)...))
	require.ErrorIs(t, err, ErrFragID)

	bad = Header{FragID: 1, MsgLen: 0}.Encode(nil)
	_, _, err = Parse(bad)
	require.ErrorIs(t, err, ErrMsgLen)

	bad = Header{FragID: 1, MsgLen: 3000, Flags: 0x02}.Encode(nil)
	_, _, err = Parse(append(bad, make([]byte, 1000)...))
	require.ErrorIs(t, err, ErrFlags)

	t.Run("cookie", func(t *testing.T) {
		h := Header{FragID: 7, MsgLen: 3000, Index: 4, Flags: FlagCookie}
		for i := range h.Cookie {
			h.Cookie[i] = byte(i + 1)
		}
		b := h.Encode(nil)
		require.Len(t, b, HeaderLen+CookieLen)
		b = append(b, make([]byte, 1000)...)

		got, sym, err := Parse(b)
		require.NoError(t, err)
		assert.Equal(t, h, got)
		assert.True(t, got.HasCookie())
		assert.Len(t, sym, 1000)

		_, _, err = Parse(b[:HeaderLen+CookieLen-1])
		require.ErrorIs(t, err, ErrNoCookie)
	})
}

func TestDefaultRepair(t *testing.T) {
	for k, want := range map[int]int{1: 2, 2: 2, 6: 2, 7: 3, 9: 3, 10: 4, 14: 5} {
		assert.Equal(t, want, DefaultRepair(k), "k=%d", k)
	}
}

func TestSender(t *testing.T) {
	_, err := NewSender(nil, testSubtype, 0, 1, 1)
	require.ErrorIs(t, err, ErrMsgLen)
	_, err = NewSender(make([]byte, 65536), testSubtype, 0, 1, 1)
	require.ErrorIs(t, err, ErrMsgLen)
	_, err = NewSender(make([]byte, 10), testSubtype, 0, 1, 0)
	require.ErrorIs(t, err, ErrFragID)

	msg := randMsg(rand.New(rand.NewPCG(1, 1)), 9800)
	s, err := NewSender(msg, testSubtype, 77, 2, 1234)
	require.NoError(t, err)
	require.Equal(t, 9, s.Layout().K)

	indexes := func(ps [][]byte) []int {
		var out []int
		for _, p := range ps {
			require.LessOrEqual(t, len(p), MaxPacketLen)
			nh, h, _ := parse(t, p)
			assert.Equal(t, header.Handshake, nh.Type)
			assert.Equal(t, testSubtype, nh.Subtype)
			assert.Equal(t, uint32(77), nh.RemoteIndex)
			assert.Equal(t, uint64(2), nh.MessageCounter)
			assert.Equal(t, uint32(1234), h.FragID)
			assert.Equal(t, uint16(9800), h.MsgLen)
			out = append(out, int(h.Index))
		}
		return out
	}

	now, later, err := s.Attempt(3)
	require.NoError(t, err)
	assert.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7, 8}, indexes(now))
	assert.Equal(t, []int{9, 10, 11}, indexes(later))

	// A retry offers only indexes the receiver has not seen.
	now, later, err = s.Attempt(3)
	require.NoError(t, err)
	assert.Equal(t, []int{12, 13, 14, 15, 16, 17, 18, 19, 20}, indexes(now))
	assert.Equal(t, []int{21, 22, 23}, indexes(later))

	// A sender rebuilt from the same message resumes where it was told to.
	s2, err := NewSender(msg, testSubtype, 77, 2, 1234)
	require.NoError(t, err)
	s2.SetNext(s.Next())
	now2, _, err := s2.Attempt(0)
	require.NoError(t, err)
	assert.Equal(t, []int{24, 25, 26, 27, 28, 29, 30, 31, 32}, indexes(now2))
	s2.SetNext(-1)
	assert.Equal(t, 255, s2.Next())

	// A cookie rides on every later packet, which still fits MaxPacketLen even
	// with a full size symbol.
	full, err := NewSender(make([]byte, 2*MaxSymbolSize), testSubtype, 0, 1, 9)
	require.NoError(t, err)
	full.SetCookie(Cookie{1, 2, 3})
	pkts, _, err := full.Attempt(1)
	require.NoError(t, err)
	for _, p := range pkts {
		assert.Len(t, p, MaxPacketLen)
		_, h, _ := parse(t, p)
		assert.True(t, h.HasCookie())
		assert.Equal(t, Cookie{1, 2, 3}, h.Cookie)
	}

	// Indexes wrap once the space is used up.
	for range 19 {
		_, _, err = s.Attempt(3)
		require.NoError(t, err)
	}
	now, _, err = s.Attempt(3)
	require.NoError(t, err)
	assert.Equal(t, []int{252, 253, 254, 255, 0, 1, 2, 3, 4}, indexes(now))
}

// TestLossy runs whole messages through heavy loss, reordering and duplication,
// merging across attempts, and checks the table ends empty.
func TestLossy(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 2))
	tb := NewTable[testKey, string](testConfig())
	now := time.Unix(1000, 0)

	for i := range 300 {
		msg := randMsg(r, 1+r.IntN(16384))
		fragID := uint32(i + 1)
		s, err := NewSender(msg, testSubtype, 0, 1, fragID)
		require.NoError(t, err)

		var got *Result
		for attempt := 0; got == nil; attempt++ {
			require.Less(t, attempt, 20, "message never completed")
			a, b, err := s.Attempt(DefaultRepair(s.Layout().K))
			require.NoError(t, err)
			var pkts [][]byte
			for _, p := range append(a, b...) {
				if r.Float64() < 0.3 {
					continue
				}
				pkts = append(pkts, p)
				if r.Float64() < 0.2 {
					pkts = append(pkts, p)
				}
			}
			r.Shuffle(len(pkts), func(i, j int) { pkts[i], pkts[j] = pkts[j], pkts[i] })

			for _, p := range pkts {
				_, h, sym := parse(t, p)
				res, err := tb.Add(testKey{"a", h.FragID}, "a", now, h, sym)
				require.NoError(t, err)
				if res != nil {
					// The table keeps no memory of completed messages, so a late
					// duplicate can complete one again; the handshake layer
					// recognises the repeat.
					require.True(t, bytes.Equal(msg, res.Msg))
					require.Len(t, res.Packet, header.Len+len(msg))
					require.Equal(t, &res.Packet[header.Len], &res.Msg[0], "Msg follows room for a header")
					got = res
				}
				checkInvariants(t, tb)
			}
			now = now.Add(100 * time.Millisecond)
		}
		require.Positive(t, got.Received)
		// Late fragments of a completed message start a fresh entry; drop it.
		tb.Expire(now.Add(time.Hour))
	}
	assert.Zero(t, tb.Len())
	assert.Zero(t, tb.Bytes())
}

// TestConcurrent spreads each message's fragments across goroutines, as
// multiple UDP reader routines would.
func TestConcurrent(t *testing.T) {
	tb := NewTable[testKey, string](testConfig())
	now := time.Unix(1000, 0)
	r := rand.New(rand.NewPCG(3, 3))

	const msgs = 50
	want := make(map[uint32][]byte, msgs)
	var pkts [][]byte
	for id := uint32(1); id <= msgs; id++ {
		msg := randMsg(r, 1+r.IntN(16384))
		want[id] = msg
		s, err := NewSender(msg, testSubtype, 0, 1, id)
		require.NoError(t, err)
		a, b, err := s.Attempt(DefaultRepair(s.Layout().K))
		require.NoError(t, err)
		pkts = append(pkts, a...)
		pkts = append(pkts, b...)
	}
	r.Shuffle(len(pkts), func(i, j int) { pkts[i], pkts[j] = pkts[j], pkts[i] })

	var mu sync.Mutex
	done := map[uint32]bool{}
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Go(func() {
			for i := w; i < len(pkts); i += 8 {
				h, sym, err := Parse(pkts[i][16:])
				if err != nil {
					t.Error(err)
					return
				}
				src := string(rune('a' + h.FragID))
				res, err := tb.Add(testKey{src, h.FragID}, src, now, h, sym)
				if err != nil {
					t.Error(err)
					return
				}
				if res != nil {
					if !bytes.Equal(want[h.FragID], res.Msg) {
						t.Errorf("message %d decoded wrong", h.FragID)
					}
					mu.Lock()
					done[h.FragID] = true
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	assert.Len(t, done, msgs)
	checkInvariants(t, tb)
}

func firstFragment(t *testing.T, msgLen int, fragID uint32) (Header, []byte) {
	t.Helper()
	s, err := NewSender(make([]byte, msgLen), testSubtype, 0, 1, fragID)
	require.NoError(t, err)
	now, _, err := s.Attempt(0)
	require.NoError(t, err)
	_, h, sym := parse(t, now[0])
	return h, sym
}

func TestTableLimits(t *testing.T) {
	now := time.Unix(1000, 0)

	t.Run("max message length", func(t *testing.T) {
		tb := NewTable[testKey, string](testConfig())
		h, sym := firstFragment(t, 16385, 1)
		_, err := tb.Add(testKey{"a", 1}, "a", now, h, sym)
		require.ErrorIs(t, err, ErrTooLarge)
		assert.Zero(t, tb.Len())
	})

	t.Run("per source quota", func(t *testing.T) {
		cfg := testConfig()
		cfg.MaxPerSource = 2
		tb := NewTable[testKey, string](cfg)
		for id := uint32(1); id <= 3; id++ {
			h, sym := firstFragment(t, 5000, id)
			_, err := tb.Add(testKey{"a", id}, "a", now, h, sym)
			if id <= 2 {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrSourceQuota)
			}
		}
		h, sym := firstFragment(t, 5000, 4)
		_, err := tb.Add(testKey{"b", 4}, "b", now, h, sym)
		require.NoError(t, err)
		assert.Equal(t, 3, tb.Len())
		checkInvariants(t, tb)
	})

	t.Run("max entries evicts", func(t *testing.T) {
		cfg := testConfig()
		cfg.MaxEntries = 4
		tb := NewTable[testKey, string](cfg)
		for id := uint32(1); id <= 10; id++ {
			h, sym := firstFragment(t, 5000, id)
			src := string(rune('a' + id))
			_, err := tb.Add(testKey{src, id}, src, now, h, sym)
			require.NoError(t, err)
			checkInvariants(t, tb)
		}
		assert.Equal(t, 4, tb.Len())
	})

	t.Run("max bytes evicts others", func(t *testing.T) {
		cfg := testConfig()
		cfg.MaxBytes = 3 * 1000
		tb := NewTable[testKey, string](cfg)
		for id := uint32(1); id <= 10; id++ {
			h, sym := firstFragment(t, 5000, id) // 5 symbols of 1000
			src := string(rune('a' + id))
			_, err := tb.Add(testKey{src, id}, src, now, h, sym)
			require.NoError(t, err)
			checkInvariants(t, tb)
		}
		assert.Equal(t, 3000, tb.Bytes())
	})

	t.Run("no room removes new entry", func(t *testing.T) {
		cfg := testConfig()
		cfg.MaxBytes = 500
		tb := NewTable[testKey, string](cfg)
		h, sym := firstFragment(t, 5000, 1)
		_, err := tb.Add(testKey{"a", 1}, "a", now, h, sym)
		require.ErrorIs(t, err, ErrNoRoom)
		assert.Zero(t, tb.Len())
		checkInvariants(t, tb)
	})

	t.Run("duplicates are not charged", func(t *testing.T) {
		tb := NewTable[testKey, string](testConfig())
		h, sym := firstFragment(t, 5000, 1)
		for range 5 {
			_, err := tb.Add(testKey{"a", 1}, "a", now, h, sym)
			require.NoError(t, err)
		}
		assert.Equal(t, 1000, tb.Bytes())
	})

	t.Run("mismatch drops the entry", func(t *testing.T) {
		tb := NewTable[testKey, string](testConfig())
		h, sym := firstFragment(t, 5000, 1)
		_, err := tb.Add(testKey{"a", 1}, "a", now, h, sym)
		require.NoError(t, err)

		h2, sym2 := firstFragment(t, 6000, 1)
		_, err = tb.Add(testKey{"a", 1}, "a", now, h2, sym2)
		require.ErrorIs(t, err, ErrMismatch)
		assert.Zero(t, tb.Len())
		assert.Zero(t, tb.Bytes())
		checkInvariants(t, tb)
	})

	t.Run("load", func(t *testing.T) {
		cfg := testConfig()
		cfg.MaxEntries = 4
		cfg.MaxBytes = 10000
		tb := NewTable[testKey, string](cfg)
		assert.Zero(t, tb.Load())
		h, sym := firstFragment(t, 5000, 1)
		_, err := tb.Add(testKey{"a", 1}, "a", now, h, sym)
		require.NoError(t, err)
		assert.InDelta(t, 0.25, tb.Load(), 0.001, "one of four entries")
		h, sym = firstFragment(t, 5000, 2)
		_, err = tb.Add(testKey{"b", 2}, "b", now, h, sym)
		require.NoError(t, err)
		assert.InDelta(t, 0.5, tb.Load(), 0.001)
	})

	t.Run("ttl", func(t *testing.T) {
		tb := NewTable[testKey, string](testConfig())
		s, err := NewSender(make([]byte, 5000), testSubtype, 0, 1, 1)
		require.NoError(t, err)
		pkts, _, err := s.Attempt(0)
		require.NoError(t, err)

		_, h, sym := parse(t, pkts[0])
		_, err = tb.Add(testKey{"a", 1}, "a", now, h, sym)
		require.NoError(t, err)

		// Activity within the TTL keeps the entry and slides its deadline.
		_, h, sym = parse(t, pkts[1])
		_, err = tb.Add(testKey{"a", 1}, "a", now.Add(1500*time.Millisecond), h, sym)
		require.NoError(t, err)
		assert.Equal(t, 2000, tb.Bytes())

		tb.Expire(now.Add(3 * time.Second))
		assert.Equal(t, 1, tb.Len())

		// A stale entry is restarted rather than merged.
		_, h, sym = parse(t, pkts[2])
		_, err = tb.Add(testKey{"a", 1}, "a", now.Add(10*time.Second), h, sym)
		require.NoError(t, err)
		assert.Equal(t, 1000, tb.Bytes())

		tb.Expire(now.Add(time.Minute))
		assert.Zero(t, tb.Len())
		checkInvariants(t, tb)
	})
}

func FuzzParse(f *testing.F) {
	f.Add(append(Header{FragID: 1, MsgLen: 3000}.Encode(nil), make([]byte, 1000)...))
	f.Add([]byte{0, 0, 0, 1, 0, 1, 0, 0, 7})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, sym, err := Parse(b)
		if err != nil {
			return
		}
		require.Equal(t, b, append(h.Encode(nil), sym...))
		l, err := h.Layout()
		require.NoError(t, err)
		require.LessOrEqual(t, l.SymbolSize, MaxSymbolSize)
	})
}

// FuzzTable drives a small table with arbitrary fragments and checks its
// bookkeeping after every step.
func FuzzTable(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	f.Fuzz(func(t *testing.T, ops []byte) {
		tb := NewTable[testKey, string](TableConfig{
			MaxBytes:     4000,
			MaxEntries:   3,
			MaxPerSource: 2,
			MaxMsgLen:    6000,
			TTL:          time.Second,
		})
		now := time.Unix(0, 0)
		for len(ops) >= 4 {
			src := string(rune('a' + ops[0]%4))
			fragID := uint32(ops[1]%5) + 1
			msgLen := uint16(ops[2])*32 + 1
			index := ops[3]
			ops = ops[4:]

			h := Header{FragID: fragID, MsgLen: msgLen, Index: index}
			l, err := h.Layout()
			require.NoError(t, err)
			sym := make([]byte, l.SymbolSize)
			if index%7 == 0 {
				now = now.Add(600 * time.Millisecond)
				tb.Expire(now)
			}
			res, err := tb.Add(testKey{src, fragID}, src, now, h, sym)
			if res != nil {
				require.NoError(t, err)
				require.Len(t, res.Msg, int(msgLen))
			}
			checkInvariants(t, tb)
		}
	})
}

// TestTableAnswered sends many large messages from one source the way a responder
// sees back to back handshakes: each attempt's data fragments complete the
// message and its repair fragments trail. Remembering answered messages keeps the
// stragglers from piling up against the source quota, and a retry with fresh
// symbols still reports the message again.
func TestTableAnswered(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 3))
	tb := NewTable[testKey, string](testConfig())
	now := time.Unix(1000, 0)
	const msgLen = 8009 // K=7 data symbols, 3 repair

	sendAll := func(key testKey, pkts [][]byte) []*Result {
		var out []*Result
		for _, p := range pkts {
			_, h, sym := parse(t, p)
			res, err := tb.Add(key, key.src, now, h, sym)
			require.NoError(t, err)
			if res != nil {
				out = append(out, res)
			}
			checkInvariants(t, tb)
		}
		return out
	}

	for i := range 3 * testConfig().MaxPerSource {
		msg := randMsg(r, msgLen)
		key := testKey{"a", uint32(i + 1)}
		s, err := NewSender(msg, testSubtype, 0, 1, key.fragID)
		require.NoError(t, err)
		data, repair, err := s.Attempt(DefaultRepair(s.Layout().K))
		require.NoError(t, err)
		require.Len(t, data, 7)
		require.Len(t, repair, 3)

		res := sendAll(key, data)
		require.Len(t, res, 1, "message %d was refused", i)
		require.Equal(t, msg, res[0].Msg)
		tb.Answered(key, res[0], now)

		assert.Empty(t, sendAll(key, repair), "stragglers are not a new message")
		assert.Zero(t, tb.Len(), "and hold no entry")
		now = now.Add(100 * time.Millisecond)
	}

	// A retry offers fresh symbols, and once K of them arrive it is a repeat.
	msg := randMsg(r, msgLen)
	key := testKey{"b", 99}
	s, err := NewSender(msg, testSubtype, 0, 1, key.fragID)
	require.NoError(t, err)
	data, repair, err := s.Attempt(DefaultRepair(s.Layout().K))
	require.NoError(t, err)
	res := sendAll(key, data)
	require.Len(t, res, 1)
	tb.Answered(key, res[0], now)
	require.Empty(t, sendAll(key, repair))

	data, repair, err = s.Attempt(DefaultRepair(s.Layout().K))
	require.NoError(t, err)
	res = sendAll(key, append(data, repair...))
	require.Len(t, res, 1)
	assert.True(t, res[0].Repeat)
	assert.Nil(t, res[0].Msg)
	assert.Equal(t, sha256.Sum256(msg), res[0].Hash)
	assert.Positive(t, res[0].Received)

	// Forgotten, the message is reassembled from scratch again.
	tb.Forget(key)
	data, _, err = s.Attempt(DefaultRepair(s.Layout().K))
	require.NoError(t, err)
	res = sendAll(key, data)
	require.Len(t, res, 1)
	assert.False(t, res[0].Repeat)
	assert.Equal(t, msg, res[0].Msg)

	// Answered messages expire with the TTL like entries do.
	tb.Answered(key, res[0], now)
	tb.Expire(now.Add(time.Hour))
	tb.mu.Lock()
	assert.Empty(t, tb.answered)
	tb.mu.Unlock()
}

// TestTableRepeatInterval checks that an answered message is reported as a
// repeat at most once per RepeatInterval on one key, while another key, a
// second path the same message arrives by, keeps its own clock.
func TestTableRepeatInterval(t *testing.T) {
	r := rand.New(rand.NewPCG(4, 4))
	cfg := testConfig()
	cfg.RepeatInterval = 100 * time.Millisecond
	tb := NewTable[testKey, string](cfg)
	now := time.Unix(1000, 0)
	msg := randMsg(r, 8009) // K=7, 3 repair

	attempt := func(s *Sender) [][]byte {
		data, repair, err := s.Attempt(DefaultRepair(s.Layout().K))
		require.NoError(t, err)
		return append(data, repair...)
	}
	repeats := func(key testKey, pkts [][]byte) int {
		n := 0
		for _, p := range pkts {
			_, h, sym := parse(t, p)
			res, err := tb.Add(key, key.src, now, h, sym)
			require.NoError(t, err)
			if res != nil {
				require.True(t, res.Repeat)
				n++
			}
		}
		return n
	}
	answer := func(key testKey, s *Sender) {
		var res *Result
		for _, p := range attempt(s) {
			_, h, sym := parse(t, p)
			got, err := tb.Add(key, key.src, now, h, sym)
			require.NoError(t, err)
			if got != nil {
				res = got
			}
		}
		require.NotNil(t, res)
		tb.Answered(key, res, now)
	}

	// Two paths carry the same message. Each has its own sender here because
	// the initiator offers the same symbols on every path.
	direct := testKey{"direct", 1}
	relayed := testKey{"relay", 1}
	sd, err := NewSender(msg, testSubtype, 0, 1, 1)
	require.NoError(t, err)
	sr, err := NewSender(msg, testSubtype, 0, 1, 1)
	require.NoError(t, err)
	answer(direct, sd)
	answer(relayed, sr)

	// A retry right after the answer carries K fresh symbols, but the clock on
	// that path has not run out.
	now = now.Add(10 * time.Millisecond)
	assert.Zero(t, repeats(direct, attempt(sd)), "a repeat inside the interval is not reported")

	// Once it has, the first fresh symbol of the next retry is enough: the
	// fresh symbols kept counting.
	now = now.Add(100 * time.Millisecond)
	retry := attempt(sd)
	assert.Equal(t, 1, repeats(direct, retry[:1]), "the held repeat is reported at once")
	assert.Zero(t, repeats(direct, retry[1:]), "and only once per retry")

	// The other path has its own clock, which only its own answer started.
	assert.Equal(t, 1, repeats(relayed, attempt(sr)), "a repeat on another path is independent")
	assert.Zero(t, repeats(relayed, attempt(sr)), "and is itself clocked")

	// Without an interval every K fresh symbols is a repeat, which is what the
	// other tests rely on.
	tb = NewTable[testKey, string](testConfig())
	s2, err := NewSender(msg, testSubtype, 0, 1, 2)
	require.NoError(t, err)
	k2 := testKey{"a", 2}
	answer(k2, s2)
	assert.Equal(t, 1, repeats(k2, attempt(s2)))
	assert.Equal(t, 1, repeats(k2, attempt(s2)))
}
