package ratelimit

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustLimiter(t testing.TB, burst int, every time.Duration) *Limiter {
	t.Helper()
	l, err := New(burst, every)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLimiterBurstAndRefill(t *testing.T) {
	l, now := mustLimiter(t, 3, time.Second), int64(0)

	for i := 0; i < 3; i++ {
		if n, ok := l.allow(now); !ok || n != 0 {
			t.Fatalf("burst line %d: ok=%v denied=%d", i, ok, n)
		}
	}
	for i := 0; i < 5; i++ {
		if _, ok := l.allow(now); ok {
			t.Fatalf("line %d past the burst logged", i)
		}
	}

	now += int64(time.Second)
	if n, ok := l.allow(now); !ok || n != 5 {
		t.Fatalf("after one refill: ok=%v denied=%d, want true 5", ok, n)
	}
	if _, ok := l.allow(now); ok {
		t.Fatal("one refill earned more than one line")
	}

	// A long quiet spell refills to burst, not past it, and the count reported above does not carry over.
	now += int64(time.Hour)
	for i, want := range []uint64{1, 0, 0} {
		if n, ok := l.allow(now); !ok || n != want {
			t.Fatalf("refilled line %d: ok=%v denied=%d, want true %d", i, ok, n, want)
		}
	}
	if _, ok := l.allow(now); ok {
		t.Fatal("bucket refilled past burst")
	}
}

func TestLimiterBounds(t *testing.T) {
	for _, every := range []time.Duration{0, -time.Second} {
		l := mustLimiter(t, 1, every)
		for i := 0; i < 100; i++ {
			if _, ok := l.allow(0); !ok {
				t.Fatalf("every=%v limited line %d", every, i)
			}
		}
	}

	l := mustLimiter(t, 0, time.Second)
	if _, ok := l.allow(0); !ok {
		t.Fatal("burst 0 should allow one line")
	}
	if _, ok := l.allow(0); ok {
		t.Fatal("burst 0 should allow only one line")
	}
}

func TestLimiterOverflow(t *testing.T) {
	for _, c := range []struct {
		burst int
		every time.Duration
	}{
		{math.MaxInt, time.Second},
		{1, math.MaxInt64},
		{2, maxSpan/2 + 1},
	} {
		if _, err := New(c.burst, c.every); err == nil {
			t.Fatalf("burst %d every %d should not fit", c.burst, c.every)
		}
	}

	l := mustLimiter(t, 2, maxSpan/2)
	for i := 0; i < 2; i++ {
		if _, ok := l.allow(0); !ok {
			t.Fatalf("the largest span should allow its burst, denied call %d", i)
		}
	}
	if _, ok := l.allow(0); ok {
		t.Fatal("the largest span allowed past its burst")
	}
}

// Concurrent callers read the clock at slightly different times, which must not limit a Limiter that never limits.
func TestLimiterUnlimitedConcurrent(t *testing.T) {
	l := mustLimiter(t, 1, 0)

	var denied atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10000; j++ {
				if _, ok := l.Allow(); !ok {
					denied.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if got := denied.Load(); got != 0 {
		t.Fatalf("denied %d lines", got)
	}
}

func TestLimiterNil(t *testing.T) {
	var l *Limiter
	for i := 0; i < 10; i++ {
		if _, ok := l.Allow(); !ok {
			t.Fatal("nil limiter limited")
		}
	}
}

func TestLimiterConcurrent(t *testing.T) {
	l := mustLimiter(t, 10, time.Hour)

	var allowed atomic.Int64
	var reported atomic.Uint64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if n, ok := l.allow(0); ok {
					allowed.Add(1)
					reported.Add(n)
				}
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != 10 {
		t.Fatalf("allowed %d lines, want the burst of 10", got)
	}
	// An allowed call that lands after some denials reports them, so the rest are still pending.
	if got := reported.Load() + l.denied.Load(); got != 16*1000-10 {
		t.Fatalf("denied %d, want %d", got, 16*1000-10)
	}
}

func BenchmarkAllowAllowed(b *testing.B) {
	l := mustLimiter(b, 1, time.Nanosecond)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l.tat.Store(0)
		l.Allow()
	}
}

func BenchmarkAllowDenied(b *testing.B) {
	l := mustLimiter(b, 1, time.Hour)
	l.Allow()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l.Allow()
	}
}

func BenchmarkAllowDeniedParallel(b *testing.B) {
	l := mustLimiter(b, 1, time.Hour)
	l.Allow()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Allow()
		}
	})
}

// FuzzLimiter checks the bucket against its exact definition over arbitrary call timings.
// A call is denied if and only if some allowed call a would leave too many calls for the time since a:
// (allowed calls since a, plus this one) * every > burst * every + (now - a).
// Every denied call must also be reported exactly once, by a later allowed call or still pending.
func FuzzLimiter(f *testing.F) {
	f.Add(uint8(3), uint16(1000), []byte{0, 0, 0, 0, 16, 0, 0, 200, 1, 1, 1, 15, 17, 0})
	f.Add(uint8(1), uint16(1), []byte{0, 16, 15, 16, 0, 255, 0, 0})
	f.Fuzz(func(t *testing.T, burst uint8, everyUs uint16, steps []byte) {
		if len(steps) > 512 {
			steps = steps[:512]
		}
		b := int64(burst%16) + 1
		every := int64(everyUs%1000+1) * int64(time.Microsecond)
		l := mustLimiter(t, int(b), time.Duration(every))

		var now int64
		var allowedAt []int64
		var denied, reported uint64
		for _, s := range steps {
			// Each step advances by a sixteenth of every, so timings land on and around the refill.
			now += int64(s) * every / 16

			over := false
			for i, a := range allowedAt {
				if int64(len(allowedAt)-i+1)*every > b*every+now-a {
					over = true
					break
				}
			}

			n, ok := l.allow(now)
			if ok == over {
				t.Fatalf("at %d with %d allowed before: ok=%v, the definition says %v", now, len(allowedAt), ok, !over)
			}
			if !ok {
				denied++
				continue
			}
			reported += n
			allowedAt = append(allowedAt, now)
		}

		if got := reported + l.denied.Load(); got != denied {
			t.Fatalf("reported %d denied calls, made %d", got, denied)
		}
	})
}

// Concurrent callers on the real clock must account for every denied call exactly once.
func TestLimiterDeniedConservedConcurrent(t *testing.T) {
	l := mustLimiter(t, 4, time.Microsecond)

	var denied, reported atomic.Uint64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20000; j++ {
				if n, ok := l.Allow(); ok {
					reported.Add(n)
				} else {
					denied.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if denied.Load() == 0 {
		t.Fatal("nothing was denied, the test proves nothing")
	}
	if got := reported.Load() + l.denied.Load(); got != denied.Load() {
		t.Fatalf("reported %d denied calls, made %d", got, denied.Load())
	}
}
