package logging

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/ratelimit"
)

type fakeLimiter struct {
	denied uint64
	ok     bool
}

func (f fakeLimiter) Allow() (uint64, bool) { return f.denied, f.ok }

func TestRateLimited(t *testing.T) {
	var buf bytes.Buffer
	base := NewLogger(&buf)

	if l, ok := RateLimited(base, fakeLimiter{ok: false}); ok || l != nil {
		t.Fatalf("denied call: ok=%v logger=%v", ok, l)
	}

	if l, ok := RateLimited(base, fakeLimiter{ok: true}); !ok || l != base {
		t.Fatal("nothing denied should hand back the same logger")
	}

	if l, ok := RateLimited(base, nil); !ok || l != base {
		t.Fatal("a nil limiter should allow with the same logger")
	}

	l, ok := RateLimited(base, fakeLimiter{denied: 7, ok: true})
	if !ok {
		t.Fatal("allowed call denied")
	}
	l.Info("hello", "k", "v")
	if !strings.Contains(buf.String(), "suppressed=7") {
		t.Fatalf("want suppressed=7, got %q", buf.String())
	}
}

// The benchmarks compare a log line through slog directly against the same line behind RateLimited: logged with
// nothing denied, denied, and logged after denials.

var (
	benchErr  = errors.New("sendto: no buffer space available")
	benchAddr = netip.MustParseAddrPort("192.0.2.1:4242")
)

func benchLogger() *slog.Logger {
	return NewLogger(io.Discard).With("localIndex", 1234, "remoteIndex", 5678)
}

func BenchmarkRateLimitedBaseline(b *testing.B) {
	lg := benchLogger()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		lg.Error("Failed to write outgoing packet", "error", benchErr, "udpAddr", benchAddr)
	}
}

func BenchmarkRateLimitedAllowed(b *testing.B) {
	lg, lim := benchLogger(), mustLimiter(b, 1, 0)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if l, ok := RateLimited(lg, lim); ok {
			l.Error("Failed to write outgoing packet", "error", benchErr, "udpAddr", benchAddr)
		}
	}
}

func BenchmarkRateLimitedDenied(b *testing.B) {
	lg, lim := benchLogger(), mustLimiter(b, 1, time.Hour)
	lim.Allow()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if l, ok := RateLimited(lg, lim); ok {
			l.Error("Failed to write outgoing packet", "error", benchErr, "udpAddr", benchAddr)
		}
	}
}

func BenchmarkRateLimitedAfterDenied(b *testing.B) {
	lg, lim := benchLogger(), fakeLimiter{denied: 5, ok: true}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if l, ok := RateLimited(lg, lim); ok {
			l.Error("Failed to write outgoing packet", "error", benchErr, "udpAddr", benchAddr)
		}
	}
}

func mustLimiter(b *testing.B, burst int, every time.Duration) *ratelimit.Limiter {
	l, err := ratelimit.New(burst, every)
	if err != nil {
		b.Fatal(err)
	}
	return l
}
