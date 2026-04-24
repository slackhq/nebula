package logging

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

// BenchmarkLogger_* compare the handler returned by NewLogger against a
// stock slog text handler. The key thing we care about is the per-log
// cost on a logger that has been derived via .With(), because that is the
// shape subsystems store on their structs (HostInfo.logger(),
// lh.l.With("subsystem", ...), etc.) and call from hot paths.

func BenchmarkLogger_Stock_RootInfo(b *testing.B) {
	l := slog.New(slog.DiscardHandler)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Info("hello", "i", i)
	}
}

func BenchmarkLogger_Nebula_RootInfo(b *testing.B) {
	l := NewLogger(io.Discard)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Info("hello", "i", i)
	}
}

func BenchmarkLogger_Stock_DerivedInfo(b *testing.B) {
	l := slog.New(slog.DiscardHandler).With(
		"subsystem", "bench",
		"localIndex", 1234,
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Info("hello", "i", i)
	}
}

func BenchmarkLogger_Nebula_DerivedInfo(b *testing.B) {
	l := NewLogger(io.Discard).With(
		"subsystem", "bench",
		"localIndex", 1234,
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Info("hello", "i", i)
	}
}

// Gated-off-path benchmarks: mimic the typical hot-path shape
// `if l.Enabled(ctx, slog.LevelDebug) { ... }` where the log is gated below
// the active level. This is the dominant pattern in inside.go/outside.go and
// what we pay on every packet.
func BenchmarkLogger_Stock_DerivedEnabledGateMiss(b *testing.B) {
	l := slog.New(slog.DiscardHandler).With(
		"subsystem", "bench",
		"localIndex", 1234,
	)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if l.Enabled(ctx, slog.LevelDebug) {
			l.Debug("hello", "i", i)
		}
	}
}

func BenchmarkLogger_Nebula_DerivedEnabledGateMiss(b *testing.B) {
	l := NewLogger(io.Discard).With(
		"subsystem", "bench",
		"localIndex", 1234,
	)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if l.Enabled(ctx, slog.LevelDebug) {
			l.Debug("hello", "i", i)
		}
	}
}
