package nebula

import (
	"context"
	"testing"
	"time"
)

func TestScheduler_PooledReuse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := NewScheduler[int](16)
	delivered := make(chan int, 256)
	go s.Run(ctx, func(item int) { delivered <- item })

	const N = 100
	for i := 0; i < N; i++ {
		s.Schedule(ctx, i, time.Millisecond)
	}

	deadline := time.After(2 * time.Second)
	got := 0
	for got < N {
		select {
		case <-delivered:
			got++
		case <-deadline:
			t.Fatalf("only %d/%d items delivered", got, N)
		}
	}
}

// BenchmarkScheduler_Schedule reports allocations per Schedule call.
// In steady state the Scheduler's sync.Pool means we should see zero allocs per op once the pool warms up.
func BenchmarkScheduler_Schedule(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := NewScheduler[int](b.N)
	go s.Run(ctx, func(int) {})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Schedule(ctx, i, time.Microsecond)
	}
}

// BenchmarkBareAfterFunc is the comparison baseline.
// What we'd pay per Schedule if Punchy called time.AfterFunc directly without the pooled Scheduler.
// Allocates a *time.Timer plus a closure each call.
func BenchmarkBareAfterFunc(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	queue := make(chan int, b.N)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-queue:
			}
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		i := i
		time.AfterFunc(time.Microsecond, func() {
			select {
			case queue <- i:
			case <-ctx.Done():
			}
		})
	}
}
