package firewall

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/logging"
)

// ConntrackCache is used as a local routine cache to know if a given flow
// has been seen in the conntrack table. Keyed on PacketKey (dense form)
// rather than Packet so the lookup hashes raw bytes instead of the
// unique.Handle each netip.Addr in Packet carries.
type ConntrackCache map[PacketKey]struct{}

type ConntrackCacheTicker struct {
	cacheV    uint64
	cacheTick atomic.Uint64

	l     *slog.Logger
	cache ConntrackCache
}

func NewConntrackCacheTicker(ctx context.Context, l *slog.Logger, d time.Duration) *ConntrackCacheTicker {
	if d == 0 {
		return nil
	}

	c := &ConntrackCacheTicker{
		l:     l,
		cache: ConntrackCache{},
	}

	go c.tick(ctx, d)

	return c
}

func (c *ConntrackCacheTicker) tick(ctx context.Context, d time.Duration) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.cacheTick.Add(1)
		}
	}
}

// Get checks if the cache ticker has moved to the next version before returning
// the map. If it has moved, we reset the map.
func (c *ConntrackCacheTicker) Get() ConntrackCache {
	if c == nil {
		return nil
	}
	if tick := c.cacheTick.Load(); tick != c.cacheV {
		c.cacheV = tick
		if ll := len(c.cache); ll > 0 {
			if c.l.Enabled(context.Background(), logging.LevelTrace) {
				c.l.Log(context.Background(), logging.LevelTrace, "resetting conntrack cache", "len", ll)
			}
			c.cache = make(ConntrackCache, ll)
		}
	}

	return c.cache
}
