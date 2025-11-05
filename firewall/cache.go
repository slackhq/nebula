package firewall

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// ConntrackCache is used as a local routine cache to know if a given flow
// has been seen in the conntrack table.
type ConntrackCache struct {
	mu      sync.Mutex
	entries map[Packet]struct{}
}

func newConntrackCache() *ConntrackCache {
	return &ConntrackCache{entries: make(map[Packet]struct{})}
}

func (c *ConntrackCache) Has(p Packet) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	_, ok := c.entries[p]
	c.mu.Unlock()
	return ok
}

func (c *ConntrackCache) Add(p Packet) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries[p] = struct{}{}
	c.mu.Unlock()
}

func (c *ConntrackCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	l := len(c.entries)
	c.mu.Unlock()
	return l
}

func (c *ConntrackCache) Reset(capHint int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[Packet]struct{}, capHint)
	c.mu.Unlock()
}

type ConntrackCacheTicker struct {
	cacheV    uint64
	cacheTick atomic.Uint64

	cache *ConntrackCache
}

func NewConntrackCacheTicker(d time.Duration) *ConntrackCacheTicker {
	if d == 0 {
		return nil
	}

	c := &ConntrackCacheTicker{cache: newConntrackCache()}

	go c.tick(d)

	return c
}

func (c *ConntrackCacheTicker) tick(d time.Duration) {
	for {
		time.Sleep(d)
		c.cacheTick.Add(1)
	}
}

// Get checks if the cache ticker has moved to the next version before returning
// the map. If it has moved, we reset the map.
func (c *ConntrackCacheTicker) Get(l *logrus.Logger) *ConntrackCache {
	if c == nil {
		return nil
	}
	if tick := c.cacheTick.Load(); tick != c.cacheV {
		c.cacheV = tick
		if ll := c.cache.Len(); ll > 0 {
			if l.Level == logrus.DebugLevel {
				l.WithField("len", ll).Debug("resetting conntrack cache")
			}
			c.cache.Reset(ll)
		}
	}

	return c.cache
}
