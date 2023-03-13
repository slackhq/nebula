package firewall

import (
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// ConntrackCache is used as a local routine cache to know if a given flow
// has been seen in the conntrack table.
type ConntrackCache map[Packet]struct{}

type ConntrackCacheTicker struct {
	cacheV    uint64
	cacheTick atomic.Uint64

	cache ConntrackCache
}

func NewConntrackCacheTicker(d time.Duration) *ConntrackCacheTicker {
	if d == 0 {
		return nil
	}

	c := &ConntrackCacheTicker{
		cache: ConntrackCache{},
	}

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
func (c *ConntrackCacheTicker) Get(l *logrus.Logger) ConntrackCache {
	if c == nil {
		return nil
	}
	if tick := c.cacheTick.Load(); tick != c.cacheV {
		c.cacheV = tick
		if ll := len(c.cache); ll > 0 {
			if l.Level == logrus.DebugLevel {
				l.WithField("len", ll).Debug("resetting conntrack cache")
			}
			c.cache = make(ConntrackCache, ll)
		}
	}

	return c.cache
}
