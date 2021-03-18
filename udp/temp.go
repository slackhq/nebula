package udp

import (
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/cert"
)

//TODO: The items in this file belong in their own packages but doing that in a single PR is a nightmare

type LightHouseHandlerFunc func(rAddr *Addr, vpnIp uint32, p []byte, c *cert.NebulaCertificate, f EncWriter)

type EncWriter interface {
	SendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte)
	SendMessageToAll(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte)
}

// ConntrackCache is used as a local routine cache to know if a given flow
// has been seen in the conntrack table.
type ConntrackCache map[FirewallPacket]struct{}

type ConntrackCacheTicker struct {
	cacheV    uint64
	cacheTick uint64

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
		atomic.AddUint64(&c.cacheTick, 1)
	}
}

// Get checks if the cache ticker has moved to the next version before returning
// the map. If it has moved, we reset the map.
func (c *ConntrackCacheTicker) Get() ConntrackCache {
	if c == nil {
		return nil
	}
	if tick := atomic.LoadUint64(&c.cacheTick); tick != c.cacheV {
		c.cacheV = tick
		if ll := len(c.cache); ll > 0 {
			//TODO
			//if l.GetLevel() == logrus.DebugLevel {
			//	l.WithField("len", ll).Debug("resetting conntrack cache")
			//}
			c.cache = make(ConntrackCache, ll)
		}
	}

	return c.cache
}
