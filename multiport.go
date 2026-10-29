package nebula

import (
	"sync/atomic"

	"github.com/slackhq/nebula/config"
)

// multiPortSettings holds the reloadable multiport config. The interface and the handshake manager share one, the
// reload callback replaces the whole config at once so readers never see a mix of old and new fields.
type multiPortSettings struct {
	p atomic.Pointer[config.MultiPortConfig]
}

// Load returns the current config, the zero config (multiport off) if none was stored or s is nil.
func (s *multiPortSettings) Load() config.MultiPortConfig {
	if s == nil {
		return config.MultiPortConfig{}
	}
	if c := s.p.Load(); c != nil {
		return *c
	}
	return config.MultiPortConfig{}
}

func (s *multiPortSettings) Store(c config.MultiPortConfig) {
	s.p.Store(&c)
}
