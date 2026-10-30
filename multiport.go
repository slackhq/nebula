package nebula

import (
	"log/slog"
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

// maxReplayWindow caps tun.multiport.replay_window, 128KB per tunnel
const maxReplayWindow = 1 << 20

// replayWindow returns the replay window length for a new tunnel, the default ReplayWindow until a config is loaded
func replayWindow(mpc config.MultiPortConfig) uint64 {
	return max(mpc.ReplayWindow, ReplayWindow)
}

// multiPortReplayWindow validates tun.multiport.replay_window, a power of two from ReplayWindow to maxReplayWindow.
// Anything else falls back to ReplayWindow.
func multiPortReplayWindow(l *slog.Logger, configured int) uint64 {
	w := uint64(configured)
	if configured < ReplayWindow || w > maxReplayWindow || w&(w-1) != 0 {
		l.Warn("tun.multiport.replay_window must be a power of two from 8192 to 1048576, using 8192",
			"configured", configured)
		return ReplayWindow
	}
	return w
}
